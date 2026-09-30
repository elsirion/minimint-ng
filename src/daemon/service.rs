//! Running guardian API composition. Installed services share immutable config;
//! waits never hold the service-switch lock or a database transaction.
use crate::{
    api::{
        announcements::{AnnouncementApi, AnnouncementError},
        backup::{self, BackupError},
        config::{ConfigApi, ConfigApiError},
        core::{CoreFailure, CoreOperation, CorePoll, CoreRequest},
        modules::{self, ModuleApiError},
        rpc::{Request, RpcError},
        server::{CallContext, Handler},
        setup::SetupApi,
    },
    config::SupportSummary,
    daemon::{config::RuntimeConfig, consensus::RuntimeHandle},
    storage::Store,
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const UNAVAILABLE: RpcError = RpcError {
    code: 500,
    message: "Guardian service unavailable",
};
const SCHEMA: RpcError = RpcError {
    code: 500,
    message: "Endpoint schema unavailable",
};

/// ConfigApi's caller-supplied advertisement must be checked against the full
/// endpoint ledger before deployment. Composition does not establish conformance.
pub struct RunningApi {
    store: Store,
    config: Arc<RuntimeConfig>,
    runtime: RuntimeHandle,
    configuration: ConfigApi,
    announcements: AnnouncementApi,
    admin: Zeroizing<String>,
}
/// Advertisement remains explicit until all endpoint definition gates close.
/// Neither this options object nor the installed handler exposes secret Debug.
pub struct RunningApiOptions {
    pub software_identity: String,
    pub support: SupportSummary,
    pub access_secret: Option<Zeroizing<String>>,
    pub admin_secret: Zeroizing<String>,
}
impl RunningApi {
    pub fn new(runtime: RuntimeHandle, options: RunningApiOptions) -> Result<Self, RpcError> {
        if options.admin_secret.is_empty() {
            return Err(RpcError::UNAUTHORIZED);
        }
        let store = runtime.store().clone();
        let config = runtime.config().clone();
        let configuration = ConfigApi::new(
            config.server_config().clone(),
            config.peer(),
            options.access_secret,
            options.software_identity,
            options.support,
        )
        .map_err(|_| RpcError::INTERNAL)?;
        let signing = config.session_config().map_err(|_| RpcError::INTERNAL)?;
        let announcements = AnnouncementApi::new(
            store.clone(),
            signing.broadcast_keys,
            signing.local_peer,
            signing.local_key,
        )
        .map_err(|_| RpcError::INTERNAL)?;
        Ok(Self {
            store,
            config,
            runtime,
            configuration,
            announcements,
            admin: options.admin_secret,
        })
    }

    fn fatal(&self) -> RpcError {
        self.runtime.request_shutdown();
        RpcError::INTERNAL
    }

    fn core(&self, request: CoreRequest, context: &CallContext<'_>) -> Result<Value, RpcError> {
        let mut operation = CoreOperation::new(request);
        loop {
            if context.is_cancelled() || self.runtime.is_stopped() {
                return Err(UNAVAILABLE);
            }
            // Observe the wake token first: a commit racing the snapshot read
            // must either be visible to poll or change the token before waiting.
            let revision = self.runtime.revision();
            match operation.poll(
                &self.store,
                self.config.modules(),
                self.config.server_config().consensus_version,
                &mut |item| self.runtime.propose(item),
            ) {
                Ok(CorePoll::Ready(value)) => return Ok(value),
                Ok(CorePoll::Pending) => {}
                Err(CoreFailure::Rpc(error)) => return Err(error),
                Err(CoreFailure::Fatal(_) | CoreFailure::Storage(_)) => return Err(self.fatal()),
            }
            // Connection cancellation has a different wake source. Bound its
            // observation latency while retaining immediate consensus wakeups.
            let remaining = context.deadline.saturating_duration_since(Instant::now());
            self.runtime
                .wait_for_change(revision, remaining.min(Duration::from_millis(50)));
        }
    }
}
impl Handler for RunningApi {
    fn handle(&self, request: &Request, context: &CallContext<'_>) -> Result<Value, RpcError> {
        if context.is_cancelled() || self.runtime.is_stopped() {
            return Err(UNAVAILABLE);
        }
        let method = request.method.as_str();
        if method == "setup_status" {
            return if request.params.is_null() {
                Ok(json!("ConsensusIsRunning"))
            } else {
                Err(RpcError::PARAMS)
            };
        }
        match self.configuration.dispatch(method, &request.params) {
            Ok(value) => return Ok(value),
            Err(ConfigApiError::MethodNotFound) => {}
            Err(ConfigApiError::InvalidParams) => return Err(RpcError::PARAMS),
            Err(ConfigApiError::InvalidConfiguration) => return Err(self.fatal()),
        }
        if method.starts_with("module_") {
            let snapshot = self.store.snapshot().map_err(|_| self.fatal())?;
            return modules::dispatch(self.config.modules(), &snapshot, method, &request.params)
                .map_err(|error| {
                    if matches!(
                        error,
                        ModuleApiError::FatalInvariant | ModuleApiError::StateUnavailable
                    ) {
                        self.runtime.request_shutdown();
                    }
                    RpcError {
                        code: error.code(),
                        message: error.message(),
                    }
                });
        }
        if matches!(method, "backup" | "recover") {
            return backup::dispatch(&self.store, method, &request.params).map_err(|error| {
                match error {
                    BackupError::Storage(_) | BackupError::CorruptState => self.fatal(),
                    BackupError::MethodNotFound => RpcError::METHOD,
                    _ => RpcError {
                        code: 400,
                        message: "Invalid backup request",
                    },
                }
            });
        }
        if matches!(method, "sign_api_announcement" | "sign_guardian_metadata") {
            request.require_admin(&self.admin)?;
            return Err(SCHEMA);
        }
        if matches!(
            method,
            "api_announcements"
                | "submit_api_announcement"
                | "guardian_metadata"
                | "submit_guardian_metadata"
        ) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| UNAVAILABLE)?
                .as_secs();
            return self
                .announcements
                .dispatch(method, &request.params, now)
                .map_err(|error| match error {
                    AnnouncementError::Storage(_)
                    | AnnouncementError::CorruptState
                    | AnnouncementError::InvalidConfiguration => self.fatal(),
                    AnnouncementError::MethodNotFound => RpcError::METHOD,
                    AnnouncementError::SchemaUnavailable => SCHEMA,
                    _ => RpcError {
                        code: 400,
                        message: "Invalid signed update",
                    },
                });
        }
        if method == "chain_id" {
            return Err(SCHEMA);
        }
        let operation = CoreRequest::decode(method, &request.params, self.config.modules())?;
        self.core(operation, context)
    }
}

/// The lifecycle driver installs the running handler only after durable setup
/// and successful runtime startup. No request can observe a partly installed set.
pub struct Service {
    setup: Option<Arc<SetupApi>>,
    running: RwLock<Option<Arc<RunningApi>>>,
}
impl Service {
    pub fn setup(setup: Arc<SetupApi>) -> Self {
        Self {
            setup: Some(setup),
            running: RwLock::new(None),
        }
    }
    pub fn restored(running: Arc<RunningApi>) -> Self {
        Self {
            setup: None,
            running: RwLock::new(Some(running)),
        }
    }
    pub fn install(&self, running: Arc<RunningApi>) -> Result<(), RpcError> {
        let mut target = self.running.write().map_err(|_| RpcError::INTERNAL)?;
        if target.is_some() {
            return Err(RpcError::INTERNAL);
        }
        if let Some(setup) = &self.setup {
            setup.mark_running()?;
        }
        *target = Some(running);
        Ok(())
    }
}
impl Handler for Service {
    fn handle(&self, request: &Request, context: &CallContext<'_>) -> Result<Value, RpcError> {
        let running = self.running.read().map_err(|_| RpcError::INTERNAL)?.clone();
        if let Some(running) = running {
            return running.handle(request, context);
        }
        self.setup
            .as_ref()
            .ok_or(UNAVAILABLE)?
            .handle(request, context)
    }
}
