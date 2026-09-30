//! Process orchestration. A watchdog bounds startup I/O and shutdown separately;
//! loss of quorum alone never triggers shutdown.
use super::{
    bitcoin::Backend,
    catchup::{Catchup, CatchupEndpoint, CatchupError, CatchupOptions},
    config::tcp_authority,
    consensus::{Runtime, RuntimeHandle, RuntimeOptions},
    lifecycle::{self, AdvertisedEndpoints, Generation, ReadyRuntime, SetupPlan},
    options::{BitcoinSource, Options, read_secret},
    service::{RunningApi, RunningApiOptions, Service},
    shutdown::Shutdown,
};
use crate::{
    api::{
        announcements::{AnnouncementApi, SignedAnnouncement},
        server::Server,
        setup::SetupApi,
        websocket::Limits,
    },
    bitcoin::{
        BackendError,
        esplora::{Esplora, EsploraOptions},
        rpc::CoreRpc,
    },
    config::{ApiVersions, CanonicalUrl, CoreSupport, ModuleSupport, SupportSummary},
    net::PeerNetwork,
    protocol::PeerId,
    setup::SetupState,
    storage::Store,
};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::TryRecvError,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy)]
pub struct ProcessError(pub &'static str);
impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ProcessError {}
const STARTUP_IO: Duration = Duration::from_secs(15);
const TICK: Duration = Duration::from_millis(10);
struct Owners {
    stop: Arc<AtomicBool>,
    server: Option<Server>,
    generation: Option<Generation>,
    catchup: Option<Catchup>,
    runtime: Option<Runtime>,
    network: Option<Arc<PeerNetwork>>,
    handle: Option<RuntimeHandle>,
    store: Option<Store>,
    announcements: Option<AnnouncementApi>,
    resolved_announcements: BTreeMap<PeerId, SignedAnnouncement>,
}
impl Owners {
    fn shutdown(&mut self) -> Result<(), ProcessError> {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = &self.server {
            server.request_shutdown();
        }
        if let Some(generation) = &self.generation {
            generation.request_shutdown();
        }
        if let Some(catchup) = &self.catchup {
            catchup.request_shutdown();
        }
        if let Some(runtime) = &self.runtime {
            runtime.request_shutdown();
        }
        // Native agreement retains its pump and peer connections until joined.
        let mut failed = false;
        if let Some(server) = self.server.take() {
            failed |= server.shutdown().is_err();
        }
        if let Some(catchup) = self.catchup.take() {
            failed |= catchup.shutdown().is_err();
        }
        if let Some(generation) = self.generation.take() {
            failed |= generation.shutdown().is_err();
        }
        if let Some(runtime) = self.runtime.take() {
            failed |= runtime.shutdown().is_err();
        }
        if let Some(network) = self.network.take() {
            network.request_shutdown();
            match Arc::try_unwrap(network) {
                Ok(network) => failed |= network.shutdown().is_err(),
                Err(_) => failed = true,
            }
        }
        self.handle.take();
        self.announcements.take();
        self.store.take();
        if failed {
            Err(ProcessError("Guardian shutdown failed"))
        } else {
            Ok(())
        }
    }
    fn check(&self) -> Result<(), ProcessError> {
        if self.server.as_ref().is_some_and(Server::is_finished)
            || self.runtime.as_ref().is_some_and(Runtime::is_finished)
            || self.catchup.as_ref().is_some_and(Catchup::is_finished)
            || self.handle.as_ref().is_some_and(RuntimeHandle::is_stopped)
        {
            return Err(ProcessError("Guardian worker stopped unexpectedly"));
        }
        Ok(())
    }
}
impl Drop for Owners {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
fn resolve(authority: &str, shutdown: &Shutdown) -> Result<Vec<SocketAddr>, ProcessError> {
    // This process already requires Linux procfs for protected credential reads.
    // Execute the running image, even if its original pathname was replaced or
    // unlinked by a subsequent build. A pathname lookup could run a different
    // helper version or fail with a "(deleted)" current_exe path.
    super::resolve::resolve(
        std::path::Path::new("/proc/self/exe"),
        authority,
        STARTUP_IO,
        &shutdown.flag(),
    )
    .map_err(|_| ProcessError("Guardian address resolution failed"))
}
fn resolve_peers(
    urls: &BTreeMap<PeerId, CanonicalUrl>,
    shutdown: &Shutdown,
) -> Result<BTreeMap<PeerId, SocketAddr>, ProcessError> {
    urls.iter()
        .map(|(peer, url)| {
            let authority =
                tcp_authority(url).map_err(|_| ProcessError("Invalid guardian endpoint"))?;
            Ok((*peer, resolve(authority, shutdown)?[0]))
        })
        .collect()
}
fn resolve_api(url: &CanonicalUrl, shutdown: &Shutdown) -> Result<Vec<SocketAddr>, ProcessError> {
    let text = url
        .as_str()
        .strip_prefix("ws://")
        .ok_or(ProcessError("Unsupported API transport"))?;
    let authority = text
        .split('/')
        .next()
        .ok_or(ProcessError("Invalid API authority"))?;
    let authority = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    resolve(&authority, shutdown)
}
fn bitcoin_backend(source: &BitcoinSource) -> Result<Backend, ProcessError> {
    let invalid = |_| ProcessError("Invalid Bitcoin backend configuration");
    match source {
        BitcoinSource::Core {
            rpc,
            credentials_file,
        } => {
            let credentials = read_secret(credentials_file)
                .map_err(|_| ProcessError("Invalid Bitcoin credentials file"))?;
            CoreRpc::new(*rpc, &credentials, Duration::from_secs(10), 6)
                .map(Backend::Core)
                .map_err(invalid)
        }
        BitcoinSource::Esplora(url) => Esplora::new(
            url.clone(),
            EsploraOptions {
                timeout: Duration::from_secs(15),
                fee_target: 6,
                extra_roots: vec![],
            },
            // Same bounded, killable helper as guardian endpoint resolution;
            // the Wallet poller must not block on an unbounded DNS lookup.
            Box::new(|authority, stop| {
                super::resolve::resolve(
                    std::path::Path::new("/proc/self/exe"),
                    authority,
                    STARTUP_IO,
                    stop,
                )
                .map_err(|_| BackendError)
            }),
        )
        .map(Backend::Esplora)
        .map_err(invalid),
    }
}
struct Context<'a> {
    options: &'a Options,
    store: Store,
    backend: Arc<Backend>,
    admin: Zeroizing<String>,
    access: Option<Zeroizing<String>>,
    shutdown: &'a Shutdown,
}
impl Context<'_> {
    fn start_running(
        &self,
        ready: ReadyRuntime,
        owners: &mut Owners,
    ) -> Result<Arc<RunningApi>, ProcessError> {
        let config = ready.config;
        owners.network = Some(ready.network.clone());
        let startup = self
            .shutdown
            .deadline(STARTUP_IO)
            .map_err(|_| ProcessError("Startup deadline failed"))?;
        let (runtime, handle) = Runtime::start(
            self.store.clone(),
            config.clone(),
            ready.network,
            self.backend.clone(),
            RuntimeOptions {
                round_delay_ms: self.options.round_delay.as_millis() as u64,
                wallet_poll_interval: self.backend.poll_interval(),
                ..RuntimeOptions::default()
            },
        )
        .map_err(|_| ProcessError("Guardian consensus startup failed"))?;
        owners.runtime = Some(runtime);
        owners.handle = Some(handle.clone());
        // Temporary development state: unresolved required diagnostic schemas
        // prevent any core API minor claim. Target remains complete core 0.9.
        let server = config.server_config();
        let support = SupportSummary {
            core: CoreSupport {
                core_consensus: server.consensus_version,
                api: ApiVersions { versions: vec![] },
            },
            modules: server
                .modules
                .iter()
                .map(|(id, module)| {
                    (
                        *id,
                        ModuleSupport {
                            core_consensus: server.consensus_version,
                            module_consensus: module.version,
                            api: ApiVersions {
                                versions: vec![crate::config::MODULE_API],
                            },
                        },
                    )
                })
                .collect(),
        };
        let api = RunningApi::new(
            handle.clone(),
            RunningApiOptions {
                software_identity: format!("minimint-ng/{}", env!("CARGO_PKG_VERSION")),
                support,
                access_secret: self.access.clone(),
                admin_secret: self.admin.clone(),
            },
        )
        .map_err(|_| ProcessError("Guardian API startup failed"))?;
        let keys = config
            .session_config()
            .map_err(|_| ProcessError("Guardian signing identity unavailable"))?;
        let updates = AnnouncementApi::new(
            self.store.clone(),
            keys.broadcast_keys,
            keys.local_peer,
            keys.local_key,
        )
        .map_err(|_| ProcessError("Guardian announcement configuration invalid"))?;
        let announcements = updates
            .announcements(
                &self
                    .store
                    .snapshot()
                    .map_err(|_| ProcessError("Guardian storage failed"))?,
            )
            .map_err(|_| ProcessError("Guardian stored announcement invalid"))?;
        drop(startup);
        let mut endpoints = vec![];
        for (peer, endpoint) in &server.api_endpoints {
            if *peer == config.peer() {
                continue;
            }
            let target = if let Some(announcement) = announcements.get(peer) {
                // A stored operational override is authoritative even while
                // unavailable. Start parked, then resolve in the refresh loop.
                CatchupEndpoint::pending_announcement(*peer, announcement.clone())
            } else {
                CatchupEndpoint::new(
                    *peer,
                    endpoint.url.clone(),
                    resolve_api(&endpoint.url, self.shutdown)?,
                )
                .map_err(|_| ProcessError("Guardian catch-up endpoint invalid"))?
            };
            endpoints.push(target);
        }
        if !endpoints.is_empty() {
            owners.catchup = Some(
                Catchup::start(
                    handle,
                    endpoints,
                    self.access.clone(),
                    CatchupOptions::default(),
                )
                .map_err(|_| ProcessError("Guardian catch-up startup failed"))?,
            );
        }
        owners.resolved_announcements.clear();
        owners.announcements = Some(updates);
        Ok(Arc::new(api))
    }

    fn refresh_catchup(&self, owners: &mut Owners) -> Result<(), ProcessError> {
        let (Some(catchup), Some(updates)) = (&owners.catchup, &owners.announcements) else {
            return Ok(());
        };
        let read = || {
            let _deadline = self
                .shutdown
                .deadline(STARTUP_IO)
                .map_err(|_| ProcessError("Announcement read deadline failed"))?;
            updates
                .announcements(
                    &self
                        .store
                        .snapshot()
                        .map_err(|_| ProcessError("Guardian storage failed"))?,
                )
                .map_err(|_| ProcessError("Guardian stored announcement invalid"))
        };
        for (peer, announcement) in read()? {
            if self.shutdown.is_requested() {
                break;
            }
            if peer == updates.local_peer()
                || owners.resolved_announcements.get(&peer) == Some(&announcement)
            {
                continue;
            }
            // Park and cancel the obsolete destination before DNS. Failure to
            // resolve the replacement must not silently restore an old URL.
            if let Err(error) = catchup.select_announcement(peer, announcement.clone()) {
                if matches!(error, CatchupError::Cancelled) && self.shutdown.is_requested() {
                    return Ok(());
                }
                return Err(ProcessError("Guardian endpoint selection failed"));
            }
            let Ok(addresses) = resolve_api(&announcement.api_announcement.api_url, self.shutdown)
            else {
                // Other peers remain usable; retry this unresolved selection on
                // the next pass. A timed-out resolver is killed and reaped
                // without terminating this guardian or other catch-up peers.
                continue;
            };
            // A newer signed record may have arrived while resolution ran.
            if read()?.get(&peer) != Some(&announcement) {
                continue;
            }
            if self.shutdown.is_requested() {
                return Ok(());
            }
            if let Err(error) = catchup.install_resolved(peer, &announcement, addresses) {
                if matches!(error, CatchupError::Cancelled) && self.shutdown.is_requested() {
                    return Ok(());
                }
                return Err(ProcessError("Guardian endpoint installation failed"));
            }
            owners.resolved_announcements.insert(peer, announcement);
        }
        Ok(())
    }
}
/// Install Shutdown before entering and retain it until all owners here finish.
pub fn run(options: Options, shutdown: &Shutdown) -> Result<(), ProcessError> {
    let mut owners = Owners {
        stop: shutdown.flag(),
        server: None,
        generation: None,
        catchup: None,
        runtime: None,
        network: None,
        handle: None,
        store: None,
        announcements: None,
        resolved_announcements: BTreeMap::new(),
    };
    let result = (|| {
        let startup = shutdown
            .deadline(STARTUP_IO)
            .map_err(|_| ProcessError("Startup deadline failed"))?;
        let admin = read_secret(&options.admin_secret_file)
            .map_err(|_| ProcessError("Invalid administrator secret file"))?;
        let access = options
            .access_secret_file
            .as_ref()
            .map(|path| read_secret(path))
            .transpose()
            .map_err(|_| ProcessError("Invalid access secret file"))?;
        let backend = Arc::new(bitcoin_backend(&options.bitcoin)?);
        let store = Store::open(&options.data_dir)
            .map_err(|_| ProcessError("Guardian storage open failed"))?;
        // Keep the final database owner outside the fallible startup closure;
        // it can only be released after the shutdown watchdog is armed.
        owners.store = Some(store.clone());
        let expected = AdvertisedEndpoints {
            api: options.api_url.clone(),
            p2p: options.p2p_url.clone(),
        };
        let restored = lifecycle::load(&store, &expected)
            .map_err(|_| ProcessError("Stored guardian configuration invalid"))?;
        if restored.as_ref().is_some_and(|restored| {
            restored.config().modules().wallet().config().network != options.bitcoin_network
        }) {
            return Err(ProcessError("Stored Bitcoin network differs from options"));
        }
        let api_listener = TcpListener::bind(options.api_bind)
            .map_err(|_| ProcessError("API listener bind failed"))?;
        let peer_listener = TcpListener::bind(options.p2p_bind)
            .map_err(|_| ProcessError("Guardian listener bind failed"))?;
        drop(startup);
        if shutdown.is_requested() {
            return Ok(());
        }
        let context = Context {
            options: &options,
            store,
            backend,
            admin,
            access,
            shutdown,
        };
        let (service, jobs) = if let Some(restored) = restored {
            let addresses = resolve_peers(restored.peer_urls(), shutdown)?;
            let ready = restored
                .connect(peer_listener, addresses, 256)
                .map_err(|_| ProcessError("Guardian reconnect failed"))?;
            let running = context.start_running(ready, &mut owners)?;
            (Arc::new(Service::restored(running)), None)
        } else {
            let (setup, jobs) = SetupApi::new(
                SetupState::new(
                    options.api_url.clone(),
                    options.p2p_url.clone(),
                    options.bitcoin_network,
                    "0.13.0".into(),
                ),
                context.admin.clone(),
            )
            .map_err(|_| ProcessError("Setup API initialization failed"))?;
            (
                Arc::new(Service::setup(Arc::new(setup))),
                Some((jobs, peer_listener)),
            )
        };
        owners.server = Some(
            Server::start(
                api_listener,
                service.clone(),
                context.access.clone(),
                Limits::default(),
                128,
            )
            .map_err(|_| ProcessError("API listener startup failed"))?,
        );
        if let Some((jobs, peer_listener)) = jobs {
            let job = loop {
                if shutdown.is_requested() {
                    return Ok(());
                }
                owners.check()?;
                match jobs.try_recv() {
                    Ok(job) => break job,
                    Err(TryRecvError::Disconnected) => {
                        return Err(ProcessError("Setup driver disconnected"));
                    }
                    Err(TryRecvError::Empty) => thread::sleep(TICK),
                }
            };
            let plan = SetupPlan::new(job, &expected)
                .map_err(|_| ProcessError("Guardian setup configuration invalid"))?;
            let addresses = resolve_peers(plan.peer_urls(), shutdown)?;
            owners.generation = Some(
                plan.start(context.store.clone(), peer_listener, addresses, 256)
                    .map_err(|_| ProcessError("Guardian generation startup failed"))?,
            );
            while !owners
                .generation
                .as_ref()
                .is_some_and(Generation::is_finished)
            {
                if shutdown.is_requested() {
                    return Ok(());
                }
                owners.check()?;
                thread::sleep(TICK);
            }
            let ready = owners
                .generation
                .take()
                .ok_or(ProcessError("Missing generation owner"))?
                .finish()
                .map_err(|_| ProcessError("Guardian generation failed"))?;
            if shutdown.is_requested() {
                owners.network = Some(ready.network);
                return Ok(());
            }
            let running = context.start_running(ready, &mut owners)?;
            if shutdown.is_requested() {
                return Ok(());
            }
            service
                .install(running)
                .map_err(|_| ProcessError("Running API installation failed"))?;
        }
        let mut next_refresh = Instant::now();
        while !shutdown.is_requested() {
            owners.check()?;
            if Instant::now() >= next_refresh {
                context.refresh_catchup(&mut owners)?;
                next_refresh = Instant::now() + Duration::from_secs(1);
            }
            thread::sleep(TICK);
        }
        Ok(())
    })();
    let cleanup = owners.shutdown();
    result.and(cleanup)
}
