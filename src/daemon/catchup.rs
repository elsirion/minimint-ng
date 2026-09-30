//! Module-aware signed history over the guardian WebSocket API. The direct peer
//! envelope path deliberately retains its separate empty-registry limitation.
use super::{
    config::RuntimeConfig,
    consensus::{HistoryQueueError, RuntimeHandle},
};
use crate::{
    api::{
        announcements::SignedAnnouncement,
        websocket::{Limits, Message, WebSocket},
    },
    codec::rpc,
    config::CanonicalUrl,
    core::history::{HistoryVerifier, SignaturePolicy},
    crypto::secp,
    json,
    protocol::{PeerId, SignedSessionOutcome},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};
use std::{
    collections::BTreeSet,
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatchupError {
    InvalidConfiguration,
    UnsupportedTransport,
    Transport,
    Timeout,
    Cancelled,
    InvalidResponse,
    Rpc,
    InvalidHistory,
    Worker,
    StaleAnnouncement,
    EndpointChanged,
}
impl std::fmt::Display for CatchupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "Invalid catch-up configuration",
            Self::UnsupportedTransport => "Unsupported catch-up transport",
            Self::Transport => "History transport failed",
            Self::Timeout => "History request timed out",
            Self::Cancelled => "History catch-up stopped",
            Self::InvalidResponse => "Invalid history response",
            Self::Rpc => "History request failed",
            Self::InvalidHistory => "Invalid signed history",
            Self::Worker => "History worker failed",
            Self::StaleAnnouncement => "Endpoint announcement is no longer current",
            Self::EndpointChanged => "History endpoint changed",
        })
    }
}
impl std::error::Error for CatchupError {}
#[derive(Clone)]
pub struct CatchupEndpoint {
    peer: PeerId,
    url: CanonicalUrl,
    addresses: Vec<SocketAddr>,
    announcement: Option<SignedAnnouncement>,
}
impl CatchupEndpoint {
    /// Restore an accepted override without DNS or a usable transport. Startup
    /// verifies the configured signer and leaves this peer parked until matching
    /// addresses are installed. It never falls back to the configured URL.
    pub fn pending_announcement(peer: PeerId, announcement: SignedAnnouncement) -> Self {
        Self {
            peer,
            url: announcement.api_announcement.api_url.clone(),
            addresses: vec![],
            announcement: Some(announcement),
        }
    }
    /// Addresses must be resolved by the driver before starting this worker; DNS
    /// resolution is not covered by the request deadline. The URL must match the
    /// immutable configured endpoint unless accompanied by a valid announcement.
    pub fn new(
        peer: PeerId,
        url: CanonicalUrl,
        addresses: Vec<SocketAddr>,
    ) -> Result<Self, CatchupError> {
        let (_, _, port) = ws_parts(&url)?;
        if addresses.is_empty() || addresses.iter().any(|address| address.port() != port) {
            return Err(CatchupError::InvalidConfiguration);
        }
        Ok(Self {
            peer,
            url,
            addresses,
            announcement: None,
        })
    }
    /// The caller selects the current operational announcement using the
    /// announcement store's nonce rules. Startup verifies its peer signature;
    /// this transport does not maintain a second announcement revision store.
    pub fn announced(
        peer: PeerId,
        announcement: SignedAnnouncement,
        addresses: Vec<SocketAddr>,
    ) -> Result<Self, CatchupError> {
        let mut endpoint = Self::new(
            peer,
            announcement.api_announcement.api_url.clone(),
            addresses,
        )?;
        endpoint.announcement = Some(announcement);
        Ok(endpoint)
    }
}
fn ws_parts(url: &CanonicalUrl) -> Result<(&str, &str, u16), CatchupError> {
    let text = url
        .as_str()
        .strip_prefix("ws://")
        .ok_or(CatchupError::UnsupportedTransport)?;
    let slash = text.find('/').ok_or(CatchupError::InvalidConfiguration)?;
    let (authority, path) = text.split_at(slash);
    let port = authority
        .rsplit_once(':')
        .map(|(_, port)| port.parse::<u16>())
        .transpose()
        .map_err(|_| CatchupError::InvalidConfiguration)?
        .unwrap_or(80);
    Ok((authority, path, port))
}
#[derive(Clone, Copy)]
pub struct CatchupOptions {
    pub request_timeout: Duration,
    pub retry_interval: Duration,
    pub max_response_bytes: usize,
}
impl Default for CatchupOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(1),
            max_response_bytes: 16 * 1024 * 1024,
        }
    }
}
struct ActiveRequest {
    peer: PeerId,
    changed: bool,
    deadline: Instant,
    socket: Option<TcpStream>,
    expired: bool,
}
#[derive(Clone)]
struct EndpointSlot {
    endpoint: CatchupEndpoint,
    revision: u64,
    ready: bool,
}
struct Routing {
    endpoints: Vec<EndpointSlot>,
    active: Option<ActiveRequest>,
}
impl Routing {
    fn invalidate(&mut self, peer: PeerId) {
        if let Some(active) = &mut self.active
            && active.peer == peer
        {
            active.changed = true;
            if let Some(socket) = &active.socket {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointUpdate {
    Unchanged,
    Updated,
}
struct Control {
    stop: AtomicBool,
    routing: Mutex<Routing>,
    last_error: Mutex<Option<CatchupError>>,
    pause: Mutex<()>,
    wake: Condvar,
}
impl Control {
    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(routing) = self.routing.lock()
            && let Some(active) = routing.active.as_ref()
            && let Some(socket) = &active.socket
        {
            let _ = socket.shutdown(Shutdown::Both);
        }
        self.wake.notify_all();
    }
    fn check(&self) -> Result<(), CatchupError> {
        if self.stop.load(Ordering::Acquire) {
            return Err(CatchupError::Cancelled);
        }
        let routing = self.routing.lock().map_err(|_| CatchupError::Worker)?;
        if routing.active.as_ref().is_some_and(|active| active.changed) {
            return Err(CatchupError::EndpointChanged);
        }
        if routing
            .active
            .as_ref()
            .is_some_and(|active| active.expired || Instant::now() >= active.deadline)
        {
            return Err(CatchupError::Timeout);
        }
        Ok(())
    }
    fn pause(&self, duration: Duration) {
        if let Ok(lock) = self.pause.lock() {
            let _ = self
                .wake
                .wait_timeout_while(lock, duration, |_| !self.stop.load(Ordering::Acquire));
        }
    }
    fn request(
        &self,
        deadline: Instant,
        selected: &EndpointSlot,
    ) -> Result<RequestGuard<'_>, CatchupError> {
        self.check()?;
        let mut routing = self.routing.lock().map_err(|_| CatchupError::Worker)?;
        if !routing.endpoints.iter().any(|slot| {
            slot.endpoint.peer == selected.endpoint.peer
                && slot.revision == selected.revision
                && slot.ready
        }) {
            return Err(CatchupError::EndpointChanged);
        }
        routing.active = Some(ActiveRequest {
            peer: selected.endpoint.peer,
            changed: false,
            deadline,
            socket: None,
            expired: false,
        });
        Ok(RequestGuard(self))
    }
    fn socket(&self, socket: &TcpStream) -> Result<(), CatchupError> {
        self.check()?;
        let mut routing = self.routing.lock().map_err(|_| CatchupError::Worker)?;
        let request = routing.active.as_mut().ok_or(CatchupError::Worker)?;
        request.socket = Some(socket.try_clone().map_err(|_| CatchupError::Transport)?);
        if self.stop.load(Ordering::Acquire)
            || request.changed
            || request.expired
            || Instant::now() >= request.deadline
        {
            let _ = socket.shutdown(Shutdown::Both);
            return Err(if self.stop.load(Ordering::Acquire) {
                CatchupError::Cancelled
            } else if request.changed {
                CatchupError::EndpointChanged
            } else {
                CatchupError::Timeout
            });
        }
        Ok(())
    }
    fn monitor(&self, runtime: &RuntimeHandle) {
        while !self.stop.load(Ordering::Acquire) {
            if runtime.is_stopped() {
                self.stop();
                break;
            }
            if let Ok(mut routing) = self.routing.lock()
                && let Some(active) = routing.active.as_mut()
                && Instant::now() >= active.deadline
            {
                active.expired = true;
                if let Some(socket) = &active.socket {
                    let _ = socket.shutdown(Shutdown::Both);
                }
            }
            self.pause(Duration::from_millis(10));
        }
    }
}
struct RequestGuard<'a>(&'a Control);
impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut routing) = self.0.routing.lock() {
            routing.active = None;
        }
    }
}
pub struct Catchup {
    control: Arc<Control>,
    config: Arc<RuntimeConfig>,
    worker: Option<JoinHandle<Result<(), CatchupError>>>,
}
impl Catchup {
    pub fn start(
        runtime: RuntimeHandle,
        endpoints: Vec<CatchupEndpoint>,
        access_secret: Option<Zeroizing<String>>,
        options: CatchupOptions,
    ) -> Result<Self, CatchupError> {
        let config = runtime.config().clone();
        if endpoints.is_empty()
            || options.request_timeout.is_zero()
            || options.retry_interval.is_zero()
            || options.max_response_bytes == 0
            || Instant::now()
                .checked_add(options.request_timeout)
                .is_none()
            || Instant::now().checked_add(options.retry_interval).is_none()
        {
            return Err(CatchupError::InvalidConfiguration);
        }
        let mut peers = BTreeSet::new();
        for endpoint in &endpoints {
            let expected = config
                .server_config()
                .api_endpoints
                .get(&endpoint.peer)
                .ok_or(CatchupError::InvalidConfiguration)?;
            if endpoint.peer == config.peer() || !peers.insert(endpoint.peer) {
                return Err(CatchupError::InvalidConfiguration);
            }
            if let Some(signed) = &endpoint.announcement {
                let key = config
                    .server_config()
                    .broadcast_public_keys
                    .get(&endpoint.peer)
                    .ok_or(CatchupError::InvalidConfiguration)?;
                let public = secp::x_only(key).map_err(|_| CatchupError::InvalidConfiguration)?;
                secp::schnorr_verify(
                    &public,
                    &signed.api_announcement.digest(),
                    &signed.signature,
                )
                .map_err(|_| CatchupError::InvalidConfiguration)?;
            } else if endpoint.url != expected.url {
                return Err(CatchupError::InvalidConfiguration);
            }
        }
        let verifier = HistoryVerifier::new(config.server_config().broadcast_public_keys.clone())
            .map_err(|_| CatchupError::InvalidConfiguration)?;
        let control = Arc::new(Control {
            stop: AtomicBool::new(false),
            routing: Mutex::new(Routing {
                endpoints: endpoints
                    .into_iter()
                    .map(|endpoint| EndpointSlot {
                        ready: !endpoint.addresses.is_empty(),
                        endpoint,
                        revision: 0,
                    })
                    .collect(),
                active: None,
            }),
            last_error: Mutex::new(None),
            pause: Mutex::new(()),
            wake: Condvar::new(),
        });
        let shared = control.clone();
        let owner_config = config.clone();
        let worker = thread::Builder::new()
            .name("guardian-api-catchup".into())
            .spawn(move || {
                thread::scope(|scope| {
                    scope.spawn(|| shared.monitor(&runtime));
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run(
                            &runtime,
                            &config,
                            access_secret.as_ref().map(|s| s.as_str()),
                            options,
                            &verifier,
                            &shared,
                        )
                    }))
                    .unwrap_or(Err(CatchupError::Worker));
                    shared.stop();
                    result
                })
            })
            .map_err(|_| CatchupError::Worker)?;
        Ok(Self {
            control,
            config: owner_config,
            worker: Some(worker),
        })
    }
    fn verify_announcement(
        &self,
        peer: PeerId,
        signed: &SignedAnnouncement,
    ) -> Result<(), CatchupError> {
        if peer == self.config.peer() {
            return Err(CatchupError::InvalidConfiguration);
        }
        let key = self
            .config
            .server_config()
            .broadcast_public_keys
            .get(&peer)
            .ok_or(CatchupError::InvalidConfiguration)?;
        let public = secp::x_only(key).map_err(|_| CatchupError::InvalidConfiguration)?;
        secp::schnorr_verify(
            &public,
            &signed.api_announcement.digest(),
            &signed.signature,
        )
        .map_err(|_| CatchupError::InvalidConfiguration)
    }
    /// Select a verified operational override before resolving it. A new selection
    /// parks this peer and interrupts its old request; other peers remain usable.
    /// Even an unsupported transport parks the old URL. Resolution/transport
    /// errors must not silently restore the immutable configured endpoint.
    pub fn select_announcement(
        &self,
        peer: PeerId,
        signed: SignedAnnouncement,
    ) -> Result<EndpointUpdate, CatchupError> {
        self.verify_announcement(peer, &signed)?;
        if self.control.stop.load(Ordering::Acquire) {
            return Err(CatchupError::Cancelled);
        }
        let mut routing = self
            .control
            .routing
            .lock()
            .map_err(|_| CatchupError::Worker)?;
        let slot = routing
            .endpoints
            .iter_mut()
            .find(|slot| slot.endpoint.peer == peer)
            .ok_or(CatchupError::InvalidConfiguration)?;
        if let Some(previous) = &slot.endpoint.announcement {
            if previous.api_announcement == signed.api_announcement {
                return Ok(EndpointUpdate::Unchanged);
            }
            if signed.api_announcement.nonce <= previous.api_announcement.nonce {
                return Err(CatchupError::StaleAnnouncement);
            }
        }
        slot.revision = slot.revision.checked_add(1).ok_or(CatchupError::Worker)?;
        slot.ready = false;
        slot.endpoint = CatchupEndpoint {
            peer,
            url: signed.api_announcement.api_url.clone(),
            addresses: vec![],
            announcement: Some(signed),
        };
        routing.invalidate(peer);
        self.control.wake.notify_all();
        Ok(EndpointUpdate::Updated)
    }
    /// Install caller-resolved addresses only for the currently selected signed
    /// fields. A newer selection while DNS runs makes this result stale. The
    /// caller bounds and joins resolution; catch-up never starts resolver threads.
    pub fn install_resolved(
        &self,
        peer: PeerId,
        signed: &SignedAnnouncement,
        addresses: Vec<SocketAddr>,
    ) -> Result<EndpointUpdate, CatchupError> {
        self.verify_announcement(peer, signed)?;
        let endpoint = CatchupEndpoint::announced(peer, signed.clone(), addresses)?;
        if self.control.stop.load(Ordering::Acquire) {
            return Err(CatchupError::Cancelled);
        }
        let mut routing = self
            .control
            .routing
            .lock()
            .map_err(|_| CatchupError::Worker)?;
        let slot = routing
            .endpoints
            .iter_mut()
            .find(|slot| slot.endpoint.peer == peer)
            .ok_or(CatchupError::InvalidConfiguration)?;
        if !slot
            .endpoint
            .announcement
            .as_ref()
            .is_some_and(|current| current.api_announcement == signed.api_announcement)
        {
            return Err(CatchupError::StaleAnnouncement);
        }
        if slot.ready && slot.endpoint.addresses == endpoint.addresses {
            return Ok(EndpointUpdate::Unchanged);
        }
        slot.revision = slot.revision.checked_add(1).ok_or(CatchupError::Worker)?;
        slot.ready = true;
        slot.endpoint = endpoint;
        routing.invalidate(peer);
        self.control.wake.notify_all();
        Ok(EndpointUpdate::Updated)
    }
    pub fn request_shutdown(&self) {
        self.control.stop();
    }
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn last_error(&self) -> Option<CatchupError> {
        self.control.last_error.lock().ok().and_then(|error| *error)
    }
    pub fn shutdown(mut self) -> Result<(), CatchupError> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<(), CatchupError> {
        self.request_shutdown();
        match self.worker.take() {
            Some(worker) => worker.join().map_err(|_| CatchupError::Worker)?,
            None => Ok(()),
        }
    }
}
impl Drop for Catchup {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}
fn fetch(
    index: u64,
    selected: &EndpointSlot,
    secret: Option<&str>,
    options: CatchupOptions,
    config: &RuntimeConfig,
    verifier: &HistoryVerifier,
    control: &Control,
) -> Result<SignedSessionOutcome, CatchupError> {
    let deadline = Instant::now()
        .checked_add(options.request_timeout)
        .ok_or(CatchupError::InvalidConfiguration)?;
    let _guard = control.request(deadline, selected)?;
    let endpoint = &selected.endpoint;
    let mut connected = None;
    for address in &endpoint.addresses {
        control.check()?;
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        if remaining.is_zero() {
            return Err(CatchupError::Timeout);
        }
        if let Ok(stream) = TcpStream::connect_timeout(address, remaining) {
            connected = Some(stream);
            break;
        }
    }
    let stream = connected.ok_or(CatchupError::Transport)?;
    control.socket(&stream)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    control.check()?;
    let limits = Limits {
        max_message_bytes: options.max_response_bytes,
        handshake_timeout: remaining,
        operation_timeout: remaining,
        ..Limits::default()
    };
    let (authority, path, _) = ws_parts(&endpoint.url)?;
    let mut ws = WebSocket::connect(stream, authority, path, secret, limits)
        .map_err(|_| control.check().err().unwrap_or(CatchupError::Transport))?;
    let request=json!({"jsonrpc":"2.0","id":1,"method":"await_signed_session_outcome","params":[{"auth":null,"params":index}]}).to_string();
    ws.send_text(&request)
        .map_err(|_| control.check().err().unwrap_or(CatchupError::Transport))?;
    let Message::Text(response) = ws
        .receive()
        .map_err(|_| control.check().err().unwrap_or(CatchupError::Transport))?
    else {
        return Err(CatchupError::InvalidResponse);
    };
    control.check()?;
    let response = json::parse(response.as_bytes(), options.max_response_bytes, 64)
        .map_err(|_| CatchupError::InvalidResponse)?;
    if response.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0")
        || response.get("id").and_then(|v| json::unsigned(v).ok()) != Some(1)
    {
        return Err(CatchupError::InvalidResponse);
    }
    let result = match (response.get("result"), response.get("error")) {
        (Some(result), None) => result,
        (None, Some(_)) => return Err(CatchupError::Rpc),
        _ => return Err(CatchupError::InvalidResponse),
    };
    let array = result
        .as_array()
        .filter(|array| array.len() == 1)
        .ok_or(CatchupError::InvalidResponse)?;
    let hex = array[0]
        .as_str()
        .ok_or(CatchupError::InvalidResponse)?
        .to_owned();
    let signed: SignedSessionOutcome =
        rpc::decode_hex(&[hex]).map_err(|_| CatchupError::InvalidHistory)?;
    signed
        .outcome
        .validate_modules(config.modules())
        .map_err(|_| CatchupError::InvalidHistory)?;
    verifier
        .verify(index, &signed, SignaturePolicy::GuardianAdoption)
        .map_err(|_| CatchupError::InvalidHistory)?;
    control.check()?;
    Ok(signed)
}
fn run(
    runtime: &RuntimeHandle,
    config: &RuntimeConfig,
    secret: Option<&str>,
    options: CatchupOptions,
    verifier: &HistoryVerifier,
    control: &Control,
) -> Result<(), CatchupError> {
    let mut next = 0usize;
    while !control.stop.load(Ordering::Acquire) && !runtime.is_stopped() {
        let Some(index) = runtime.current_session() else {
            control.pause(options.retry_interval);
            continue;
        };
        let selected = {
            let routing = control.routing.lock().map_err(|_| CatchupError::Worker)?;
            let mut selected = None;
            for _ in 0..routing.endpoints.len() {
                let slot = &routing.endpoints[next];
                next = (next + 1) % routing.endpoints.len();
                if slot.ready {
                    selected = Some(slot.clone());
                    break;
                }
            }
            selected
        };
        let Some(selected) = selected else {
            control.pause(options.retry_interval);
            continue;
        };
        let signed = match fetch(index, &selected, secret, options, config, verifier, control) {
            Ok(signed) => signed,
            Err(CatchupError::Cancelled) => break,
            Err(CatchupError::EndpointChanged) => continue,
            Err(error) => {
                if let Ok(mut last) = control.last_error.lock() {
                    *last = Some(error);
                }
                control.pause(options.retry_interval);
                continue;
            }
        };
        while !control.stop.load(Ordering::Acquire) && !runtime.is_stopped() {
            match runtime.submit_history(index, signed.clone()) {
                Ok(()) => {
                    while !control.stop.load(Ordering::Acquire)
                        && !runtime.is_stopped()
                        && runtime
                            .current_session()
                            .is_none_or(|current| current == index)
                    {
                        control.pause(options.retry_interval);
                    }
                    break;
                }
                Err(HistoryQueueError::Full | HistoryQueueError::Closed) => {
                    control.pause(options.retry_interval)
                }
                Err(HistoryQueueError::Stale | HistoryQueueError::Future) => break,
                Err(HistoryQueueError::Invalid) => return Err(CatchupError::InvalidHistory),
            }
        }
    }
    Ok(())
}
