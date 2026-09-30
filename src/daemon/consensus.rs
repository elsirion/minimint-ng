//! Ordered guardian controller. Network envelopes have no added session prefix.
//! Only local commands carry an epoch; native agreement validates unit sessions.
//! Shutdown is cooperative and joined, not a hard wall-clock deadline guarantee.
use super::config::RuntimeConfig;
use crate::{
    agreement::{AgreementError, EngineIo, FinalizedUnit, ProposalQueue},
    api::core::ProposalUnavailable,
    bitcoin::{BitcoinBackend, rpc::CoreRpc},
    codec::{ConsensusEncode, DecodeError, Reader},
    core::session::{self, Phase, Session, SessionError},
    modules::wallet::{self, WalletError},
    net::{PeerNetwork, envelope::Envelope},
    protocol::{
        ConsensusItem, DynamicValue, ModuleId, ModuleRegistry, ModuleValueKind, PeerId,
        SignedSessionOutcome,
    },
    storage::{Store, StoreError},
};
use futures::{FutureExt, StreamExt};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Cancellation must interrupt retry loops and bound active calls by a finite
/// implementation-defined deadline. A backend that ignores it can prevent join.
/// Do not share one backend between independently stoppable runtimes.
/// Cancellation must be idempotent and must not panic, including during unwind.
pub trait RuntimeBackend: BitcoinBackend + Send + Sync + 'static {
    fn request_shutdown(&self);
}
impl RuntimeBackend for CoreRpc {
    fn request_shutdown(&self) {
        CoreRpc::request_shutdown(self);
    }
}
#[derive(Clone, Copy)]
pub struct RuntimeOptions {
    pub round_delay_ms: u64,
    pub queue_capacity: usize,
    pub tick: Duration,
    pub wallet_poll_interval: Duration,
}
impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            round_delay_ms: 50,
            queue_capacity: 256,
            tick: Duration::from_millis(10),
            wallet_poll_interval: Duration::from_secs(1),
        }
    }
}
#[derive(Debug)]
pub enum RuntimeError {
    Storage(StoreError),
    Fatal(&'static str),
}
impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Storage(_) => "guardian runtime storage failure",
            Self::Fatal(_) => "guardian runtime failure",
        })
    }
}
impl std::error::Error for RuntimeError {}
impl From<StoreError> for RuntimeError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
fn session_error(e: SessionError) -> RuntimeError {
    match e {
        SessionError::Storage(e) => RuntimeError::Storage(e),
        SessionError::Fatal(s) => RuntimeError::Fatal(s),
        _ => RuntimeError::Fatal("unexpected-session-result"),
    }
}
fn wallet_error(e: WalletError) -> RuntimeError {
    match e {
        WalletError::Storage(e) => RuntimeError::Storage(e),
        WalletError::Invariant(s) => RuntimeError::Fatal(s),
        _ => RuntimeError::Fatal("wallet-worker-invariant"),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryQueueError {
    Stale,
    Future,
    Full,
    Closed,
    Invalid,
}
enum Command {
    History {
        epoch: u64,
        outcome: SignedSessionOutcome,
    },
    Signature {
        epoch: u64,
        peer: PeerId,
        signature: [u8; 64],
    },
}
enum RouteQueue {
    Agreement(ProposalQueue),
    Single(VecDeque<ConsensusItem>),
}
struct Route {
    index: u64,
    queue: RouteQueue,
}
struct Shared {
    route: Mutex<Option<Route>>,
    revision: Mutex<u64>,
    wake: Condvar,
    stop: AtomicBool,
    capacity: usize,
    commands: SyncSender<Command>,
    cancel: Arc<dyn Fn() + Send + Sync>,
}
impl Shared {
    fn notify(&self) {
        if let Ok(mut n) = self.revision.lock() {
            *n = n.wrapping_add(1);
            self.wake.notify_all();
        }
    }
    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        (self.cancel)();
        self.notify();
    }
}
#[derive(Clone)]
pub struct RuntimeHandle {
    shared: Arc<Shared>,
    config: Arc<RuntimeConfig>,
    store: Store,
}
impl RuntimeHandle {
    pub(crate) fn store(&self) -> &Store {
        &self.store
    }
    pub(crate) fn config(&self) -> &Arc<RuntimeConfig> {
        &self.config
    }
    pub fn propose(&self, item: ConsensusItem) -> Result<(), ProposalUnavailable> {
        if self.shared.stop.load(Ordering::Acquire) {
            return Err(ProposalUnavailable::Closed);
        }
        let mut route = self
            .shared
            .route
            .lock()
            .map_err(|_| ProposalUnavailable::Closed)?;
        let route = route.as_mut().ok_or(ProposalUnavailable::SignaturePhase)?;
        match &mut route.queue {
            RouteQueue::Agreement(queue) => queue.push(item).map_err(|e| match e {
                AgreementError::QueueFull => ProposalUnavailable::Full,
                AgreementError::SignaturePhase => ProposalUnavailable::SignaturePhase,
                _ => ProposalUnavailable::Closed,
            }),
            RouteQueue::Single(queue) => {
                if queue.len() >= self.shared.capacity {
                    return Err(ProposalUnavailable::Full);
                }
                queue.push_back(item);
                Ok(())
            }
        }
    }
    pub fn current_session(&self) -> Option<u64> {
        self.shared.route.lock().ok()?.as_ref().map(|r| r.index)
    }
    /// Typed API history still receives the configured schema gate before queueing.
    /// Success is queued work, never an acknowledgement of history adoption.
    pub fn submit_history(
        &self,
        index: u64,
        outcome: SignedSessionOutcome,
    ) -> Result<(), HistoryQueueError> {
        outcome
            .outcome
            .validate_modules(self.config.modules())
            .map_err(|_| HistoryQueueError::Invalid)?;
        let route = self
            .shared
            .route
            .lock()
            .map_err(|_| HistoryQueueError::Closed)?;
        let route = route.as_ref().ok_or(HistoryQueueError::Closed)?;
        if self.shared.stop.load(Ordering::Acquire) {
            return Err(HistoryQueueError::Closed);
        }
        if index < route.index {
            return Err(HistoryQueueError::Stale);
        }
        if index > route.index {
            return Err(HistoryQueueError::Future);
        }
        self.shared
            .commands
            .try_send(Command::History {
                epoch: index,
                outcome,
            })
            .map_err(|e| match e {
                TrySendError::Full(_) => HistoryQueueError::Full,
                TrySendError::Disconnected(_) => HistoryQueueError::Closed,
            })
    }
    /// Capture before polling API state; wait rechecks under the notification lock.
    pub fn revision(&self) -> u64 {
        self.shared.revision.lock().map(|n| *n).unwrap_or(u64::MAX)
    }
    pub fn wait_for_change(&self, observed: u64, timeout: Duration) -> u64 {
        let Ok(n) = self.shared.revision.lock() else {
            return u64::MAX;
        };
        let Ok((n, _)) = self.shared.wake.wait_timeout_while(n, timeout, |n| {
            *n == observed && !self.shared.stop.load(Ordering::Acquire)
        }) else {
            return u64::MAX;
        };
        *n
    }
    pub fn request_shutdown(&self) {
        self.shared.stop();
    }
    pub fn is_stopped(&self) -> bool {
        self.shared.stop.load(Ordering::Acquire)
    }
}
pub struct Runtime {
    handle: RuntimeHandle,
    worker: Option<JoinHandle<Result<(), RuntimeError>>>,
}
impl Runtime {
    pub fn start<B: RuntimeBackend>(
        store: Store,
        config: Arc<RuntimeConfig>,
        network: Arc<PeerNetwork>,
        backend: Arc<B>,
        options: RuntimeOptions,
    ) -> Result<(Self, RuntimeHandle), RuntimeError> {
        if options.queue_capacity == 0
            || options.tick.is_zero()
            || options.wallet_poll_interval.is_zero()
        {
            return Err(RuntimeError::Fatal("runtime-options"));
        }
        let initial = start_session(&store, &config, options)?;
        let (commands, receiver) = mpsc::sync_channel(options.queue_capacity);
        let cancel_backend = backend.clone();
        let shared = Arc::new(Shared {
            route: Mutex::new(None),
            revision: Mutex::new(0),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
            capacity: options.queue_capacity,
            commands,
            cancel: Arc::new(move || cancel_backend.request_shutdown()),
        });
        let handle = RuntimeHandle {
            shared,
            config: config.clone(),
            store: store.clone(),
        };
        let worker_handle = handle.clone();
        let worker = thread::Builder::new()
            .name("guardian-ordered-runtime".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(
                        store,
                        network,
                        backend,
                        options,
                        initial,
                        receiver,
                        &worker_handle,
                    )
                }))
                .unwrap_or(Err(RuntimeError::Fatal("runtime-panicked")));
                worker_handle.shared.stop();
                if let Ok(mut route) = worker_handle.shared.route.lock() {
                    *route = None;
                }
                worker_handle.shared.notify();
                result
            })
            .map_err(|_| RuntimeError::Fatal("runtime-spawn"))?;
        Ok((
            Self {
                handle: handle.clone(),
                worker: Some(worker),
            },
            handle,
        ))
    }
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
    pub fn request_shutdown(&self) {
        self.handle.request_shutdown();
    }
    pub fn shutdown(mut self) -> Result<(), RuntimeError> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<(), RuntimeError> {
        self.request_shutdown();
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| RuntimeError::Fatal("runtime-panicked"))?,
            None => Ok(()),
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}
struct SessionSlot(Option<Session>);
impl std::ops::Deref for SessionSlot {
    type Target = Session;
    fn deref(&self) -> &Session {
        self.0.as_ref().expect("owned active session")
    }
}
impl std::ops::DerefMut for SessionSlot {
    fn deref_mut(&mut self) -> &mut Session {
        self.0.as_mut().expect("owned active session")
    }
}
impl SessionSlot {
    fn abort(&mut self) -> Result<(), RuntimeError> {
        match self.0.take() {
            Some(session) => session.abort().map_err(session_error),
            None => Ok(()),
        }
    }
    fn finish(&mut self) -> Result<(), RuntimeError> {
        self.0
            .take()
            .ok_or(RuntimeError::Fatal("missing-active-session"))?
            .finish()
            .map(|_| ())
            .map_err(session_error)
    }
}
struct Active {
    session: SessionSlot,
    io: Option<EngineIo>,
    proposals: ProposalQueue,
    pump: Option<Pump>,
    finalized: Option<Receiver<FinalizedUnit>>,
}
impl Drop for Active {
    fn drop(&mut self) {
        // Unwind/early-return ordering is identical to normal cancellation:
        // retain the network pump and finalized receiver until engine join.
        if let Some(pump) = &self.pump {
            pump.joining.store(true, Ordering::Release);
        }
        let _ = self.session.abort();
        if let Some(pump) = self.pump.take() {
            let _ = pump.join();
        }
    }
}
struct WalletWorker {
    worker: Option<JoinHandle<Result<(), RuntimeError>>>,
    stop: RuntimeHandle,
}
impl WalletWorker {
    fn join(&mut self) -> Result<(), RuntimeError> {
        self.stop.request_shutdown();
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| RuntimeError::Fatal("wallet-poller-panicked"))?,
            None => Ok(()),
        }
    }
}
impl Drop for WalletWorker {
    fn drop(&mut self) {
        let _ = self.join();
    }
}
fn start_session(
    store: &Store,
    config: &RuntimeConfig,
    options: RuntimeOptions,
) -> Result<Active, RuntimeError> {
    let sc = config
        .session_config()
        .map_err(|_| RuntimeError::Fatal("runtime-session-config"))?;
    if sc.broadcast_keys.len() == 1 {
        let session = Session::open(store.clone(), sc).map_err(session_error)?;
        let (proposals, _) = ProposalQueue::new(options.queue_capacity)
            .map_err(|_| RuntimeError::Fatal("runtime-capacity"))?;
        Ok(Active {
            session: SessionSlot(Some(session)),
            pump: None,
            finalized: None,
            io: None,
            proposals,
        })
    } else {
        let (session, io, proposals) = Session::start(
            store.clone(),
            sc,
            options.round_delay_ms,
            options.queue_capacity,
        )
        .map_err(session_error)?;
        Ok(Active {
            session: SessionSlot(Some(session)),
            pump: None,
            finalized: None,
            io: Some(io),
            proposals,
        })
    }
}
struct EmptyRegistry;
impl ModuleRegistry for EmptyRegistry {
    fn decode_payload(
        &self,
        _: ModuleId,
        _: ModuleValueKind,
        _: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        Err(DecodeError::UnknownModule)
    }
}
struct Pump {
    joining: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: JoinHandle<Result<(), RuntimeError>>,
}
impl Pump {
    fn join(self) -> Result<(), RuntimeError> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .join()
            .map_err(|_| RuntimeError::Fatal("network-pump-panicked"))?
    }
}
fn pump(
    store: Store,
    config: Arc<RuntimeConfig>,
    network: Arc<PeerNetwork>,
    io: Option<EngineIo>,
    epoch: u64,
    shared: Arc<Shared>,
    tick: Duration,
) -> Result<(Pump, Option<Receiver<FinalizedUnit>>), RuntimeError> {
    let (mut inbound, mut outbound, finalized) = match io {
        Some(io) => (Some(io.inbound), Some(io.outbound), Some(io.finalized)),
        None => (None, None, None),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let joining = Arc::new(AtomicBool::new(false));
    let engine_joining = joining.clone();
    let worker = thread::Builder::new()
        .name("guardian-network-pump".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                while !stopped.load(Ordering::Acquire) {
                    if let Some(outbound) = &mut outbound {
                        // Bound each pass so sustained agreement traffic cannot starve receive.
                        for _ in 0..64 {
                            let message = match outbound.next().now_or_never() {
                                Some(Some(message)) => message,
                                Some(None) if !engine_joining.load(Ordering::Acquire) => {
                                    return Err(RuntimeError::Fatal("agreement-network-closed"));
                                }
                                _ => break,
                            };
                            match message.recipient {
                                Some(peer) if peer != config.peer() => {
                                    let _ =
                                        network.send(peer, Envelope::Agreement(message.payload));
                                }
                                None => {
                                    for peer in config.remote_peer_urls().keys() {
                                        let _ = network.send(
                                            *peer,
                                            Envelope::Agreement(message.payload.clone()),
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    let received = network
                        .recv_timeout(tick)
                        .map_err(|_| RuntimeError::Fatal("peer-network-closed"))?;
                    if let Some((peer, message)) = received {
                        match message {
                            Envelope::Agreement(bytes) => {
                                if let Some(inbound) = &mut inbound {
                                    let _ = inbound.try_send(bytes);
                                }
                            }
                            Envelope::SessionSignature(signature) => {
                                let _ = shared.commands.try_send(Command::Signature {
                                    epoch,
                                    peer,
                                    signature,
                                });
                            }
                            Envelope::SessionIndex(index) => {
                                if let Some(outcome) = session::completed(&store.snapshot()?, index)
                                    .map_err(session_error)?
                                {
                                    let _ = network.send(
                                        peer,
                                        Envelope::SignedSessionOutcome(outcome.consensus_encode()),
                                    );
                                }
                            }
                            Envelope::SignedSessionOutcome(bytes) => {
                                if let Ok(outcome) = SignedSessionOutcome::decode_with_registry(
                                    &bytes,
                                    &EmptyRegistry,
                                ) {
                                    let _ = shared
                                        .commands
                                        .try_send(Command::History { epoch, outcome });
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Ok(())
            }))
            .unwrap_or(Err(RuntimeError::Fatal("network-pump-panicked")));
            if result.is_err() {
                shared.stop();
            }
            result
        })
        .map_err(|_| RuntimeError::Fatal("network-pump-spawn"))?;
    Ok((
        Pump {
            joining,
            stop,
            worker,
        },
        finalized,
    ))
}
fn wallet_pass<B: RuntimeBackend>(
    store: &Store,
    config: &RuntimeConfig,
    backend: &B,
    handle: &RuntimeHandle,
) -> Result<(), RuntimeError> {
    let wallet = config.modules().wallet();
    let snapshot = store.snapshot()?;
    let mut items = wallet.local_signatures(&snapshot).map_err(wallet_error)?;
    if let Ok(count) = backend.block_count() {
        items.push(
            wallet
                .block_proposal(&snapshot, count)
                .map_err(wallet_error)?,
        );
    }
    // WAL-004: an unavailable backend must withdraw the previous fee vote.
    // Preserve successful-but-absent estimates as None pending Q16's separate
    // clarification of the available-backend floor policy.
    items.push(wallet::Wallet::fee_proposal(
        backend.fee_rate().unwrap_or(None),
    ));
    for item in items {
        if handle
            .propose(ConsensusItem::Module(DynamicValue {
                module_id: wallet.module_id(),
                payload: item.consensus_encode(),
            }))
            .is_err()
        {
            break;
        }
    }
    match wallet.broadcast_pending(store, backend) {
        Ok(()) | Err(WalletError::Backend(_)) => Ok(()),
        Err(e) => Err(wallet_error(e)),
    }
}
fn run<B: RuntimeBackend>(
    store: Store,
    network: Arc<PeerNetwork>,
    backend: Arc<B>,
    options: RuntimeOptions,
    mut active: Active,
    commands: Receiver<Command>,
    handle: &RuntimeHandle,
) -> Result<(), RuntimeError> {
    let config = handle.config.clone();
    let wallet_handle = handle.clone();
    let wallet_store = store.clone();
    let wallet_config = config.clone();
    let wallet_backend = backend.clone();
    let wallet_worker = thread::Builder::new()
        .name("guardian-wallet-poller".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                while !wallet_handle.is_stopped() {
                    let result = wallet_pass(
                        &wallet_store,
                        &wallet_config,
                        wallet_backend.as_ref(),
                        &wallet_handle,
                    );
                    if result.is_err() {
                        wallet_handle.request_shutdown();
                        return result;
                    }
                    let deadline = Instant::now() + options.wallet_poll_interval;
                    while !wallet_handle.is_stopped() && Instant::now() < deadline {
                        thread::sleep(
                            options
                                .tick
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                }
                Ok(())
            }))
            .unwrap_or(Err(RuntimeError::Fatal("wallet-poller-panicked")));
            if result.is_err() {
                wallet_handle.request_shutdown();
            }
            result
        })
        .map_err(|_| RuntimeError::Fatal("wallet-poller-spawn"))?;
    let mut wallet_worker = WalletWorker {
        worker: Some(wallet_worker),
        stop: handle.clone(),
    };
    let result = (|| {
        loop {
            let notifier = handle.shared.clone();
            active
                .session
                .set_commit_notifier(Arc::new(move || notifier.notify()));
            let index = active.session.status().index;
            let single = active.io.is_none();
            let (pump, finalized) = pump(
                store.clone(),
                config.clone(),
                network.clone(),
                active.io.take(),
                index,
                handle.shared.clone(),
                options.tick,
            )?;
            active.pump = Some(pump);
            active.finalized = finalized;
            *handle
                .shared
                .route
                .lock()
                .map_err(|_| RuntimeError::Fatal("proposal-route-lock"))? = Some(Route {
                index,
                queue: if single {
                    RouteQueue::Single(VecDeque::new())
                } else {
                    RouteQueue::Agreement(active.proposals.clone())
                },
            });
            handle.shared.notify();
            let started = Instant::now();
            let mut single_front = None;
            let mut retry = false;
            let execution = (|| {
                while !handle.is_stopped() {
                    if active.pump.as_ref().is_none_or(|p| p.worker.is_finished()) {
                        return Err(RuntimeError::Fatal("network-pump-stopped"));
                    }
                    active.session.check_health().map_err(session_error)?;
                    // A pinned adoption or unprocessed finalized item always retries
                    // before newer history commands, signatures, or finalized units.
                    if !retry && let Ok(command) = commands.try_recv() {
                        match command {
                            Command::History { epoch, outcome } if epoch == index => match active
                                .session
                                .adopt(outcome, config.modules(), backend.as_ref())
                            {
                                Ok(()) | Err(SessionError::Rejected) => {}
                                Err(SessionError::Retry) => retry = true,
                                Err(e) => return Err(session_error(e)),
                            },
                            Command::Signature {
                                epoch,
                                peer,
                                signature,
                            } if epoch == index => {
                                match active.session.receive_signature(peer, signature) {
                                    Ok(()) | Err(SessionError::Rejected) => {}
                                    Err(e) => return Err(session_error(e)),
                                }
                            }
                            _ => {}
                        }
                    }
                    if active.session.status().phase != Phase::Ready {
                        let result = if single && retry && single_front.is_none() {
                            active.session.drive(
                                config.modules(),
                                backend.as_ref(),
                                &active.proposals,
                            )
                        } else if single {
                            if single_front.is_none()
                                && let Some(Route {
                                    queue: RouteQueue::Single(queue),
                                    ..
                                }) = handle
                                    .shared
                                    .route
                                    .lock()
                                    .map_err(|_| RuntimeError::Fatal("proposal-route-lock"))?
                                    .as_mut()
                            {
                                single_front = queue.pop_front();
                            }
                            if let Some(item) = single_front.clone() {
                                active.session.process_single(
                                    item,
                                    started.elapsed(),
                                    config.modules(),
                                    backend.as_ref(),
                                    &active.proposals,
                                )
                            } else {
                                active.session.drive(
                                    config.modules(),
                                    backend.as_ref(),
                                    &active.proposals,
                                )
                            }
                        } else {
                            if !retry && let Some(finalized) = &active.finalized {
                                match finalized.try_recv() {
                                    Ok(unit) => active.session.enqueue(unit),
                                    Err(mpsc::TryRecvError::Disconnected) => {
                                        return Err(RuntimeError::Fatal("finalized-stream-closed"));
                                    }
                                    Err(mpsc::TryRecvError::Empty) => {}
                                }
                            }
                            active.session.drive(
                                config.modules(),
                                backend.as_ref(),
                                &active.proposals,
                            )
                        };
                        match result {
                            Ok(()) | Err(SessionError::Rejected) => {
                                retry = false;
                                single_front = None;
                            }
                            Err(SessionError::Retry) => retry = true,
                            Err(e) => return Err(session_error(e)),
                        }
                    }
                    // Also wakes Full retries when the native provider drained its
                    // queue without an application commit (no provider callback).
                    handle.shared.notify();
                    if active.session.status().phase == Phase::Ready {
                        return Ok(true);
                    }
                    thread::sleep(options.tick);
                }
                Ok(false)
            })();
            *handle
                .shared
                .route
                .lock()
                .map_err(|_| RuntimeError::Fatal("proposal-route-lock"))? = None;
            handle.shared.notify();
            // Keep the pump alive until finish/drop has joined the actual engine.
            if let Some(pump) = &active.pump {
                pump.joining.store(true, Ordering::Release);
            }
            let completion = match execution {
                Ok(true) => active.session.finish().map(|_| true),
                Ok(false) => active.session.abort().map(|_| false),
                Err(error) => {
                    let _ = active.session.abort();
                    Err(error)
                }
            };
            let pump_result = active
                .pump
                .take()
                .ok_or(RuntimeError::Fatal("missing-network-pump"))?
                .join();
            pump_result?;
            let completed = completion?;
            handle.shared.notify();
            if !completed || handle.is_stopped() {
                return Ok(());
            }
            active = start_session(&store, &config, options)?;
        }
    })();
    handle.request_shutdown();
    let wallet_result = wallet_worker.join();
    result.and(wallet_result)
}
