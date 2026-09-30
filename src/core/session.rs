//! CON-004..010 ordered session application and restart recovery.
//!
//! Replicated private schema `core/session/v1/`: `count` is E(u64),
//! `completed/` + BE64(index) is E(SignedSessionOutcome), and `pending/` +
//! BE64(position) is E(AcceptedItem). Pending belongs to `count`. Only successful
//! engine shutdown permits the atomic completed/count/pending/backup update.
use super::{
    history::{HistoryVerifier, SignaturePolicy, header},
    transaction::{self, ExecutionError},
};
use crate::{
    agreement::{Data, EngineSession, FinalizedUnit, ProposalQueue},
    bitcoin::BitcoinBackend,
    codec::{ConsensusEncode, decode_whole},
    crypto::secp::SecretKey,
    modules::{
        Modules,
        wallet::{self, WalletError},
    },
    protocol::{
        AcceptedItem, ConsensusItem, PeerId, SessionOutcome, SignedSessionOutcome, Version,
        decode_batch,
    },
    storage::{Namespace, Snapshot, Store, StoreError},
};
use std::collections::{BTreeMap, VecDeque};
const COUNT: &[u8] = b"core/session/v1/count";
const COMPLETED: &[u8] = b"core/session/v1/completed/";
const PENDING: &[u8] = b"core/session/v1/pending/";
fn key(prefix: &[u8], index: u64) -> Vec<u8> {
    [prefix, &index.to_be_bytes()].concat()
}

#[derive(Debug)]
pub enum SessionError {
    Rejected,
    Retry,
    Storage(StoreError),
    Fatal(&'static str),
}
impl From<StoreError> for SessionError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected => "session item rejected",
            Self::Retry => "session work requires retry",
            Self::Storage(_) => "session storage failure",
            Self::Fatal(_) => "fatal session invariant failure",
        })
    }
}
impl std::error::Error for SessionError {}
fn wallet_error(e: WalletError) -> SessionError {
    match e {
        WalletError::Backend(_) | WalletError::StaleScan => SessionError::Retry,
        WalletError::Rejected(_) | WalletError::Module(_) => SessionError::Rejected,
        WalletError::Storage(e) => SessionError::Storage(e),
        _ => SessionError::Fatal("wallet-invariant"),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Collecting,
    Signing,
    Ready,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub index: u64,
    pub phase: Phase,
    pub pending: SessionOutcome,
    pub replay_cursor: usize,
}
pub struct SessionConfig {
    pub broadcast_keys: BTreeMap<PeerId, [u8; 33]>,
    pub local_peer: PeerId,
    pub local_key: SecretKey,
    pub version: Version,
    pub rounds: u16,
}
enum Work {
    Unit(FinalizedUnit),
    Item(AcceptedItem),
}
pub struct Session {
    store: Store,
    config: SessionConfig,
    verifier: HistoryVerifier,
    index: u64,
    pending: SessionOutcome,
    cursor: usize,
    phase: Phase,
    signatures: BTreeMap<PeerId, [u8; 64]>,
    queue: VecDeque<Work>,
    ready: Option<SignedSessionOutcome>,
    adoption: Option<SignedSessionOutcome>,
    engine: Option<EngineSession>,
    failed: bool,
    commit_notifier: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}
pub fn completed(
    snapshot: &Snapshot,
    index: u64,
) -> Result<Option<SignedSessionOutcome>, SessionError> {
    snapshot
        .get(Namespace::Replicated, &key(COMPLETED, index))?
        .map(|v| decode_whole(&v).map_err(|_| SessionError::Fatal("corrupt-completed")))
        .transpose()
}
pub fn session_count(snapshot: &Snapshot) -> Result<u64, SessionError> {
    snapshot
        .get(Namespace::Replicated, COUNT)?
        .map(|v| decode_whole(&v).map_err(|_| SessionError::Fatal("corrupt-session-count")))
        .transpose()
        .map(|v| v.unwrap_or(0))
}
impl Session {
    pub fn open(store: Store, config: SessionConfig) -> Result<Self, SessionError> {
        let verifier = HistoryVerifier::new(config.broadcast_keys.clone())
            .map_err(|_| SessionError::Fatal("invalid-session-keys"))?;
        if config.rounds == 0 {
            return Err(SessionError::Fatal("invalid-session-rounds"));
        }
        verifier
            .sign(
                0,
                &SessionOutcome { items: vec![] },
                config.local_peer,
                &config.local_key,
            )
            .map_err(|_| SessionError::Fatal("invalid-local-key"))?;
        let snapshot = store.snapshot()?;
        let index = session_count(&snapshot)?;
        let rows = snapshot.scan_prefix(Namespace::Replicated, COMPLETED)?;
        if u64::try_from(rows.len()).ok() != Some(index) {
            return Err(SessionError::Fatal("noncontiguous-completed"));
        }
        for (i, (k, v)) in rows.iter().enumerate() {
            if *k != key(COMPLETED, i as u64) {
                return Err(SessionError::Fatal("noncontiguous-completed"));
            }
            let signed: SignedSessionOutcome =
                decode_whole(v).map_err(|_| SessionError::Fatal("corrupt-completed"))?;
            verifier
                .verify(i as u64, &signed, SignaturePolicy::GuardianAdoption)
                .map_err(|_| SessionError::Fatal("invalid-completed-signatures"))?;
        }
        let mut items = vec![];
        for (i, (k, v)) in snapshot
            .scan_prefix(Namespace::Replicated, PENDING)?
            .into_iter()
            .enumerate()
        {
            if k != key(PENDING, i as u64) {
                return Err(SessionError::Fatal("noncontiguous-pending"));
            }
            let accepted: AcceptedItem =
                decode_whole(&v).map_err(|_| SessionError::Fatal("corrupt-pending"))?;
            if !config.broadcast_keys.contains_key(&accepted.peer) {
                return Err(SessionError::Fatal("invalid-pending-creator"));
            }
            items.push(accepted);
        }
        Ok(Self {
            store,
            config,
            verifier,
            index,
            pending: SessionOutcome { items },
            cursor: 0,
            phase: Phase::Collecting,
            signatures: BTreeMap::new(),
            queue: VecDeque::new(),
            ready: None,
            adoption: None,
            engine: None,
            failed: false,
            commit_notifier: None,
        })
    }
    pub fn status(&self) -> SessionStatus {
        SessionStatus {
            index: self.index,
            phase: self.phase,
            pending: self.pending.clone(),
            replay_cursor: self.cursor,
        }
    }
    /// Internal runtime wakeup, called after durable commits and outside writers.
    pub(crate) fn set_commit_notifier(&mut self, notifier: std::sync::Arc<dyn Fn() + Send + Sync>) {
        self.commit_notifier = Some(notifier);
    }
    pub fn enqueue(&mut self, unit: FinalizedUnit) {
        self.queue.push_back(Work::Unit(unit));
    }
    pub fn queued_work(&self) -> usize {
        self.queue.len()
    }
    fn begin_signing(&mut self, proposals: &ProposalQueue) -> Result<(), SessionError> {
        if self.cursor != self.pending.items.len() {
            return Err(SessionError::Fatal("unreplayed-prefix-at-boundary"));
        }
        let signature = self
            .verifier
            .sign(
                self.index,
                &self.pending,
                self.config.local_peer,
                &self.config.local_key,
            )
            .map_err(|_| SessionError::Fatal("local-history-signature"))?;
        proposals
            .set_signature(signature)
            .map_err(|_| SessionError::Fatal("signature-proposal"))?;
        self.phase = Phase::Signing;
        self.signatures.insert(self.config.local_peer, signature);
        self.check_quorum();
        Ok(())
    }
    fn check_quorum(&mut self) {
        if self.signatures.len() == self.verifier.quorum() {
            self.ready = Some(SignedSessionOutcome {
                outcome: self.pending.clone(),
                signatures: self.signatures.clone(),
            });
            self.phase = Phase::Ready;
        }
    }
    /// Side-channel caller must supply the authenticated sender identity.
    pub fn receive_signature(
        &mut self,
        peer: PeerId,
        signature: [u8; 64],
    ) -> Result<(), SessionError> {
        self.ensure_running()?;
        if self.phase != Phase::Signing {
            return Err(SessionError::Rejected);
        }
        self.verifier
            .verify_signature(self.index, &self.pending, peer, &signature)
            .map_err(|_| SessionError::Rejected)?;
        self.signatures.insert(peer, signature);
        self.check_quorum();
        Ok(())
    }
    /// Drain in order. Retry leaves the current item at the front, including when
    /// it originated in a previously dequeued finalized batch.
    pub fn drive(
        &mut self,
        modules: &Modules,
        backend: &impl BitcoinBackend,
        proposals: &ProposalQueue,
    ) -> Result<(), SessionError> {
        self.ensure_running()?;
        let result = self.drive_inner(modules, backend, proposals);
        self.latch(result)
    }
    /// Poll even when no finalized unit arrives: an exited native engine is fatal.
    pub fn check_health(&mut self) -> Result<(), SessionError> {
        self.ensure_running()
    }
    fn ensure_running(&mut self) -> Result<(), SessionError> {
        if self.failed {
            return Err(SessionError::Fatal("session-stopped"));
        }
        if self.engine.as_ref().is_some_and(EngineSession::is_finished) {
            self.failed = true;
            return Err(SessionError::Fatal("agreement-stopped"));
        }
        Ok(())
    }
    fn latch<T>(&mut self, result: Result<T, SessionError>) -> Result<T, SessionError> {
        if matches!(
            result,
            Err(SessionError::Fatal(_) | SessionError::Storage(_))
        ) {
            self.failed = true;
        }
        result
    }
    fn drive_inner(
        &mut self,
        modules: &Modules,
        backend: &impl BitcoinBackend,
        proposals: &ProposalQueue,
    ) -> Result<(), SessionError> {
        if let Some(signed) = self.adoption.clone() {
            self.adopt(signed, modules, backend)?;
        }
        while self.phase != Phase::Ready {
            let Some(work) = self.queue.front() else {
                break;
            };
            match work {
                Work::Item(item) => {
                    let item = item.clone();
                    match self.accept(&item, modules, backend, true) {
                        Ok(()) | Err(SessionError::Rejected) => {
                            self.queue.pop_front();
                        }
                        Err(e) => return Err(e),
                    }
                }
                Work::Unit(unit) => {
                    let unit = unit.clone();
                    if !self.config.broadcast_keys.contains_key(&unit.creator) {
                        return Err(SessionError::Fatal("invalid-finalized-creator"));
                    }
                    if self.phase == Phase::Collecting && unit.round >= self.config.rounds {
                        self.begin_signing(proposals)?;
                        self.queue.pop_front();
                        continue;
                    }
                    self.queue.pop_front();
                    match (self.phase, unit.data) {
                        (Phase::Collecting, Some(Data::Batch(bytes))) => {
                            if bytes.len() > 50_000 {
                                continue;
                            }
                            if let Ok(items) = decode_batch(&bytes, modules) {
                                for item in items.into_iter().rev() {
                                    self.queue.push_front(Work::Item(AcceptedItem {
                                        item,
                                        peer: unit.creator,
                                    }));
                                }
                            }
                        }
                        (Phase::Signing, Some(Data::Signature(signature))) => {
                            let _ = self.receive_signature(unit.creator, signature);
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
    fn accept(
        &mut self,
        accepted: &AcceptedItem,
        modules: &Modules,
        backend: &impl BitcoinBackend,
        replay: bool,
    ) -> Result<(), SessionError> {
        if replay && self.cursor < self.pending.items.len() {
            if self.pending.items[self.cursor] == *accepted {
                self.cursor += 1;
                return Ok(());
            }
            return Err(SessionError::Rejected);
        }
        if !self.config.broadcast_keys.contains_key(&accepted.peer) {
            return Err(SessionError::Rejected);
        }
        accepted
            .item
            .validate_modules(modules)
            .map_err(|_| SessionError::Rejected)?;
        let wallet_item = match &accepted.item {
            ConsensusItem::Module(value) if value.module_id == modules.wallet().module_id() => {
                Some(
                    decode_whole::<wallet::ConsensusItem>(&value.payload)
                        .map_err(|_| SessionError::Rejected)?,
                )
            }
            _ => None,
        };
        let scan = if let Some(item) = &wallet_item {
            modules
                .wallet()
                .required_scan(&self.store.snapshot()?, accepted.peer, item)
                .map_err(wallet_error)?
                .map(|request| wallet::prepare_scan(backend, request).map_err(wallet_error))
                .transpose()?
        } else {
            None
        };
        let mut writer = self.store.transaction()?;
        // Catch accidentally concurrent session executors, including an adoption
        // racing a completion; tentative module mutations must never overwrite history.
        let persisted_count = writer
            .get(Namespace::Replicated, COUNT)?
            .map(|v| {
                decode_whole::<u64>(&v).map_err(|_| SessionError::Fatal("corrupt-session-count"))
            })
            .transpose()?
            .unwrap_or(0);
        if persisted_count != self.index
            || writer.scan_prefix(Namespace::Replicated, PENDING)?.len() != self.pending.items.len()
        {
            return Err(SessionError::Fatal("concurrent-session-executor"));
        }
        match &accepted.item {
            ConsensusItem::Transaction(transaction) => {
                transaction::apply_consensus(
                    &mut writer,
                    transaction,
                    modules,
                    self.config.version,
                )
                .map_err(|e| match e {
                    ExecutionError::Rejected(_) | ExecutionError::AlreadyAccepted => {
                        SessionError::Rejected
                    }
                    ExecutionError::Storage(e) => SessionError::Storage(e),
                    _ => SessionError::Fatal("transaction-invariant"),
                })?;
            }
            ConsensusItem::Module(_) => {
                let item = wallet_item.as_ref().ok_or(SessionError::Rejected)?;
                modules
                    .wallet()
                    .process_consensus(&mut writer, accepted.peer, item, scan.as_ref())
                    .map_err(wallet_error)?;
            }
            ConsensusItem::Unknown { .. } => return Err(SessionError::Rejected),
        }
        modules
            .audit(&writer)
            .map_err(|_| SessionError::Fatal("module-audit"))?;
        writer.put(
            Namespace::Replicated,
            &key(PENDING, self.pending.items.len() as u64),
            &accepted.consensus_encode(),
        )?;
        writer.commit()?;
        self.pending.items.push(accepted.clone());
        self.cursor = self.pending.items.len();
        if let Some(notify) = &self.commit_notifier {
            notify();
        }
        Ok(())
    }
    /// Exactly-q signatures are checked before any prefix comparison or mutation.
    /// Transient backend preparation may retry adoption with the same outcome.
    pub fn adopt(
        &mut self,
        signed: SignedSessionOutcome,
        modules: &Modules,
        backend: &impl BitcoinBackend,
    ) -> Result<(), SessionError> {
        self.ensure_running()?;
        let result = self.adopt_inner(signed, modules, backend);
        self.latch(result)
    }
    fn adopt_inner(
        &mut self,
        signed: SignedSessionOutcome,
        modules: &Modules,
        backend: &impl BitcoinBackend,
    ) -> Result<(), SessionError> {
        self.verifier
            .verify(self.index, &signed, SignaturePolicy::GuardianAdoption)
            .map_err(|_| SessionError::Rejected)?;
        if self
            .adoption
            .as_ref()
            .is_some_and(|target| target.outcome != signed.outcome)
        {
            return Err(SessionError::Fatal("changed-adoption-target"));
        }
        if self.phase != Phase::Collecting {
            if header(self.index, &self.pending) != header(self.index, &signed.outcome) {
                return Err(SessionError::Fatal("divergent-adopted-header"));
            }
        } else {
            if !signed.outcome.items.starts_with(&self.pending.items) {
                return Err(SessionError::Fatal("divergent-adopted-prefix"));
            }
            self.adoption = Some(signed.clone());
            for item in &signed.outcome.items[self.pending.items.len()..] {
                match self.accept(item, modules, backend, false) {
                    Err(SessionError::Rejected) => {
                        return Err(SessionError::Fatal("adopted-item-rejected"));
                    }
                    result => result?,
                }
            }
        }
        self.adoption = None;
        self.ready = Some(signed);
        self.phase = Phase::Ready;
        Ok(())
    }
    /// Single guardian processes one submitted item. Elapsed time is sampled by
    /// the driver after receipt: silence never calls this method or closes a session.
    pub fn process_single(
        &mut self,
        item: ConsensusItem,
        elapsed: std::time::Duration,
        modules: &Modules,
        backend: &impl BitcoinBackend,
        proposals: &ProposalQueue,
    ) -> Result<(), SessionError> {
        self.ensure_running()?;
        let result = self.process_single_inner(item, elapsed, modules, backend, proposals);
        self.latch(result)
    }
    fn process_single_inner(
        &mut self,
        item: ConsensusItem,
        elapsed: std::time::Duration,
        modules: &Modules,
        backend: &impl BitcoinBackend,
        proposals: &ProposalQueue,
    ) -> Result<(), SessionError> {
        if self.config.broadcast_keys.len() != 1 || self.phase != Phase::Collecting {
            return Err(SessionError::Rejected);
        }
        let result = self.accept(
            &AcceptedItem {
                item,
                peer: self.config.local_peer,
            },
            modules,
            backend,
            false,
        );
        match result {
            Ok(()) | Err(SessionError::Rejected) => {}
            Err(e) => return Err(e),
        }
        if elapsed > std::time::Duration::from_secs(60) {
            self.cursor = self.pending.items.len();
            self.begin_signing(proposals)?;
        }
        result
    }
    pub fn ready_outcome(&self) -> Option<&SignedSessionOutcome> {
        self.ready.as_ref()
    }
    /// Start and retain the native engine for this exact store and session.
    pub fn start(
        store: Store,
        config: SessionConfig,
        round_delay_ms: u64,
        queue_capacity: usize,
    ) -> Result<(Self, crate::agreement::EngineIo, ProposalQueue), SessionError> {
        let keychain = crate::agreement::GuardianKeychain::new(
            config.local_peer,
            SecretKey::from_bytes(&zeroize::Zeroizing::new(config.local_key.to_bytes()))
                .map_err(|_| SessionError::Fatal("local-key"))?,
            config.broadcast_keys.clone(),
        )
        .map_err(|_| SessionError::Fatal("agreement-keychain"))?;
        let mut session = Self::open(store, config)?;
        if session.config.broadcast_keys.len() == 1 {
            return Err(SessionError::Fatal("single-guardian-engine-bypass"));
        }
        let (proposals, provider) = ProposalQueue::new(queue_capacity)
            .map_err(|_| SessionError::Fatal("agreement-capacity"))?;
        let (engine, io) = EngineSession::start(
            keychain,
            session.store.clone(),
            session.index,
            session.config.rounds,
            round_delay_ms,
            provider,
            queue_capacity,
        )
        .map_err(|_| SessionError::Fatal("agreement-start"))?;
        session.engine = Some(engine);
        Ok((session, io, proposals))
    }
    /// Stop and join the owned engine without completing the session or changing
    /// any pending history or agreement backup. Shutdown failures remain fatal.
    pub fn abort(mut self) -> Result<(), SessionError> {
        if let Some(engine) = self.engine.take() {
            engine
                .shutdown()
                .map_err(|_| SessionError::Fatal("agreement-shutdown"))?;
        }
        Ok(())
    }
    /// Completion cannot substitute a different session engine or inject a stop.
    /// A state-only multi-guardian instance cannot complete.
    pub fn finish(mut self) -> Result<SignedSessionOutcome, SessionError> {
        self.ensure_running()?;
        if self.ready.is_none() {
            return Err(SessionError::Fatal("session-not-ready"));
        }
        match self.engine.take() {
            Some(engine) => engine
                .shutdown()
                .map_err(|_| SessionError::Fatal("agreement-shutdown"))?,
            None if self.config.broadcast_keys.len() == 1 => {}
            None => return Err(SessionError::Fatal("missing-owned-agreement-engine")),
        }
        let signed = self.ready.ok_or(SessionError::Fatal("session-not-ready"))?;
        let mut writer = self.store.transaction()?;
        let count = writer
            .get(Namespace::Replicated, COUNT)?
            .map(|v| {
                decode_whole::<u64>(&v).map_err(|_| SessionError::Fatal("corrupt-session-count"))
            })
            .transpose()?
            .unwrap_or(0);
        if count != self.index
            || writer
                .get(Namespace::Replicated, &key(COMPLETED, self.index))?
                .is_some()
        {
            return Err(SessionError::Fatal("completed-session-replacement"));
        }
        let rows = writer.scan_prefix(Namespace::Replicated, PENDING)?;
        if rows.len() != signed.outcome.items.len() {
            return Err(SessionError::Fatal("pending-changed-before-completion"));
        }
        for (i, ((k, v), item)) in rows.iter().zip(&signed.outcome.items).enumerate() {
            if *k != key(PENDING, i as u64) || *v != item.consensus_encode() {
                return Err(SessionError::Fatal("pending-changed-before-completion"));
            }
            writer.delete(Namespace::Replicated, k)?;
        }
        writer.clear_agreement(self.index)?;
        writer.put(
            Namespace::Replicated,
            &key(COMPLETED, self.index),
            &signed.consensus_encode(),
        )?;
        writer.put(
            Namespace::Replicated,
            COUNT,
            &self
                .index
                .checked_add(1)
                .ok_or(SessionError::Fatal("session-count-overflow"))?
                .consensus_encode(),
        )?;
        writer.commit()?;
        if let Some(notify) = &self.commit_notifier {
            notify();
        }
        Ok(signed)
    }
}

/// Durable status evidence only. `None` deliberately leaves the undocumented
/// empty-current/future-index Initial versus Pending([]) API policy to the driver.
pub fn persisted_status(
    snapshot: &Snapshot,
    index: u64,
) -> Result<Option<crate::protocol::SessionStatusV2>, SessionError> {
    let count = session_count(snapshot)?;
    if index < count {
        return completed(snapshot, index)?
            .map(crate::protocol::SessionStatusV2::Complete)
            .map(Some)
            .ok_or(SessionError::Fatal("missing-completed-session"));
    }
    if index > count {
        return Ok(None);
    }
    let mut items = vec![];
    for (i, (k, v)) in snapshot
        .scan_prefix(Namespace::Replicated, PENDING)?
        .into_iter()
        .enumerate()
    {
        if k != key(PENDING, i as u64) {
            return Err(SessionError::Fatal("noncontiguous-pending"));
        }
        items.push(
            decode_whole::<AcceptedItem>(&v).map_err(|_| SessionError::Fatal("corrupt-pending"))?,
        );
    }
    if items.is_empty() {
        Ok(None)
    } else {
        Ok(Some(crate::protocol::SessionStatusV2::Pending(items)))
    }
}
