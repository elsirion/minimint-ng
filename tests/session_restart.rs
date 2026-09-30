use minimint_ng::{
    agreement::{EngineIo, FinalizedUnit, ProposalQueue},
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::{ConsensusEncode, decode_whole},
    config::{BitcoinNetwork, DescriptorKind, Fee, RawMintConfig, RawWalletConfig},
    core::session::{Phase, Session, SessionConfig, completed, session_count},
    crypto::{
        bls::{G2, Scalar},
        secp::SecretKey,
    },
    modules::{Modules, mint, wallet},
    protocol::{ConsensusItem, DynamicValue, ModuleId, PeerId, SessionOutcome, Version},
    storage::{Namespace, Store},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
const MINT: ModuleId = ModuleId(42);
const WALLET: ModuleId = ModuleId(99);
pub fn secret(n: u64) -> SecretKey {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_bytes(&b).unwrap()
}
pub fn modules() -> Modules {
    let public = G2::generator().mul(&Scalar::from_u64(5)).to_bytes();
    let mint = mint::Mint::new(
        MINT,
        PeerId(0),
        RawMintConfig {
            aggregate_keys: (0..42).map(|d| (d, public)).collect(),
            public_shares: (0..42)
                .map(|d| (d, (0..4).map(|i| (PeerId(i), public)).collect()))
                .collect(),
            fee: Fee {
                base: 100,
                parts_per_million: 0,
            },
            amount_unit: 0,
        },
        (0..42).map(|d| (d, Scalar::from_u64(5))).collect(),
    )
    .unwrap();
    let wallet = wallet::Wallet::new(
        WALLET,
        PeerId(0),
        RawWalletConfig {
            bitcoin_pks: (0..4)
                .map(|i| (PeerId(i), secret(u64::from(i) + 1).public_key()))
                .collect(),
            descriptor: DescriptorKind::Wsh,
            send_tx_vbytes: 228,
            receive_tx_vbytes: 316,
            feerate_base: 250,
            dust_limit: 10000,
            fee_consensus: Fee {
                base: 100000,
                parts_per_million: 0,
            },
            network: BitcoinNetwork::Regtest,
        },
        secret(1),
    )
    .unwrap();
    Modules::new(mint, wallet).unwrap()
}
pub struct Backend(pub bitcoin::Block);
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        Ok(7)
    }
    fn wait_for_count(&self, n: u64) -> Result<(), BackendError> {
        if n <= 7 { Ok(()) } else { Err(BackendError) }
    }
    fn block_hash(&self, h: u64) -> Result<[u8; 32], BackendError> {
        if h == 0 {
            Ok(self.0.hash())
        } else {
            Err(BackendError)
        }
    }
    fn block(&self, h: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        if h == self.0.hash() {
            Ok(self.0.clone())
        } else {
            Err(BackendError)
        }
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Ok(Some(1000))
    }
    fn broadcast(&self, _: &bitcoin::Transaction) -> Result<(), BackendError> {
        Err(BackendError)
    }
}

fn config() -> SessionConfig {
    SessionConfig {
        broadcast_keys: (0..4)
            .map(|i| (PeerId(i), secret(u64::from(i) + 1).public_key()))
            .collect(),
        local_peer: PeerId(0),
        local_key: secret(1),
        version: Version { major: 2, minor: 1 },
        rounds: 12,
    }
}
fn backend() -> Backend {
    Backend(bitcoin::Block {
        header: [0; 80],
        transactions: vec![],
    })
}
fn fee(value: u64) -> ConsensusItem {
    ConsensusItem::Module(DynamicValue {
        module_id: WALLET,
        payload: wallet::ConsensusItem::FeeRate(Some(value)).consensus_encode(),
    })
}
use futures::{StreamExt, executor::block_on};
use std::{
    io::{BufRead, BufReader, Write},
    os::{
        fd::OwnedFd,
        unix::{net::UnixStream, process::ExitStatusExt},
    },
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
struct Federation {
    sessions: Vec<Session>,
    proposals: Vec<ProposalQueue>,
    finalized: Vec<mpsc::Receiver<FinalizedUnit>>,
    routers: Vec<thread::JoinHandle<()>>,
}
impl Federation {
    fn start(stores: &[Store]) -> Self {
        let mut sessions = vec![];
        let mut proposals = vec![];
        let mut finalized = vec![];
        let mut inputs = vec![];
        let mut outputs = vec![];
        for (i, store) in stores.iter().enumerate() {
            let mut c = config();
            c.local_peer = PeerId(i as u16);
            c.local_key = secret(i as u64 + 1);
            let (
                session,
                EngineIo {
                    inbound,
                    outbound,
                    finalized: events,
                },
                queue,
            ) = Session::start(store.clone(), c, 20, 1024).unwrap();
            queue.push(fee(1000)).unwrap();
            sessions.push(session);
            proposals.push(queue);
            finalized.push(events);
            inputs.push(inbound);
            outputs.push(outbound);
        }
        let routers = outputs
            .into_iter()
            .enumerate()
            .map(|(source, mut output)| {
                let mut inputs = inputs.clone();
                thread::spawn(move || {
                    block_on(async move {
                        while let Some(message) = output.next().await {
                            match message.recipient {
                                Some(peer) => {
                                    let _ = inputs[usize::from(peer.0)].try_send(message.payload);
                                }
                                None => {
                                    for (target, input) in inputs.iter_mut().enumerate() {
                                        if target != source {
                                            let _ = input.try_send(message.payload.clone());
                                        }
                                    }
                                }
                            }
                        }
                    })
                })
            })
            .collect();
        Self {
            sessions,
            proposals,
            finalized,
            routers,
        }
    }
    fn ready(&mut self) {
        let m = modules();
        let b = backend();
        let deadline = Instant::now() + Duration::from_secs(45);
        while self
            .sessions
            .iter()
            .any(|s| s.status().phase != Phase::Ready)
        {
            assert!(
                Instant::now() < deadline,
                "native sessions did not reach signed outcome"
            );
            for i in 0..self.sessions.len() {
                for unit in self.finalized[i].try_iter() {
                    self.sessions[i].enqueue(unit);
                }
                self.sessions[i].drive(&m, &b, &self.proposals[i]).unwrap();
            }
            thread::sleep(Duration::from_millis(5));
        }
        let first = self.sessions[0].status().pending;
        assert!(!first.items.is_empty());
        for session in &self.sessions {
            assert_eq!(session.status().pending, first);
        }
    }
    fn checkpoint(&mut self, mode: &str) {
        let m = modules();
        let b = backend();
        let deadline = Instant::now() + Duration::from_secs(45);
        let mut frozen = [false; 4];
        while frozen.iter().any(|done| !done) {
            assert!(Instant::now() < deadline, "native checkpoint deadline");
            for (i, done) in frozen.iter_mut().enumerate() {
                if *done {
                    continue;
                }
                let Ok(unit) = self.finalized[i].try_recv() else {
                    continue;
                };
                let previous = self.sessions[i].status();
                let round = unit.round;
                self.sessions[i].enqueue(unit);
                self.sessions[i].drive(&m, &b, &self.proposals[i]).unwrap();
                let current = self.sessions[i].status();
                *done = if mode == "item" {
                    if current.pending.items.is_empty() {
                        false
                    } else {
                        assert_eq!(current.pending.items.len(), 1);
                        assert_eq!(current.phase, Phase::Collecting);
                        true
                    }
                } else {
                    if current.phase == Phase::Collecting {
                        false
                    } else {
                        assert_eq!(previous.phase, Phase::Collecting);
                        assert!(round >= config().rounds);
                        assert_eq!(current.phase, Phase::Signing);
                        assert_eq!(
                            current.pending, previous.pending,
                            "boundary data must be ignored"
                        );
                        true
                    }
                };
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn replay_prefixes(&mut self, stores: &[Store], expected: &[SessionOutcome]) {
        let m = modules();
        let b = backend();
        let original: Vec<_> = stores
            .iter()
            .map(|store| {
                store
                    .snapshot()
                    .unwrap()
                    .scan_prefix(Namespace::Replicated, b"")
                    .unwrap()
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(45);
        let mut replayed = [false; 4];
        while replayed.iter().any(|done| !done) {
            assert!(Instant::now() < deadline, "native prefix replay deadline");
            for (i, done) in replayed.iter_mut().enumerate() {
                if *done {
                    continue;
                }
                let Ok(unit) = self.finalized[i].try_recv() else {
                    continue;
                };
                self.sessions[i].enqueue(unit);
                self.sessions[i].drive(&m, &b, &self.proposals[i]).unwrap();
                let status = self.sessions[i].status();
                assert_eq!(status.pending, expected[i]);
                assert_eq!(
                    stores[i]
                        .snapshot()
                        .unwrap()
                        .scan_prefix(Namespace::Replicated, b"")
                        .unwrap(),
                    original[i],
                    "replaying committed items must not duplicate module or history effects"
                );
                assert!(status.replay_cursor <= expected[i].items.len());
                *done = status.replay_cursor == expected[i].items.len();
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn finish(mut self) {
        for session in self.sessions.drain(..) {
            session.finish().unwrap();
        }
        for router in self.routers.drain(..) {
            router.join().unwrap();
        }
    }
}
impl Drop for Federation {
    fn drop(&mut self) {
        // Keep finalized consumers alive until every native worker terminates,
        // then join transport routers even if an assertion unwinds this fixture.
        for session in self.sessions.drain(..) {
            let _ = session.abort();
        }
        for router in self.routers.drain(..) {
            let _ = router.join();
        }
    }
}
fn stores(path: &std::path::Path) -> Vec<Store> {
    (0..4)
        .map(|i| Store::open(path.join(i.to_string())).unwrap())
        .collect()
}
#[test]
fn session_crash_child() {
    let Ok(path) = std::env::var("MINIMINT_SESSION_CRASH_PATH") else {
        return;
    };
    let mode = std::env::var("MINIMINT_SESSION_CRASH_MODE").unwrap();
    let stores = stores(std::path::Path::new(&path));
    let mut federation = Federation::start(&stores);
    if mode == "item" || mode == "signing" {
        federation.checkpoint(&mode);
        let pending: Vec<_> = federation
            .sessions
            .iter()
            .map(|s| s.status().pending)
            .collect();
        let mut file =
            std::fs::File::create(std::path::Path::new(&path).join("checkpoint.bin")).unwrap();
        file.write_all(&pending.consensus_encode()).unwrap();
        file.sync_all().unwrap();
    } else if mode.starts_with("recover-") {
        let expected: Vec<SessionOutcome> = decode_whole(
            &std::fs::read(std::path::Path::new(&path).join("checkpoint.bin")).unwrap(),
        )
        .unwrap();
        for (session, prefix) in federation.sessions.iter().zip(&expected) {
            let status = session.status();
            assert_eq!(
                status.phase,
                Phase::Collecting,
                "phase/signature map resets on reopen"
            );
            assert_eq!(status.replay_cursor, 0);
            assert_eq!(&status.pending, prefix);
        }
        federation.replay_prefixes(&stores, &expected);
        federation.ready();
        for (session, prefix) in federation.sessions.iter().zip(&expected) {
            assert!(session.status().pending.items.starts_with(&prefix.items));
        }
    } else {
        federation.ready();
    }
    for store in &stores {
        assert!(!store.read_agreement(0).unwrap().is_empty());
    }
    if mode == "after" || mode.starts_with("recover-") {
        federation.finish();
    } else {
        std::mem::forget(federation);
    }
    println!("SESSION_BOUNDARY");
    std::io::stdout().flush().unwrap();
    loop {
        thread::park();
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn kill(path: &std::path::Path, mode: &str) {
    let (reader, writer) = UnixStream::pair().unwrap();
    let descriptor: OwnedFd = writer.into();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "session_crash_child", "--nocapture"])
            .env("MINIMINT_SESSION_CRASH_PATH", path)
            .env("MINIMINT_SESSION_CRASH_MODE", mode)
            .stdout(Stdio::from(descriptor))
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(reader);
    let deadline = Instant::now() + Duration::from_secs(55);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "{mode} child boundary deadline");
        reader.get_ref().set_read_timeout(Some(remaining)).unwrap();
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() != 0,
            "{mode} child exited before boundary"
        );
        if line.trim() == "SESSION_BOUNDARY" {
            break;
        }
    }
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(9));
}
#[test]
fn sigkill_before_and_after_completion_replays_native_backup_and_pending_prefix() {
    let before = fixture::TestDir::new();
    kill(before.path(), "before");
    let reopened = stores(before.path());
    let pending: Vec<_> = reopened
        .iter()
        .map(|store| {
            assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 0);
            assert!(completed(&store.snapshot().unwrap(), 0).unwrap().is_none());
            assert!(!store.read_agreement(0).unwrap().is_empty());
            let session = Session::open(store.clone(), config()).unwrap();
            assert_eq!(session.status().replay_cursor, 0);
            session.status().pending
        })
        .collect();
    let mut federation = Federation::start(&reopened);
    federation.ready();
    for (session, expected) in federation.sessions.iter().zip(pending) {
        assert_eq!(session.status().pending, expected);
        assert_eq!(session.status().replay_cursor, expected.items.len());
    }
    federation.finish();
    for store in &reopened {
        assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 1);
        assert!(store.read_agreement(0).unwrap().is_empty());
        let next = Session::open(store.clone(), config()).unwrap();
        assert_eq!(next.status().index, 1);
        assert!(next.status().pending.items.is_empty());
    }
    let after = fixture::TestDir::new();
    kill(after.path(), "after");
    for store in stores(after.path()) {
        assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 1);
        assert!(completed(&store.snapshot().unwrap(), 0).unwrap().is_some());
        assert!(store.read_agreement(0).unwrap().is_empty());
        assert!(
            Session::open(store, config())
                .unwrap()
                .status()
                .pending
                .items
                .is_empty()
        );
    }
}
#[test]
fn failed_native_shutdown_preserves_pending_and_backup() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    store.append_agreement(0, &[255, 255, 255]).unwrap();
    let (mut session, _io, _queue) = Session::start(store.clone(), config(), 20, 32).unwrap();
    let outcome = minimint_ng::protocol::SessionOutcome { items: vec![] };
    let verifier =
        minimint_ng::core::history::HistoryVerifier::new(config().broadcast_keys).unwrap();
    let signatures = (0..3)
        .map(|i| {
            (
                PeerId(i),
                verifier
                    .sign(0, &outcome, PeerId(i), &secret(u64::from(i) + 1))
                    .unwrap(),
            )
        })
        .collect();
    let adoption = session.adopt(
        minimint_ng::protocol::SignedSessionOutcome {
            outcome,
            signatures,
        },
        &modules(),
        &backend(),
    );
    assert!(
        adoption.is_ok()
            || matches!(
                adoption,
                Err(minimint_ng::core::session::SessionError::Fatal(
                    "agreement-stopped"
                ))
            )
    );
    // Give native restore an opportunity to report its failed backup; finish must
    // await and propagate that failure even though the local signed outcome is ready.
    thread::sleep(Duration::from_millis(100));
    assert!(session.finish().is_err());
    assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 0);
    assert_eq!(store.read_agreement(0).unwrap(), [255, 255, 255]);
    assert!(completed(&store.snapshot().unwrap(), 0).unwrap().is_none());
}
#[test]
fn native_restore_failure_is_reported_by_idle_driver_before_ready() {
    use minimint_ng::core::session::SessionError;
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut initial = Session::open(store.clone(), config()).unwrap();
    let q = ProposalQueue::new(32).unwrap().0;
    initial.enqueue(FinalizedUnit {
        creator: PeerId(0),
        round: 0,
        data: Some(minimint_ng::agreement::Data::Batch(
            vec![fee(1000)].consensus_encode(),
        )),
    });
    initial.drive(&modules(), &backend(), &q).unwrap();
    let pending = initial.status().pending;
    drop(initial);
    store.append_agreement(0, &[255, 255, 255]).unwrap();
    let (mut session, _io, q) = Session::start(store.clone(), config(), 20, 32).unwrap();
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match session.drive(&modules(), &backend(), &q) {
            Err(SessionError::Fatal("agreement-stopped")) => break,
            Ok(()) => {
                assert!(
                    Instant::now() < deadline,
                    "idle driver ignored failed native restore"
                );
                thread::sleep(Duration::from_millis(5));
            }
            result => panic!("unexpected driver result: {result:?}"),
        }
    }
    assert_eq!(session.status().phase, Phase::Collecting);
    assert_eq!(session.status().pending, pending);
    assert!(matches!(
        session.check_health(),
        Err(SessionError::Fatal("session-stopped"))
    ));
    assert!(session.finish().is_err());
    assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 0);
    assert_eq!(store.read_agreement(0).unwrap(), [255, 255, 255]);
    assert_eq!(
        Session::open(store, config()).unwrap().status().pending,
        pending
    );
}

#[test]
fn explicit_abort_reports_failed_native_restore_without_clearing_backup() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    store.append_agreement(0, &[255, 255, 255]).unwrap();
    let (mut session, _io, _proposals) = Session::start(store.clone(), config(), 20, 32).unwrap();
    let deadline = Instant::now() + Duration::from_secs(25);
    while session.check_health().is_ok() {
        assert!(
            Instant::now() < deadline,
            "native restore failed to report failure"
        );
        thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        session.abort(),
        Err(minimint_ng::core::session::SessionError::Fatal(
            "agreement-shutdown"
        ))
    ));
    assert_eq!(store.read_agreement(0).unwrap(), [255, 255, 255]);
    assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 0);
}

#[test]
fn sigkill_item_and_first_signing_boundary_replay_each_prefix_without_duplicate_effects() {
    for mode in ["item", "signing"] {
        let directory = fixture::TestDir::new();
        kill(directory.path(), mode);
        let expected: Vec<SessionOutcome> =
            decode_whole(&std::fs::read(directory.path().join("checkpoint.bin")).unwrap()).unwrap();
        assert_eq!(expected.len(), 4);
        assert!(
            expected
                .iter()
                .all(|prefix| prefix.items.len() == if mode == "item" { 1 } else { 4 })
        );
        for (store, prefix) in stores(directory.path()).into_iter().zip(&expected) {
            assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 0);
            assert!(completed(&store.snapshot().unwrap(), 0).unwrap().is_none());
            assert!(!store.read_agreement(0).unwrap().is_empty());
            let opened = Session::open(store, config()).unwrap();
            assert_eq!(opened.status().phase, Phase::Collecting);
            assert_eq!(opened.status().replay_cursor, 0);
            assert_eq!(&opened.status().pending, prefix);
        }
        // Recovery and its awaited native shutdown also stay inside an owned,
        // bounded process; the test host never inherits native worker threads.
        kill(directory.path(), &format!("recover-{mode}"));
        let mut agreed = None;
        let verifier =
            minimint_ng::core::history::HistoryVerifier::new(config().broadcast_keys).unwrap();
        let m = modules();
        for (store, prefix) in stores(directory.path()).into_iter().zip(expected) {
            let snapshot = store.snapshot().unwrap();
            assert_eq!(session_count(&snapshot).unwrap(), 1);
            let certificate = completed(&snapshot, 0).unwrap().unwrap();
            verifier
                .verify(
                    0,
                    &certificate,
                    minimint_ng::core::history::SignaturePolicy::GuardianAdoption,
                )
                .unwrap();
            assert!(certificate.outcome.items.starts_with(&prefix.items));
            assert_eq!(certificate.outcome.items.len(), 4);
            let creators: std::collections::BTreeSet<_> = certificate
                .outcome
                .items
                .iter()
                .map(|item| {
                    assert_eq!(item.item, fee(1000));
                    item.peer
                })
                .collect();
            assert_eq!(creators, (0..4).map(PeerId).collect());
            if let Some(first) = &agreed {
                assert_eq!(&certificate.outcome, first);
            } else {
                agreed = Some(certificate.outcome);
            }
            let wallet = m.wallet().snapshot(&snapshot).unwrap();
            assert_eq!(wallet.consensus_fee_rate, Some(1000));
            assert!(
                wallet.wallet.is_none()
                    && wallet.chain.is_empty()
                    && wallet.pending_chain.is_empty()
            );
            assert_eq!(m.mint().recovery_count(&snapshot).unwrap(), 0);
            assert!(store.read_agreement(0).unwrap().is_empty());
            let next = Session::open(store.clone(), config()).unwrap();
            assert_eq!(next.status().index, 1);
            assert!(next.status().pending.items.is_empty());
        }
    }
}
