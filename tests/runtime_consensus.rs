//! Controller integration uses real native agreement and mutually authenticated TCP.
use minimint_ng::{
    codec::ConsensusEncode,
    core::{
        history::HistoryVerifier,
        session::{completed, session_count},
        transaction::{accepted_output_modules, transaction_id},
    },
    daemon::{
        config::RuntimeConfig,
        consensus::{HistoryQueueError, Runtime, RuntimeHandle, RuntimeOptions},
    },
    modules::wallet,
    net::{PeerNetwork, envelope::Envelope},
    protocol::{
        AcceptedItem, ConsensusItem, DynamicValue, ModuleId, PeerId, SessionOutcome,
        SignedSessionOutcome, Transaction, TransactionSignatures,
    },
    storage::Store,
};
use std::{
    net::TcpListener,
    sync::{Arc, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
#[path = "fixtures/runtime/mod.rs"]
mod runtime_fixture;
use runtime_fixture::{Backend, configs, key};
struct Running {
    _dirs: Vec<fixture::TestDir>,
    stores: Vec<Store>,
    configs: Vec<Arc<RuntimeConfig>>,
    networks: Vec<Arc<PeerNetwork>>,
    backends: Vec<Arc<Backend>>,
    runtimes: Vec<Runtime>,
    handles: Vec<RuntimeHandle>,
}
impl Running {
    fn new(n: u16, rounds: u16) -> Self {
        Self::with_engines(n, rounds, n)
    }
    // Adoption/cleanup tests need a live owned engine, but must not race an
    // independently completing quorum while assembling a fixture certificate.
    // All peer networks are real; the q3 signatures are locally constructed.
    fn isolated_engine() -> Self {
        let result = Self::with_engines(4, 500, 1);
        wait(|| !result.stores[0].read_agreement(0).unwrap().is_empty());
        result
    }
    fn with_engines(n: u16, rounds: u16, engines: u16) -> Self {
        let listeners: Vec<_> = (0..n)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let configs = configs(n, rounds, &listeners);
        let networks: Vec<_> = listeners
            .into_iter()
            .enumerate()
            .map(|(p, l)| {
                Arc::new(
                    PeerNetwork::start(
                        PeerId(p as u16),
                        configs[p].tls_config(),
                        configs[p].resolve_peer_addresses().unwrap(),
                        l,
                        256,
                    )
                    .unwrap(),
                )
            })
            .collect();
        let dirs: Vec<_> = (0..n).map(|_| fixture::TestDir::new()).collect();
        let stores: Vec<_> = dirs
            .iter()
            .map(|d| Store::open(d.path()).unwrap())
            .collect();
        let backends: Vec<_> = (0..n).map(|_| Arc::new(Backend::new())).collect();
        let mut runtimes = vec![];
        let mut handles = vec![];
        for p in 0..usize::from(engines) {
            let (r, h) = Runtime::start(
                stores[p].clone(),
                configs[p].clone(),
                networks[p].clone(),
                backends[p].clone(),
                RuntimeOptions {
                    round_delay_ms: 20,
                    queue_capacity: 64,
                    tick: Duration::from_millis(2),
                    wallet_poll_interval: Duration::from_millis(20),
                },
            )
            .unwrap();
            runtimes.push(r);
            handles.push(h);
        }
        let result = Self {
            _dirs: dirs,
            stores,
            configs,
            networks,
            backends,
            runtimes,
            handles,
        };
        wait(|| {
            result
                .handles
                .iter()
                .all(|h| h.current_session() == Some(0))
        });
        result
    }
    fn stop(mut self) {
        for h in &self.handles {
            h.request_shutdown();
        }
        for r in self.runtimes.drain(..) {
            r.shutdown().unwrap();
        }
        for b in self.backends.iter().take(self.handles.len()) {
            assert!(b.stopped.load(Ordering::SeqCst));
        }
        for n in self.networks.drain(..) {
            match Arc::try_unwrap(n) {
                Ok(n) => n.shutdown().unwrap(),
                Err(_) => panic!("network reference leaked"),
            }
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        for h in &self.handles {
            h.request_shutdown();
        }
        for r in self.runtimes.drain(..) {
            let _ = r.shutdown();
        }
        for n in &self.networks {
            n.request_shutdown();
        }
    }
}
#[track_caller]
fn wait(mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !f() {
        assert!(Instant::now() < deadline, "runtime deadline");
        thread::sleep(Duration::from_millis(5));
    }
}
fn transaction(n: u8) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [n; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    }
}
fn module(item: wallet::ConsensusItem) -> ConsensusItem {
    ConsensusItem::Module(DynamicValue {
        module_id: ModuleId(1),
        payload: item.consensus_encode(),
    })
}
// Preserve the real initial absence votes emitted by unavailable fixture backends.
// Adoption must extend the durable accepted prefix, never replace it with an
// artificially empty history. Native tests retain the observed guardian order.
fn signed(r: &Running, index: u64, suffix: Vec<AcceptedItem>) -> SignedSessionOutcome {
    let config = &r.configs[0];
    let mut items = None;
    if r.handles.len() == 1 && r.configs.len() == 4 {
        assert!(
            minimint_ng::core::session::persisted_status(&r.stores[0].snapshot().unwrap(), index)
                .unwrap()
                .is_none(),
            "isolated native engine cannot finalize a prefix without quorum"
        );
        items = Some(vec![]);
    }
    wait(|| {
        if items.is_some() {
            return true;
        }
        assert!(
            !r.handles[0].is_stopped(),
            "runtime stopped before initial history prefix"
        );
        assert_eq!(
            r.handles[0].current_session(),
            Some(index),
            "session advanced before all initial guardian votes were observed"
        );
        let Some(minimint_ng::protocol::SessionStatusV2::Pending(prefix)) =
            minimint_ng::core::session::persisted_status(&r.stores[0].snapshot().unwrap(), index)
                .unwrap()
        else {
            return false;
        };
        if prefix.len() != r.configs.len() {
            return false;
        }
        assert!(
            prefix
                .iter()
                .all(|entry| entry.item == module(wallet::ConsensusItem::FeeRate(None)))
        );
        items = Some(prefix);
        true
    });
    let mut items = items.unwrap();
    items.extend(suffix);
    let verifier =
        HistoryVerifier::new(config.server_config().broadcast_public_keys.clone()).unwrap();
    let outcome = SessionOutcome { items };
    let signatures = (0..verifier.quorum())
        .map(|p| {
            (
                PeerId(p as u16),
                verifier
                    .sign(index, &outcome, PeerId(p as u16), &key(p as u8 + 1))
                    .unwrap(),
            )
        })
        .collect();
    SignedSessionOutcome {
        outcome,
        signatures,
    }
}
#[test]
fn four_native_engines_route_over_tls_and_commit_identical_history() {
    let r = Running::new(4, 12);
    let tx = transaction(1);
    let id = transaction_id(&tx);
    let mut containing_session = None;
    // Submission is not tied to session zero. Retry the same ID across a
    // signature-phase boundary until acceptance, then wait for its certificate.
    wait(|| {
        let snapshot = r.stores[0].snapshot().unwrap();
        if accepted_output_modules(&snapshot, &id).unwrap().is_none() {
            match r.handles[0].propose(ConsensusItem::Transaction(tx.clone())) {
                Ok(())
                | Err(minimint_ng::api::core::ProposalUnavailable::Full)
                | Err(minimint_ng::api::core::ProposalUnavailable::SignaturePhase) => {}
                Err(error) => panic!("transaction route closed: {error:?}"),
            }
        }
        let count = session_count(&snapshot).unwrap();
        for index in 0..count {
            let outcome = completed(&snapshot, index).unwrap().unwrap();
            if outcome.outcome.items.iter().any(|item| {
                matches!(
                    &item.item, ConsensusItem::Transaction(value) if transaction_id(value) == id
                )
            }) {
                containing_session = Some(index);
                return r
                    .stores
                    .iter()
                    .all(|store| session_count(&store.snapshot().unwrap()).unwrap() > index);
            }
        }
        false
    });
    let index = containing_session.unwrap();
    let first = completed(&r.stores[0].snapshot().unwrap(), index)
        .unwrap()
        .unwrap();
    let verifier =
        HistoryVerifier::new(r.configs[0].server_config().broadcast_public_keys.clone()).unwrap();
    for store in &r.stores {
        let snapshot = store.snapshot().unwrap();
        let outcome = completed(&snapshot, index).unwrap().unwrap();
        verifier
            .verify(
                index,
                &outcome,
                minimint_ng::core::history::SignaturePolicy::GuardianAdoption,
            )
            .unwrap();
        assert_eq!(outcome.outcome, first.outcome);
        assert!(accepted_output_modules(&snapshot, &id).unwrap().is_some());
    }
    r.stop();
}
#[test]
fn single_retry_keeps_front_and_wakes_acceptance_pollers() {
    let r = Running::new(1, 100);
    let tx = transaction(2);
    let id = transaction_id(&tx);
    r.handles[0]
        .propose(module(wallet::ConsensusItem::BlockCount(1)))
        .unwrap();
    wait(|| r.backends[0].attempts.load(Ordering::SeqCst) > 1);
    r.handles[0]
        .propose(ConsensusItem::Transaction(tx))
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(
        accepted_output_modules(&r.stores[0].snapshot().unwrap(), &id)
            .unwrap()
            .is_none()
    );
    let revision = r.handles[0].revision();
    r.backends[0].scan.store(true, Ordering::SeqCst);
    assert_ne!(
        r.handles[0].wait_for_change(revision, Duration::from_secs(1)),
        revision
    );
    wait(|| {
        accepted_output_modules(&r.stores[0].snapshot().unwrap(), &id)
            .unwrap()
            .is_some()
    });
    assert_eq!(session_count(&r.stores[0].snapshot().unwrap()).unwrap(), 0);
    r.stop();
}
#[test]
fn typed_module_history_adoption_switches_epoch_and_rejects_wrong_indices() {
    let r = Running::new(1, 100);
    let history = signed(
        &r,
        0,
        vec![AcceptedItem {
            peer: PeerId(0),
            item: module(wallet::ConsensusItem::FeeRate(Some(1000))),
        }],
    );
    assert_eq!(
        r.handles[0].submit_history(1, history.clone()),
        Err(HistoryQueueError::Future)
    );
    r.handles[0].submit_history(0, history.clone()).unwrap();
    wait(|| r.handles[0].current_session() == Some(1));
    assert_eq!(
        completed(&r.stores[0].snapshot().unwrap(), 0)
            .unwrap()
            .unwrap(),
        history
    );
    assert_eq!(
        r.handles[0].submit_history(0, history),
        Err(HistoryQueueError::Stale)
    );
    thread::sleep(Duration::from_millis(50));
    assert_eq!(session_count(&r.stores[0].snapshot().unwrap()).unwrap(), 1);
    r.stop();
}
#[test]
fn stopping_mid_session_retains_native_backup_and_committed_prefix() {
    let r = Running::new(4, 500);
    let tx = transaction(3);
    let id = transaction_id(&tx);
    r.handles[0]
        .propose(ConsensusItem::Transaction(tx))
        .unwrap();
    wait(|| {
        r.stores.iter().all(|s| {
            accepted_output_modules(&s.snapshot().unwrap(), &id)
                .unwrap()
                .is_some()
        })
    });
    for h in &r.handles {
        h.request_shutdown();
    }
    wait(|| r.runtimes.iter().all(Runtime::is_finished));
    for s in &r.stores {
        let snapshot = s.snapshot().unwrap();
        assert_eq!(session_count(&snapshot).unwrap(), 0);
        assert!(!s.read_agreement(0).unwrap().is_empty());
        assert!(accepted_output_modules(&snapshot, &id).unwrap().is_some());
    }
    r.stop();
}

#[test]
fn wallet_worker_panic_stops_runtime_and_preserves_native_prefix() {
    let mut r = Running::new(4, 500);
    let tx = transaction(4);
    let id = transaction_id(&tx);
    r.handles[0]
        .propose(ConsensusItem::Transaction(tx))
        .unwrap();
    wait(|| {
        accepted_output_modules(&r.stores[0].snapshot().unwrap(), &id)
            .unwrap()
            .is_some()
    });
    r.backends[0].panic_poll.store(true, Ordering::SeqCst);
    wait(|| r.handles[0].is_stopped() && r.runtimes[0].is_finished());
    assert!(matches!(
        r.runtimes.remove(0).shutdown(),
        Err(minimint_ng::daemon::consensus::RuntimeError::Fatal(
            "wallet-poller-panicked"
        ))
    ));
    assert_eq!(session_count(&r.stores[0].snapshot().unwrap()).unwrap(), 0);
    assert!(!r.stores[0].read_agreement(0).unwrap().is_empty());
    assert!(
        accepted_output_modules(&r.stores[0].snapshot().unwrap(), &id)
            .unwrap()
            .is_some()
    );
    r.stop();
}

#[test]
fn ordered_worker_panic_joins_engine_and_pump_without_completing_history() {
    let mut r = Running::isolated_engine();
    r.backends[0].panic_scan.store(true, Ordering::SeqCst);
    let history = signed(
        &r,
        0,
        (0..3)
            .map(|p| AcceptedItem {
                peer: PeerId(p),
                item: module(wallet::ConsensusItem::BlockCount(1)),
            })
            .collect(),
    );
    r.handles[0].submit_history(0, history).unwrap();
    wait(|| r.handles[0].is_stopped() && r.runtimes[0].is_finished());
    assert!(matches!(
        r.runtimes.remove(0).shutdown(),
        Err(minimint_ng::daemon::consensus::RuntimeError::Fatal(
            "runtime-panicked"
        ))
    ));
    let snapshot = r.stores[0].snapshot().unwrap();
    assert_eq!(session_count(&snapshot).unwrap(), 0);
    let Some(minimint_ng::protocol::SessionStatusV2::Pending(items)) =
        minimint_ng::core::session::persisted_status(&snapshot, 0).unwrap()
    else {
        panic!("committed prefix missing")
    };
    assert_eq!(items.len(), 2);
    assert!(!r.stores[0].read_agreement(0).unwrap().is_empty());
    r.stop(); // Also asserts that all worker Arc<PeerNetwork> references were released.
}

#[test]
fn cancellation_interrupts_blocked_scan_and_retains_committed_prefix() {
    let mut r = Running::new(1, 100);
    let tx = transaction(5);
    let id = transaction_id(&tx);
    r.handles[0]
        .propose(ConsensusItem::Transaction(tx))
        .unwrap();
    wait(|| {
        accepted_output_modules(&r.stores[0].snapshot().unwrap(), &id)
            .unwrap()
            .is_some()
    });
    r.backends[0].block_scan.store(true, Ordering::SeqCst);
    r.handles[0]
        .propose(module(wallet::ConsensusItem::BlockCount(1)))
        .unwrap();
    wait(|| r.backends[0].attempts.load(Ordering::SeqCst) > 0);
    let start = Instant::now();
    r.handles[0].request_shutdown();
    r.runtimes.remove(0).shutdown().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "cancellable test backend failed to join promptly"
    );
    assert!(
        accepted_output_modules(&r.stores[0].snapshot().unwrap(), &id)
            .unwrap()
            .is_some()
    );
    assert_eq!(session_count(&r.stores[0].snapshot().unwrap()).unwrap(), 0);
    r.stop();
}

#[test]
fn module_bearing_peer_history_is_discarded_but_api_history_is_adopted() {
    let r = Running::isolated_engine();
    wait(|| r.networks[1].connected(PeerId(0)));
    let history = signed(
        &r,
        0,
        vec![AcceptedItem {
            peer: PeerId(0),
            item: module(wallet::ConsensusItem::FeeRate(Some(1000))),
        }],
    );
    r.networks[1]
        .send(
            PeerId(0),
            Envelope::SignedSessionOutcome(history.consensus_encode()),
        )
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(session_count(&r.stores[0].snapshot().unwrap()).unwrap(), 0);
    assert!(
        minimint_ng::core::session::persisted_status(&r.stores[0].snapshot().unwrap(), 0)
            .unwrap()
            .is_none()
    );
    r.handles[0].submit_history(0, history.clone()).unwrap();
    wait(|| r.handles[0].current_session() == Some(1));
    assert_eq!(
        completed(&r.stores[0].snapshot().unwrap(), 0)
            .unwrap()
            .unwrap(),
        history
    );
    r.stop();
}

#[test]
fn pump_failure_cancels_an_ordered_scan_wait_instead_of_stranding_runtime() {
    let mut r = Running::new(1, 100);
    r.backends[0].block_scan.store(true, Ordering::SeqCst);
    r.handles[0]
        .propose(module(wallet::ConsensusItem::BlockCount(1)))
        .unwrap();
    wait(|| r.backends[0].attempts.load(Ordering::SeqCst) > 0);
    r.networks[0].request_shutdown();
    wait(|| r.handles[0].is_stopped() && r.runtimes[0].is_finished());
    assert!(matches!(
        r.runtimes.remove(0).shutdown(),
        Err(minimint_ng::daemon::consensus::RuntimeError::Fatal(
            "peer-network-closed"
        ))
    ));
    assert_eq!(session_count(&r.stores[0].snapshot().unwrap()).unwrap(), 0);
    r.stop();
}

#[test]
fn retrying_history_target_finishes_before_newer_history_commands() {
    let r = Running::new(1, 100);
    let first = signed(
        &r,
        0,
        vec![AcceptedItem {
            peer: PeerId(0),
            item: module(wallet::ConsensusItem::BlockCount(1)),
        }],
    );
    let later = signed(
        &r,
        0,
        vec![AcceptedItem {
            peer: PeerId(0),
            item: module(wallet::ConsensusItem::FeeRate(Some(1000))),
        }],
    );
    r.handles[0].submit_history(0, first.clone()).unwrap();
    wait(|| r.backends[0].attempts.load(Ordering::SeqCst) > 1);
    r.handles[0].submit_history(0, later).unwrap();
    r.backends[0].scan.store(true, Ordering::SeqCst);
    wait(|| r.handles[0].current_session() == Some(1));
    thread::sleep(Duration::from_millis(30));
    assert_eq!(
        completed(&r.stores[0].snapshot().unwrap(), 0)
            .unwrap()
            .unwrap(),
        first
    );
    assert!(!r.handles[0].is_stopped());
    r.stop();
}

#[test]
fn each_adoption_commit_notifies_even_when_the_next_scan_blocks() {
    let r = Running::new(1, 100);
    r.backends[0].block_scan.store(true, Ordering::SeqCst);
    let mut items: Vec<_> = (0..10)
        .map(|i| AcceptedItem {
            peer: PeerId(0),
            item: module(wallet::ConsensusItem::FeeRate(Some(1000 + i))),
        })
        .collect();
    items.push(AcceptedItem {
        peer: PeerId(0),
        item: module(wallet::ConsensusItem::BlockCount(1)),
    });
    let revision = r.handles[0].revision();
    r.handles[0]
        .submit_history(0, signed(&r, 0, items))
        .unwrap();
    wait(|| r.backends[0].attempts.load(Ordering::SeqCst) > 0);
    // The ordered worker is still inside one adopt() call. Its outer tick cannot
    // supply these notifications; each preceding committed item must do so.
    assert!(r.handles[0].revision().wrapping_sub(revision) >= 10);
    let Some(minimint_ng::protocol::SessionStatusV2::Pending(items)) =
        minimint_ng::core::session::persisted_status(&r.stores[0].snapshot().unwrap(), 0).unwrap()
    else {
        panic!("missing pending prefix")
    };
    assert_eq!(items.len(), r.configs.len() + 10);
    r.stop();
}

#[test]
fn backend_fee_failure_withdraws_a_present_vote_and_recovery_remains_possible() {
    use minimint_ng::{
        bitcoin::{BackendError, BitcoinBackend},
        daemon::consensus::RuntimeBackend,
    };
    use std::sync::atomic::{AtomicBool, AtomicU8};
    struct FeeBackend {
        mode: AtomicU8,
        stopped: AtomicBool,
    }
    impl BitcoinBackend for FeeBackend {
        fn block_count(&self) -> Result<u64, BackendError> {
            Err(BackendError)
        }
        fn wait_for_count(&self, _: u64) -> Result<(), BackendError> {
            Err(BackendError)
        }
        fn block_hash(&self, _: u64) -> Result<[u8; 32], BackendError> {
            Err(BackendError)
        }
        fn block(&self, _: [u8; 32]) -> Result<minimint_ng::bitcoin::Block, BackendError> {
            Err(BackendError)
        }
        fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
            match self.mode.load(Ordering::SeqCst) {
                0 => Ok(Some(2500)),
                1 => Err(BackendError),
                _ => Ok(None),
            }
        }
        fn broadcast(&self, _: &minimint_ng::bitcoin::Transaction) -> Result<(), BackendError> {
            Ok(())
        }
    }
    impl RuntimeBackend for FeeBackend {
        fn request_shutdown(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
    }
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = configs(1, 3600, std::slice::from_ref(&listener))
        .pop()
        .unwrap();
    let network = Arc::new(
        PeerNetwork::start(
            PeerId(0),
            config.tls_config(),
            config.resolve_peer_addresses().unwrap(),
            listener,
            64,
        )
        .unwrap(),
    );
    let backend = Arc::new(FeeBackend {
        mode: AtomicU8::new(0),
        stopped: AtomicBool::new(false),
    });
    let (runtime, handle) = Runtime::start(
        store.clone(),
        config.clone(),
        network.clone(),
        backend.clone(),
        RuntimeOptions {
            tick: Duration::from_millis(2),
            wallet_poll_interval: Duration::from_millis(5),
            ..RuntimeOptions::default()
        },
    )
    .unwrap();
    let await_rate = |expected| {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = config
                .modules()
                .wallet()
                .snapshot(&store.snapshot().unwrap())
                .unwrap()
                .consensus_fee_rate;
            if observed == expected {
                break;
            }
            assert!(
                Instant::now() < end,
                "fee observation did not become accepted consensus state"
            );
            assert!(!handle.is_stopped());
            thread::sleep(Duration::from_millis(5));
        }
    };
    await_rate(Some(2500));
    backend.mode.store(1, Ordering::SeqCst);
    await_rate(None); // Failure must withdraw the existing present vote, not skip proposal.
    backend.mode.store(0, Ordering::SeqCst);
    await_rate(Some(2500));
    backend.mode.store(2, Ordering::SeqCst);
    await_rate(None); // Preserve successful no-estimate observations pending Q16.
    assert!(!handle.is_stopped());
    runtime.shutdown().unwrap();
    assert!(backend.stopped.load(Ordering::SeqCst));
    let Some(minimint_ng::protocol::SessionStatusV2::Pending(items)) =
        minimint_ng::core::session::persisted_status(&store.snapshot().unwrap(), 0).unwrap()
    else {
        panic!("fee vote history missing")
    };
    let rates: Vec<_> = items
        .iter()
        .map(|accepted| {
            let ConsensusItem::Module(item) = &accepted.item else {
                panic!("unexpected transaction")
            };
            let wallet::ConsensusItem::FeeRate(rate) =
                minimint_ng::codec::decode_whole(&item.payload).unwrap()
            else {
                panic!("unexpected wallet item")
            };
            rate
        })
        .collect();
    assert_eq!(rates, vec![Some(2500), None, Some(2500), None]);
    Arc::try_unwrap(network).ok().unwrap().shutdown().unwrap();
}
