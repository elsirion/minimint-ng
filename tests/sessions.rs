use minimint_ng::{
    agreement::{Data, FinalizedUnit, ProposalQueue},
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::ConsensusEncode,
    config::{BitcoinNetwork, DescriptorKind, Fee, RawMintConfig, RawWalletConfig},
    core::{
        history::HistoryVerifier,
        session::{Phase, Session, SessionConfig, SessionError, completed, session_count},
    },
    crypto::{
        bls::{G2, Scalar},
        secp::SecretKey,
    },
    modules::{Modules, mint, wallet},
    protocol::{
        AcceptedItem, ConsensusItem, DynamicValue, ModuleId, PeerId, SessionOutcome,
        SignedSessionOutcome, Version,
    },
    storage::Store,
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
    modules_with_wallet_id(WALLET)
}
fn modules_with_wallet_id(wallet_id: ModuleId) -> Modules {
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
        wallet_id,
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
fn block() -> ConsensusItem {
    ConsensusItem::Module(DynamicValue {
        module_id: WALLET,
        payload: wallet::ConsensusItem::BlockCount(1).consensus_encode(),
    })
}
fn item(peer: u16, item: ConsensusItem) -> AcceptedItem {
    AcceptedItem {
        peer: PeerId(peer),
        item,
    }
}
fn batch(session: &mut Session, peer: u16, items: Vec<ConsensusItem>) {
    session.enqueue(FinalizedUnit {
        creator: PeerId(peer),
        round: 0,
        data: Some(Data::Batch(items.consensus_encode())),
    });
}
fn sign(items: Vec<AcceptedItem>) -> SignedSessionOutcome {
    let verifier = HistoryVerifier::new(config().broadcast_keys).unwrap();
    let outcome = SessionOutcome { items };
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
    SignedSessionOutcome {
        outcome,
        signatures,
    }
}
fn queue() -> ProposalQueue {
    ProposalQueue::new(32).unwrap().0
}
#[test]
fn batch_gate_rejects_whole_batch_but_item_rejection_preserves_later_items() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let mut s = Session::open(store, config()).unwrap();
    let q = queue();
    batch(
        &mut s,
        0,
        vec![
            fee(1000),
            ConsensusItem::Module(DynamicValue {
                module_id: ModuleId(300),
                payload: vec![],
            }),
        ],
    );
    s.drive(&m, &backend(), &q).unwrap();
    assert!(s.status().pending.items.is_empty());
    batch(
        &mut s,
        0,
        vec![
            ConsensusItem::Unknown {
                tag: 99,
                payload: vec![],
            },
            fee(1000),
            fee(1000),
            fee(1100),
        ],
    );
    s.drive(&m, &backend(), &q).unwrap();
    assert_eq!(
        s.status().pending.items,
        vec![item(0, fee(1000)), item(0, fee(1100))]
    );
}
#[test]
fn restart_replays_only_matching_item_and_creator_without_reexecution() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    let mut first = Session::open(store.clone(), config()).unwrap();
    batch(&mut first, 0, vec![fee(1000)]);
    batch(&mut first, 1, vec![fee(1100)]);
    first.drive(&m, &backend(), &q).unwrap();
    drop(first);
    let mut s = Session::open(store.clone(), config()).unwrap();
    assert_eq!(s.status().replay_cursor, 0);
    batch(&mut s, 0, vec![fee(900)]);
    batch(&mut s, 1, vec![fee(1000)]);
    batch(&mut s, 0, vec![fee(1000)]);
    batch(&mut s, 1, vec![fee(1100)]);
    batch(&mut s, 2, vec![fee(1200)]);
    s.drive(&m, &backend(), &q).unwrap();
    assert_eq!(s.status().replay_cursor, 3);
    assert_eq!(
        s.status().pending.items,
        vec![item(0, fee(1000)), item(1, fee(1100)), item(2, fee(1200))]
    );
    assert_eq!(
        m.wallet()
            .snapshot(&store.snapshot().unwrap())
            .unwrap()
            .consensus_fee_rate,
        Some(1200)
    );
}
struct Flaky {
    ready: std::cell::Cell<bool>,
}
impl BitcoinBackend for Flaky {
    fn block_count(&self) -> Result<u64, BackendError> {
        backend().block_count()
    }
    fn wait_for_count(&self, n: u64) -> Result<(), BackendError> {
        if self.ready.get() {
            backend().wait_for_count(n)
        } else {
            Err(BackendError)
        }
    }
    fn block_hash(&self, n: u64) -> Result<[u8; 32], BackendError> {
        backend().block_hash(n)
    }
    fn block(&self, h: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        backend().block(h)
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Ok(None)
    }
    fn broadcast(&self, _: &bitcoin::Transaction) -> Result<(), BackendError> {
        Err(BackendError)
    }
}
#[test]
fn scan_retry_keeps_batch_tail_ahead_of_newer_units() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    let mut s = Session::open(store.clone(), config()).unwrap();
    let b = Flaky {
        ready: std::cell::Cell::new(false),
    };
    batch(&mut s, 0, vec![block()]);
    batch(&mut s, 1, vec![block()]);
    batch(&mut s, 2, vec![block(), fee(1000)]);
    batch(&mut s, 3, vec![fee(1100)]);
    assert!(matches!(s.drive(&m, &b, &q), Err(SessionError::Retry)));
    assert_eq!(s.status().pending.items.len(), 2);
    assert_eq!(s.queued_work(), 3);
    b.ready.set(true);
    s.drive(&m, &b, &q).unwrap();
    assert_eq!(
        s.status().pending.items,
        vec![
            item(0, block()),
            item(1, block()),
            item(2, block()),
            item(2, fee(1000)),
            item(3, fee(1100))
        ]
    );
    assert_eq!(
        m.wallet()
            .snapshot(&store.snapshot().unwrap())
            .unwrap()
            .block_count,
        1
    );
}
#[test]
fn boundary_data_is_ignored_and_distinct_signatures_complete() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    let mut s = Session::open(store, config()).unwrap();
    batch(&mut s, 0, vec![fee(1000)]);
    s.enqueue(FinalizedUnit {
        creator: PeerId(1),
        round: 12,
        data: Some(Data::Batch(vec![fee(2000)].consensus_encode())),
    });
    s.drive(&m, &backend(), &q).unwrap();
    assert_eq!(s.status().phase, Phase::Signing);
    assert_eq!(s.status().pending.items, vec![item(0, fee(1000))]);
    assert!(matches!(
        s.receive_signature(PeerId(1), [0; 64]),
        Err(SessionError::Rejected)
    ));
    let signed = sign(s.status().pending.items);
    for _ in 0..3 {
        s.receive_signature(PeerId(1), signed.signatures[&PeerId(1)])
            .unwrap();
    }
    assert_eq!(s.status().phase, Phase::Signing);
    s.receive_signature(PeerId(2), signed.signatures[&PeerId(2)])
        .unwrap();
    assert_eq!(s.status().phase, Phase::Ready);
    // State-only open cannot bypass native-engine shutdown.
    assert!(matches!(
        s.finish(),
        Err(SessionError::Fatal("missing-owned-agreement-engine"))
    ));
}
#[test]
fn adoption_validates_signatures_before_prefix_and_rejects_unexecutable_suffix_fatally() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    let mut s = Session::open(store.clone(), config()).unwrap();
    batch(&mut s, 0, vec![fee(1000)]);
    s.drive(&m, &backend(), &q).unwrap();
    let mut shorter = sign(vec![]);
    shorter.signatures.insert(PeerId(0), [0; 64]);
    assert!(matches!(
        s.adopt(shorter, &m, &backend()),
        Err(SessionError::Rejected)
    ));
    assert!(matches!(
        s.adopt(sign(vec![]), &m, &backend()),
        Err(SessionError::Fatal("divergent-adopted-prefix"))
    ));
    let mut s = Session::open(store.clone(), config()).unwrap();
    let duplicate = sign(vec![item(0, fee(1000)), item(0, fee(1000))]);
    assert!(matches!(
        s.adopt(duplicate, &m, &backend()),
        Err(SessionError::Fatal("adopted-item-rejected"))
    ));
    assert_eq!(s.status().pending.items.len(), 1);
    let mut s = Session::open(store, config()).unwrap();
    s.adopt(
        sign(vec![item(0, fee(1000)), item(1, fee(1200))]),
        &m,
        &backend(),
    )
    .unwrap();
    assert_eq!(s.status().phase, Phase::Ready);
    assert_eq!(s.status().pending.items.len(), 2);
}
#[test]
fn adoption_retry_pins_suffix_and_never_executes_newer_queue() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    let mut s = Session::open(store, config()).unwrap();
    let b = Flaky {
        ready: std::cell::Cell::new(false),
    };
    let target = sign(vec![
        item(0, block()),
        item(1, block()),
        item(2, block()),
        item(2, fee(1000)),
    ]);
    assert!(matches!(
        s.adopt(target.clone(), &m, &b),
        Err(SessionError::Retry)
    ));
    assert_eq!(s.status().pending.items.len(), 2);
    batch(&mut s, 0, vec![fee(5000)]);
    assert!(matches!(s.drive(&m, &b, &q), Err(SessionError::Retry)));
    assert_eq!(s.queued_work(), 1);
    b.ready.set(true);
    s.drive(&m, &b, &q).unwrap();
    assert_eq!(s.ready_outcome(), Some(&target));
    assert_eq!(s.queued_work(), 1);
}
#[test]
fn single_guardian_timeout_requires_item_and_completes_atomically() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    let mut c = config();
    c.broadcast_keys.retain(|peer, _| peer.0 == 0);
    let mut s = Session::open(store.clone(), c).unwrap();
    s.process_single(
        fee(1000),
        std::time::Duration::from_secs(60),
        &m,
        &backend(),
        &q,
    )
    .unwrap();
    assert_eq!(s.status().phase, Phase::Collecting);
    // Silence does not transition; even a rejected item is processed at the next wakeup.
    assert!(matches!(
        s.process_single(
            fee(1000),
            std::time::Duration::from_secs(61),
            &m,
            &backend(),
            &q
        ),
        Err(SessionError::Rejected)
    ));
    assert_eq!(s.status().phase, Phase::Ready);
    let signed = s.finish().unwrap();
    assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 1);
    assert_eq!(
        completed(&store.snapshot().unwrap(), 0).unwrap(),
        Some(signed)
    );
}
#[test]
fn transaction_marker_and_pending_history_commit_once_together() {
    use minimint_ng::{
        core::transaction::{accepted_output_modules, transaction_id},
        protocol::{Transaction, TransactionSignatures},
    };
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    let mut s = Session::open(store.clone(), config()).unwrap();
    let transaction = Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [0; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    let id = transaction_id(&transaction);
    batch(
        &mut s,
        0,
        vec![
            ConsensusItem::Transaction(transaction.clone()),
            ConsensusItem::Transaction(transaction),
        ],
    );
    s.drive(&m, &backend(), &q).unwrap();
    assert_eq!(s.status().pending.items.len(), 1);
    assert_eq!(
        accepted_output_modules(&store.snapshot().unwrap(), &id).unwrap(),
        Some(vec![])
    );
    assert!(
        matches!(minimint_ng::core::session::persisted_status(&store.snapshot().unwrap(),0).unwrap(),Some(minimint_ng::protocol::SessionStatusV2::Pending(items)) if items.len()==1)
    );
}
#[test]
fn corrupt_noncontiguous_records_and_extra_completed_signature_are_fatal() {
    use minimint_ng::storage::Namespace;
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let pending_key = [&b"core/session/v1/pending/"[..], &1u64.to_be_bytes()].concat();
    let mut writer = store.transaction().unwrap();
    writer
        .put(
            Namespace::Replicated,
            &pending_key,
            &item(0, fee(1000)).consensus_encode(),
        )
        .unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        Session::open(store.clone(), config()),
        Err(SessionError::Fatal("noncontiguous-pending"))
    ));
    let mut writer = store.transaction().unwrap();
    writer.delete(Namespace::Replicated, &pending_key).unwrap();
    let mut signed = sign(vec![]);
    let verifier = HistoryVerifier::new(config().broadcast_keys).unwrap();
    signed.signatures.insert(
        PeerId(3),
        verifier
            .sign(0, &signed.outcome, PeerId(3), &secret(4))
            .unwrap(),
    );
    verifier
        .verify(
            0,
            &signed,
            minimint_ng::core::history::SignaturePolicy::Generic,
        )
        .unwrap();
    writer
        .put(
            Namespace::Replicated,
            b"core/session/v1/count",
            &1u64.consensus_encode(),
        )
        .unwrap();
    writer
        .put(
            Namespace::Replicated,
            &[&b"core/session/v1/completed/"[..], &0u64.to_be_bytes()].concat(),
            &signed.consensus_encode(),
        )
        .unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        Session::open(store, config()),
        Err(SessionError::Fatal("invalid-completed-signatures"))
    ));
}
#[test]
fn negative_audit_rolls_back_successful_module_item_and_stops_session() {
    use minimint_ng::storage::Namespace;
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let q = queue();
    // Inject one outstanding denomination-0 Mint note without backing assets.
    // The fee vote itself succeeds, then the required all-module audit must fail.
    let mut writer = store.transaction().unwrap();
    writer
        .put(
            Namespace::Replicated,
            &[&b"mint/v1/"[..], &42u16.to_be_bytes(), &[1, 0]].concat(),
            &1u64.to_be_bytes(),
        )
        .unwrap();
    writer.commit().unwrap();
    let before = store
        .snapshot()
        .unwrap()
        .scan_prefix(Namespace::Replicated, b"")
        .unwrap();
    let mut s = Session::open(store.clone(), config()).unwrap();
    batch(&mut s, 0, vec![fee(1000), fee(2000)]);
    assert!(matches!(
        s.drive(&m, &backend(), &q),
        Err(SessionError::Fatal("module-audit"))
    ));
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Replicated, b"")
            .unwrap(),
        before
    );
    assert!(s.status().pending.items.is_empty());
    assert_eq!(s.queued_work(), 2);
    assert!(matches!(
        s.drive(&m, &backend(), &q),
        Err(SessionError::Fatal("session-stopped"))
    ));
    assert!(matches!(
        s.adopt(sign(vec![]), &m, &backend()),
        Err(SessionError::Fatal("session-stopped"))
    ));
}

#[test]
fn first_none_votes_preserve_the_two_public_reference_history_frames() {
    use minimint_ng::codec::{
        decode_whole,
        text::{hex_decode, hex_encode},
    };
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};
    // Public accepted-item bytes captured from the reference's pending session:
    // Wallet instance 1, FeeRate(None), first submitted by peer 1 and then peer 0.
    // The former admission rule omitted exactly these two leaves locally.
    let captured = minimint_ng::json::parse(
        include_bytes!("fixtures/interop/first-none-vote.json"),
        4096,
        64,
    )
    .unwrap();
    let frames: Vec<_> = captured["missing_accepted_items_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(frames, ["0105010301010001", "0105010301010000"]);
    let accepted: Vec<AcceptedItem> = frames
        .iter()
        .map(|frame| decode_whole(&hex_decode(frame).unwrap()).unwrap())
        .collect();
    let captured_pending = |name: &str| {
        let wrapped = vec![captured[name][0].as_str().unwrap().to_owned()];
        let minimint_ng::protocol::SessionStatus::Pending(items) =
            minimint_ng::codec::rpc::decode_hex(&wrapped).unwrap()
        else {
            panic!("captured status must be pending")
        };
        items
    };
    let before = captured_pending("before_fix");
    let reference = captured_pending("reference");
    assert_eq!((before.len(), reference.len()), (10, 12));
    assert_eq!(
        reference
            .into_iter()
            .filter(|item| !accepted.contains(item))
            .collect::<Vec<_>>(),
        before
    );
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let modules = modules_with_wallet_id(ModuleId(1));
    let mut session = Session::open(store.clone(), config()).unwrap();
    let (proposals, _) = ProposalQueue::new(32).unwrap();
    for accepted in &accepted {
        batch(&mut session, accepted.peer.0, vec![accepted.item.clone()]);
    }
    session.drive(&modules, &backend(), &proposals).unwrap();
    assert_eq!(session.status().pending.items, accepted);
    assert_eq!(
        hex_encode(&session.status().pending.consensus_encode()),
        "0201050103010100010105010301010000"
    );
    for accepted in &accepted {
        batch(&mut session, accepted.peer.0, vec![accepted.item.clone()]);
    }
    session.drive(&modules, &backend(), &proposals).unwrap();
    assert_eq!(session.status().pending.items, accepted);
    assert_eq!(
        Session::open(store, config())
            .unwrap()
            .status()
            .pending
            .items,
        accepted
    );
}
