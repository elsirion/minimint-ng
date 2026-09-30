use minimint_ng::{
    api::core::{CoreFailure, CoreOperation, CorePoll, CoreRequest, ProposalUnavailable},
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::{ConsensusEncode, rpc},
    config::{BitcoinNetwork, DescriptorKind, Fee, RawMintConfig, RawWalletConfig},
    core::{
        session::{Session, SessionConfig},
        transaction::{self},
    },
    crypto::{
        bls::{G2, Scalar},
        secp::SecretKey,
    },
    modules::{Modules, mint, wallet},
    protocol::{
        ConsensusItem, ModuleId, PeerId, Transaction, TransactionError, TransactionSignatures,
        Version,
    },
    storage::Store,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
const MINT: ModuleId = ModuleId(42);
const WALLET: ModuleId = ModuleId(99);
const VERSION: Version = Version { major: 2, minor: 1 };
pub fn secret(n: u64) -> SecretKey {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_bytes(&b).unwrap()
}
pub fn modules() -> Modules {
    modules_with_wallet_fee(Fee {
        base: 100000,
        parts_per_million: 0,
    })
}
fn modules_with_wallet_fee(fee: Fee) -> Modules {
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
            fee_consensus: fee,
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

fn observe_deposit(store: &Store, modules: &Modules) {
    let script = minimint_ng::codec::text::hex_decode(
        "00206760a3fc7b8c1d4f7266aa80773672cd98bc5f3e4e9d6eb2edf300156bef0a06",
    )
    .unwrap();
    assert_eq!(
        modules
            .wallet()
            .deposit_script(&secret(53843).public_key())
            .unwrap(),
        script
    );
    let backend = Backend(bitcoin::Block {
        header: [0; 80],
        transactions: vec![bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            inputs: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid([7; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: u32::MAX,
                witness: vec![],
            }],
            outputs: vec![bitcoin::TxOut {
                value_sat: 50000,
                script_pubkey: script,
            }],
        }],
    });
    for item in [
        wallet::ConsensusItem::BlockCount(1),
        wallet::ConsensusItem::FeeRate(Some(1000)),
    ] {
        for peer in 0..3 {
            let request = modules
                .wallet()
                .required_scan(&store.snapshot().unwrap(), PeerId(peer), &item)
                .unwrap();
            let prepared = request.map(|r| wallet::prepare_scan(&backend, r).unwrap());
            let mut tx = store.transaction().unwrap();
            modules
                .wallet()
                .process_consensus(&mut tx, PeerId(peer), &item, prepared.as_ref())
                .unwrap();
            modules.audit(&tx).unwrap();
            tx.commit().unwrap();
        }
    }
}
fn config(single: bool) -> SessionConfig {
    SessionConfig {
        broadcast_keys: (0..if single { 1 } else { 4 })
            .map(|i| (PeerId(i), secret(u64::from(i) + 1).public_key()))
            .collect(),
        local_peer: PeerId(0),
        local_key: secret(1),
        version: VERSION,
        rounds: 12,
    }
}
fn empty() -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [0; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    }
}
fn backend() -> Backend {
    Backend(bitcoin::Block {
        header: [0; 80],
        transactions: vec![],
    })
}
fn accept(store: &Store, m: &Modules, tx: Transaction) {
    let mut s = Session::open(store.clone(), config(false)).unwrap();
    // Match any already persisted prefix before extending this restarted driver.
    for accepted in s.status().pending.items {
        s.enqueue(minimint_ng::agreement::FinalizedUnit {
            creator: accepted.peer,
            round: 0,
            data: Some(minimint_ng::agreement::Data::Batch(
                vec![accepted.item].consensus_encode(),
            )),
        });
    }
    s.enqueue(minimint_ng::agreement::FinalizedUnit {
        creator: PeerId(0),
        round: 0,
        data: Some(minimint_ng::agreement::Data::Batch(
            vec![ConsensusItem::Transaction(tx)].consensus_encode(),
        )),
    });
    s.drive(
        m,
        &backend(),
        &minimint_ng::agreement::ProposalQueue::new(32).unwrap().0,
    )
    .unwrap();
}
fn ready(poll: CorePoll) -> Value {
    match poll {
        CorePoll::Ready(value) => value,
        CorePoll::Pending => panic!("unexpected pending"),
    }
}
fn array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}
fn submission(value: &Value) -> Result<[u8; 32], TransactionError> {
    rpc::decode_hex(&array(value)).unwrap()
}
fn poll(op: &mut CoreOperation, store: &Store, m: &Modules) -> Result<CorePoll, CoreFailure> {
    op.poll(store, m, VERSION, &mut |_| {
        panic!("read endpoint proposed transaction")
    })
}
fn claim(nonce: u8) -> Transaction {
    let mut tx = Transaction {
        inputs: vec![minimint_ng::protocol::DynamicValue {
            module_id: WALLET,
            payload: wallet::Input::V0 {
                output_index: 0,
                claimant: secret(53843).public_key(),
                mining_fee_sat: 316,
            }
            .consensus_encode(),
        }],
        outputs: vec![],
        nonce: [nonce; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    tx.signatures = TransactionSignatures::Schnorr(vec![
        secret(53843)
            .schnorr_sign(&transaction::transaction_id(&tx))
            .unwrap(),
    ]);
    tx
}
#[test]
fn queue_ack_is_pending_full_retries_without_revision_and_acceptance_is_idempotent() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let tx = empty();
    let id = transaction::transaction_id(&tx);
    let mut op = CoreOperation::new(CoreRequest::Submit(tx.clone()));
    let mut attempts = 0;
    let mut submit = |_: ConsensusItem| {
        attempts += 1;
        if attempts < 3 {
            Err(ProposalUnavailable::Full)
        } else {
            Ok(())
        }
    };
    for _ in 0..4 {
        assert!(matches!(
            op.poll(&store, &m, VERSION, &mut submit).unwrap(),
            CorePoll::Pending
        ));
    }
    assert_eq!(attempts, 3);
    assert!(
        transaction::accepted_output_modules(&store.snapshot().unwrap(), &id)
            .unwrap()
            .is_none()
    );
    accept(&store, &m, tx.clone());
    assert_eq!(
        submission(&ready(poll(&mut op, &store, &m).unwrap())).unwrap(),
        id
    );
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    let mut changed = tx;
    changed.signatures = TransactionSignatures::Unknown {
        tag: 19,
        payload: vec![1, 2],
    };
    let request =
        CoreRequest::decode("submit_transaction", &json!(rpc::hex(&changed)), &m).unwrap();
    let mut op = CoreOperation::new(request);
    assert_eq!(
        submission(&ready(poll(&mut op, &store, &m).unwrap())).unwrap(),
        id
    );
}
#[test]
fn submission_invalid_encoding_is_outer_error_and_validation_is_encoded_with_rollback() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    assert_eq!(
        CoreRequest::decode("submit_transaction", &json!(["00"]), &m)
            .err()
            .unwrap()
            .code,
        400
    );
    let mut tx = empty();
    tx.outputs.push(minimint_ng::protocol::DynamicValue {
        module_id: MINT,
        payload: mint::Output::V0(mint::OutputV0 {
            denomination: 0,
            blinded_message: mint::G1Bytes::from_bytes(
                minimint_ng::crypto::bls::G1::generator().to_bytes(),
            )
            .unwrap(),
            tweak: [0; 16],
        })
        .consensus_encode(),
    });
    let before = store
        .snapshot()
        .unwrap()
        .scan_prefix(minimint_ng::storage::Namespace::Replicated, b"")
        .unwrap();
    let mut op = CoreOperation::new(CoreRequest::Submit(tx));
    let result = submission(&ready(poll(&mut op, &store, &m).unwrap()));
    assert!(matches!(
        result,
        Err(TransactionError::UnbalancedTransaction { .. })
    ));
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(minimint_ng::storage::Namespace::Replicated, b"")
            .unwrap(),
        before
    );
}
#[test]
fn pending_submission_revalidates_after_another_transaction_spends_deposit() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    observe_deposit(&store, &m);
    let mut op = CoreOperation::new(CoreRequest::Submit(claim(1)));
    let mut proposed = 0;
    assert!(matches!(
        op.poll(&store, &m, VERSION, &mut |_| {
            proposed += 1;
            Ok(())
        })
        .unwrap(),
        CorePoll::Pending
    ));
    assert!(
        m.wallet()
            .snapshot(&store.snapshot().unwrap())
            .unwrap()
            .wallet
            .is_none()
    );
    accept(&store, &m, claim(2));
    assert!(matches!(
        submission(&ready(poll(&mut op, &store, &m).unwrap())),
        Err(TransactionError::Input(_))
    ));
    assert_eq!(proposed, 1);
}
#[test]
fn boundary_reproposes_and_history_waits_return_exact_wrappers() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let mut op = CoreOperation::new(CoreRequest::Submit(empty()));
    let mut sent = 0;
    assert!(matches!(
        op.poll(&store, &m, VERSION, &mut |_| {
            sent += 1;
            Ok(())
        })
        .unwrap(),
        CorePoll::Pending
    ));
    let mut history = CoreOperation::new(CoreRequest::AwaitSession {
        index: 0,
        signed: true,
    });
    assert!(matches!(
        poll(&mut history, &store, &m).unwrap(),
        CorePoll::Pending
    ));
    let mut s = Session::open(store.clone(), config(true)).unwrap();
    assert!(
        s.process_single(
            ConsensusItem::Unknown {
                tag: 99,
                payload: vec![]
            },
            std::time::Duration::from_secs(61),
            &m,
            &backend(),
            &minimint_ng::agreement::ProposalQueue::new(1).unwrap().0
        )
        .is_err()
    );
    let signed = s.finish().unwrap();
    assert!(matches!(
        op.poll(&store, &m, VERSION, &mut |_| {
            sent += 1;
            Ok(())
        })
        .unwrap(),
        CorePoll::Pending
    ));
    assert_eq!(sent, 2);
    assert_eq!(
        ready(poll(&mut history, &store, &m).unwrap()),
        json!(rpc::hex(&signed))
    );
    let mut legacy = CoreOperation::new(CoreRequest::AwaitSession {
        index: 0,
        signed: false,
    });
    assert_eq!(
        ready(poll(&mut legacy, &store, &m).unwrap()),
        json!(rpc::hex(&signed.outcome))
    );
    let mut status = CoreOperation::new(CoreRequest::SessionStatus {
        index: 0,
        signed: true,
    });
    assert_eq!(
        ready(poll(&mut status, &store, &m).unwrap()),
        json!(rpc::base64(
            &minimint_ng::protocol::SessionStatusV2::Complete(signed)
        ))
    );
    let mut count = CoreOperation::new(CoreRequest::SessionCount);
    assert_eq!(
        ready(poll(&mut count, &store, &m).unwrap()).as_u64(),
        Some(1)
    );
}
#[test]
fn signature_phase_refusal_retries_next_session_and_waits_for_durable_acceptance() {
    use fedimint_aleph_bft::DataProvider;
    use minimint_ng::agreement::{AgreementError, Data, ProposalQueue};

    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let tx = empty();
    let id = transaction::transaction_id(&tx);
    let mut operation = CoreOperation::new(
        CoreRequest::decode("submit_transaction", &json!(rpc::hex(&tx)), &m).unwrap(),
    );
    let (old_queue, mut old_provider) = ProposalQueue::new(4).unwrap();
    let mut session = Session::open(store.clone(), config(true)).unwrap();
    // The real session boundary switches its real proposal queue to signatures.
    // This n1 fixture becomes Ready immediately; the queue remains in the same
    // signature-only state used by a larger federation while gathering quorum.
    assert!(matches!(
        session.process_single(
            ConsensusItem::Unknown {
                tag: 99,
                payload: vec![],
            },
            std::time::Duration::from_secs(61),
            &m,
            &backend(),
            &old_queue,
        ),
        Err(minimint_ng::core::session::SessionError::Rejected)
    ));
    assert!(matches!(
        futures::executor::block_on(old_provider.get_data()),
        Some(Data::Signature(_))
    ));
    let mut refusals = 0;
    assert!(matches!(
        operation
            .poll(&store, &m, VERSION, &mut |item| {
                assert_eq!(old_queue.push(item), Err(AgreementError::SignaturePhase));
                refusals += 1;
                Err(ProposalUnavailable::SignaturePhase)
            })
            .unwrap(),
        CorePoll::Pending
    ));
    assert_eq!(refusals, 1);
    assert!(session.finish().unwrap().outcome.items.is_empty());
    assert_eq!(
        minimint_ng::core::session::session_count(&store.snapshot().unwrap()).unwrap(),
        1
    );

    let (next_queue, mut next_provider) = ProposalQueue::new(4).unwrap();
    let mut submissions = 0;
    for _ in 0..2 {
        assert!(matches!(
            operation
                .poll(&store, &m, VERSION, &mut |item| {
                    next_queue.push(item).unwrap();
                    submissions += 1;
                    Ok(())
                })
                .unwrap(),
            CorePoll::Pending
        ));
    }
    assert_eq!(submissions, 1);
    assert!(
        transaction::accepted_output_modules(&store.snapshot().unwrap(), &id)
            .unwrap()
            .is_none()
    );
    let Some(Data::Batch(bytes)) = futures::executor::block_on(next_provider.get_data()) else {
        panic!("next session must propose the still-pending transaction");
    };
    let mut items = minimint_ng::codec::decode_whole::<Vec<ConsensusItem>>(&bytes).unwrap();
    assert_eq!(items, vec![ConsensusItem::Transaction(tx)]);
    assert!(futures::executor::block_on(next_provider.get_data()).is_none());

    // Queue delivery still is not acceptance. Execute through the actual session
    // transaction, then reopen before letting the pending API operation succeed.
    let mut session = Session::open(store.clone(), config(true)).unwrap();
    assert_eq!(session.status().index, 1);
    session
        .process_single(
            items.pop().unwrap(),
            std::time::Duration::ZERO,
            &m,
            &backend(),
            &next_queue,
        )
        .unwrap();
    drop(session);
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        transaction::accepted_output_modules(&store.snapshot().unwrap(), &id).unwrap(),
        Some(vec![])
    );
    assert_eq!(
        submission(&ready(
            operation
                .poll(&store, &m, VERSION, &mut |_| {
                    panic!("accepted transaction must not be proposed again")
                })
                .unwrap()
        )),
        Ok(id)
    );
}
#[test]
fn persisted_nonempty_status_handlers_preserve_wrappers_and_legacy_completion_after_reopen() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let proposals = minimint_ng::agreement::ProposalQueue::new(4).unwrap().0;
    let mut session = Session::open(store.clone(), config(true)).unwrap();
    session
        .process_single(
            ConsensusItem::Transaction(empty()),
            std::time::Duration::ZERO,
            &m,
            &backend(),
            &proposals,
        )
        .unwrap();
    drop(session);
    drop(store);
    let store = Store::open(dir.path()).unwrap();

    // Literal API-003 envelopes: byte-vector length19, Pending tag1/body17,
    // one accepted transaction (tag0/body13), empty inputs/outputs, zero nonce,
    // empty Schnorr signatures (tag0/body1/list0), and creator0.
    for (method, expected) in [
        (
            "session_status",
            json!(["13011101000d0000000000000000000000010000"]),
        ),
        (
            "signed_session_status",
            json!(["EwERAQANAAAAAAAAAAAAAAABAAA"]),
        ),
    ] {
        let request = CoreRequest::decode(method, &json!(0), &m).unwrap();
        let mut operation = CoreOperation::new(request);
        assert_eq!(ready(poll(&mut operation, &store, &m).unwrap()), expected);
    }
    let mut count =
        CoreOperation::new(CoreRequest::decode("session_count", &json!(null), &m).unwrap());
    assert_eq!(ready(poll(&mut count, &store, &m).unwrap()), json!(0));

    // A fresh request after completion must select completed history, not cache
    // the earlier Pending observation. This n1 fixture isolates API persistence;
    // four-engine restart and quorum validation have separate tests.
    let mut session = Session::open(store.clone(), config(true)).unwrap();
    let mut second = empty();
    second.nonce = [1; 8];
    session
        .process_single(
            ConsensusItem::Transaction(second),
            std::time::Duration::from_secs(61),
            &m,
            &backend(),
            &proposals,
        )
        .unwrap();
    let signed = session.finish().unwrap();
    assert_eq!(signed.outcome.items.len(), 2);
    assert_eq!(signed.signatures.len(), 1);
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    let request = CoreRequest::decode("session_status", &json!(0), &m).unwrap();
    let mut operation = CoreOperation::new(request);
    // Legacy Complete tag2/body33 holds the two accepted items, without the
    // signature map. The second transaction has eight nonce bytes equal to1.
    assert_eq!(
        ready(poll(&mut operation, &store, &m).unwrap()),
        json!(["23022102000d0000000000000000000000010000000d0000010101010101010100010000"])
    );
    let request = CoreRequest::decode("signed_session_status", &json!(0), &m).unwrap();
    let mut operation = CoreOperation::new(request);
    let response = ready(poll(&mut operation, &store, &m).unwrap());
    assert_eq!(
        rpc::decode_base64::<minimint_ng::protocol::SessionStatusV2>(&array(&response)).unwrap(),
        minimint_ng::protocol::SessionStatusV2::Complete(signed)
    );
    let mut count =
        CoreOperation::new(CoreRequest::decode("session_count", &json!(null), &m).unwrap());
    assert_eq!(ready(poll(&mut count, &store, &m).unwrap()), json!(1));
}
#[test]
fn output_ranges_validate_before_wait_empty_ranges_still_wait_and_absent_outcome_is_error() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    let tx = empty();
    let id = transaction::transaction_id(&tx);
    for (start, end) in [(2, 1), (0, 1025)] {
        assert_eq!(CoreRequest::decode("await_outputs_outcomes",&json!({"txid":minimint_ng::codec::text::hex_encode(&id),"idx_range":{"start":start,"end":end}}),&m).err().unwrap().code,400);
    }
    let mut wait = CoreOperation::new(CoreRequest::AwaitTransaction(id));
    assert!(matches!(
        poll(&mut wait, &store, &m).unwrap(),
        CorePoll::Pending
    ));
    let mut range = CoreOperation::new(CoreRequest::AwaitOutputs {
        txid: id,
        range: u64::MAX..u64::MAX,
    });
    assert!(matches!(
        poll(&mut range, &store, &m).unwrap(),
        CorePoll::Pending
    ));
    let mut single =
        CoreOperation::new(CoreRequest::AwaitOutput(minimint_ng::protocol::OutPoint {
            txid: id,
            out_idx: 0,
        }));
    assert!(matches!(
        poll(&mut single, &store, &m).unwrap(),
        CorePoll::Pending
    ));
    accept(&store, &m, tx);
    assert_eq!(ready(poll(&mut range, &store, &m).unwrap()), json!([]));
    assert_eq!(
        poll(&mut single, &store, &m)
            .err()
            .unwrap()
            .rpc_error()
            .code,
        400
    );
    assert_eq!(
        ready(poll(&mut wait, &store, &m).unwrap()),
        json!(minimint_ng::codec::text::hex_encode(&id))
    );
}
#[test]
fn accepted_builtin_output_is_null_in_batch_and_missing_in_single_query() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules();
    observe_deposit(&store, &m);
    let mut tx = claim(9);
    tx.outputs.push(minimint_ng::protocol::DynamicValue {
        module_id: MINT,
        payload: mint::Output::V0(mint::OutputV0 {
            denomination: 0,
            blinded_message: mint::G1Bytes::from_bytes(
                minimint_ng::crypto::bls::G1::generator().to_bytes(),
            )
            .unwrap(),
            tweak: [0; 16],
        })
        .consensus_encode(),
    });
    tx.signatures = TransactionSignatures::Schnorr(vec![
        secret(53843)
            .schnorr_sign(&transaction::transaction_id(&tx))
            .unwrap(),
    ]);
    let id = transaction::transaction_id(&tx);
    accept(&store, &m, tx);
    let mut batch = CoreOperation::new(CoreRequest::AwaitOutputs {
        txid: id,
        range: 0..1,
    });
    assert_eq!(ready(poll(&mut batch, &store, &m).unwrap()), json!([null]));
    let mut single =
        CoreOperation::new(CoreRequest::AwaitOutput(minimint_ng::protocol::OutPoint {
            txid: id,
            out_idx: 0,
        }));
    assert_eq!(
        poll(&mut single, &store, &m)
            .err()
            .unwrap()
            .rpc_error()
            .code,
        400
    );
    let mut invalid = CoreOperation::new(CoreRequest::AwaitOutputs {
        txid: id,
        range: 0..2,
    });
    assert_eq!(
        poll(&mut invalid, &store, &m)
            .err()
            .unwrap()
            .rpc_error()
            .code,
        400
    );
}
#[test]
fn unsupported_module_arithmetic_is_fatal_and_tentative_writes_rollback() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let m = modules_with_wallet_fee(Fee {
        base: u64::MAX,
        parts_per_million: 1,
    });
    observe_deposit(&store, &m);
    let before = store
        .snapshot()
        .unwrap()
        .scan_prefix(minimint_ng::storage::Namespace::Replicated, b"")
        .unwrap();
    let mut op = CoreOperation::new(CoreRequest::Submit(claim(22)));
    let error = poll(&mut op, &store, &m).err().unwrap();
    assert!(matches!(
        error,
        CoreFailure::Fatal("wallet-unsupported-arithmetic-domain")
    ));
    assert_eq!(error.rpc_error(), minimint_ng::api::rpc::RpcError::INTERNAL);
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(minimint_ng::storage::Namespace::Replicated, b"")
            .unwrap(),
        before
    );
}
#[test]
fn audit_session_and_storage_failures_remain_distinct_before_rpc_sanitization() {
    use minimint_ng::{
        core::{audit::require_nonnegative, transaction::ExecutionError},
        storage::{Namespace, StoreError},
    };
    // API submission checks do not add the consensus-only audit. Its failure
    // conversion nevertheless must remain fatal when propagated by the driver.
    let audit = require_nonnegative([-123]).unwrap_err();
    let failure = CoreFailure::from(ExecutionError::FatalAudit(audit));
    assert!(matches!(failure, CoreFailure::Fatal("transaction-audit")));
    assert_eq!(failure.rpc_error().message, "Server error");
    let storage = CoreFailure::from(StoreError::Io(std::io::Error::other(
        "private-path-and-credential",
    )));
    assert!(matches!(storage, CoreFailure::Storage(_)));
    let reply = minimint_ng::api::rpc::response(json!(1), Err(storage.rpc_error()));
    let encoded = minimint_ng::json::encode(&reply).unwrap();
    assert!(!String::from_utf8(encoded).unwrap().contains("private-path"));
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut writer = store.transaction().unwrap();
    writer
        .put(Namespace::Replicated, b"core/session/v1/count", &[255])
        .unwrap();
    writer.commit().unwrap();
    let mut operation = CoreOperation::new(CoreRequest::SessionCount);
    assert!(matches!(
        poll(&mut operation, &store, &modules()),
        Err(CoreFailure::Fatal("corrupt-session-count"))
    ));
}
