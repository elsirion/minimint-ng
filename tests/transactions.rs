use minimint_ng::{
    core::{
        audit::{self, AuditError},
        transaction::*,
    },
    crypto::secp::SecretKey,
    protocol::{
        DynamicValue, ModuleId, OutPoint, Transaction, TransactionError, TransactionSignatures,
        Version,
    },
    storage::{Namespace, Store, StoreError, WriteTransaction},
};
use std::cell::RefCell;
#[path = "fixtures/storage/mod.rs"]
mod fixture;
const V21: Version = Version { major: 2, minor: 1 };

struct Modules {
    inputs: Vec<(u64, u64)>,
    outputs: Vec<(u64, u64)>,
    failure: Option<(&'static str, usize)>,
    infrastructure: bool,
    fatal: bool,
    calls: RefCell<Vec<String>>,
    key: SecretKey,
}
impl Modules {
    fn new(inputs: &[(u64, u64)], outputs: &[(u64, u64)]) -> Self {
        Self {
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
            failure: None,
            infrastructure: false,
            fatal: false,
            calls: RefCell::new(Vec::new()),
            key: SecretKey::from_bytes(&[1; 32]).unwrap(),
        }
    }
    fn call(&self, stage: &'static str, value: &DynamicValue) -> Result<usize, TransitionError> {
        let index = usize::from(value.payload[0]);
        self.calls.borrow_mut().push(format!("{stage}{index}"));
        if self.failure == Some((stage, index)) {
            return Err(if self.fatal {
                TransitionError::FatalInvariant("mint-counter-underflow")
            } else if self.infrastructure {
                TransitionError::Storage(StoreError::Io(std::io::Error::other("injected")))
            } else {
                TransitionError::Module(vec![9, 0])
            });
        }
        Ok(index)
    }
    fn write(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<(), TransitionError> {
        assert_eq!(point.out_idx, u64::from(value.payload[0]));
        for ns in [
            Namespace::Replicated,
            Namespace::Local,
            Namespace::Outbox,
            Namespace::ClientBackup,
        ] {
            tx.put(
                ns,
                &[b's', value.module_id.0 as u8, value.payload[0]],
                &point.txid,
            )?;
        }
        Ok(())
    }
    fn transaction(&self) -> Transaction {
        let values = |len: usize, id| {
            (0..len)
                .map(|i| DynamicValue {
                    module_id: ModuleId(id),
                    payload: vec![i as u8],
                })
                .collect()
        };
        let mut transaction = Transaction {
            inputs: values(self.inputs.len(), 0),
            outputs: values(self.outputs.len(), 1),
            nonce: [3; 8],
            signatures: TransactionSignatures::Schnorr(vec![]),
        };
        let id = transaction_id(&transaction);
        transaction.signatures = TransactionSignatures::Schnorr(
            (0..self.inputs.len())
                .map(|_| self.key.schnorr_sign(&id).unwrap())
                .collect(),
        );
        transaction
    }
}
impl ModuleTransitions for Modules {
    fn stateless_input(&self, value: &DynamicValue) -> Result<(), TransitionError> {
        self.call("stateless", value).map(|_| ())
    }
    fn submission_input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<(), TransitionError> {
        self.call("submit-input", value)?;
        self.write(tx, value, point)
    }
    fn submission_output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<(), TransitionError> {
        self.call("submit-output", value)?;
        self.write(tx, value, point)
    }
    fn input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<InputMeta, TransitionError> {
        let i = self.call("input", value)?;
        self.write(tx, value, point)?;
        Ok(InputMeta {
            amount_msat: self.inputs[i].0,
            fee_msat: self.inputs[i].1,
            public_key: self.key.public_key(),
        })
    }
    fn output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        point: OutPoint,
    ) -> Result<OutputMeta, TransitionError> {
        let i = self.call("output", value)?;
        self.write(tx, value, point)?;
        Ok(OutputMeta {
            amount_msat: self.outputs[i].0,
            fee_msat: self.outputs[i].1,
        })
    }
}
fn rejection(result: Result<[u8; 32], ExecutionError>) -> TransactionError {
    match result {
        Err(ExecutionError::Rejected(error)) => error,
        _ => panic!("expected ordinary rejection"),
    }
}
fn empty(store: &Store) {
    for ns in [
        Namespace::Replicated,
        Namespace::Local,
        Namespace::Outbox,
        Namespace::ClientBackup,
    ] {
        assert!(
            store
                .snapshot()
                .unwrap()
                .scan_prefix(ns, b"")
                .unwrap()
                .is_empty()
        );
    }
}
#[test]
fn submission_is_tentative_consensus_is_atomic_with_caller_history() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = Modules::new(&[(70, 2), (40, 3)], &[(100, 5)]);
    let transaction = modules.transaction();
    let id = check_submission(&store, &transaction, &modules, V21).unwrap();
    assert_eq!(
        *modules.calls.borrow(),
        [
            "stateless0",
            "stateless1",
            "submit-input0",
            "input0",
            "submit-input1",
            "input1",
            "submit-output0",
            "output0"
        ]
    );
    empty(&store);
    modules.calls.borrow_mut().clear();
    let old = store.snapshot().unwrap();
    let mut tx = store.transaction().unwrap();
    assert_eq!(
        apply_consensus(&mut tx, &transaction, &modules, V21).unwrap(),
        id
    );
    assert_eq!(
        *modules.calls.borrow(),
        ["stateless0", "stateless1", "input0", "input1", "output0"]
    );
    assert_eq!(accepted_output_modules(&old, &id).unwrap(), None);
    tx.put(Namespace::Replicated, b"history/accepted/0", &id)
        .unwrap();
    audit::require_nonnegative([100, -100]).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        accepted_output_modules(&store.snapshot().unwrap(), &id).unwrap(),
        Some(vec![ModuleId(1)])
    );
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .get(Namespace::Replicated, b"history/accepted/0")
            .unwrap(),
        Some(id.to_vec())
    );
    assert_eq!(accepted_output_modules(&old, &id).unwrap(), None);
}
#[test]
fn duplicate_api_success_precedes_witness_and_module_checks() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = Modules::new(&[(1, 0)], &[(1, 0)]);
    let mut transaction = modules.transaction();
    let mut tx = store.transaction().unwrap();
    let id = apply_consensus(&mut tx, &transaction, &modules, V21).unwrap();
    tx.commit().unwrap();
    modules.calls.borrow_mut().clear();
    transaction.signatures = TransactionSignatures::Unknown {
        tag: 77,
        payload: vec![0xff],
    };
    assert_eq!(
        check_submission(&store, &transaction, &modules, V21).unwrap(),
        id
    );
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        apply_consensus(&mut tx, &transaction, &modules, V21),
        Err(ExecutionError::AlreadyAccepted)
    ));
    assert!(modules.calls.borrow().is_empty());
}
#[test]
fn stateless_all_before_transitions_and_storage_failure_is_not_rejection() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut modules = Modules::new(&[(1, 0), (1, 0)], &[]);
    modules.failure = Some(("stateless", 1));
    let transaction = modules.transaction();
    assert_eq!(
        rejection(check_submission(&store, &transaction, &modules, V21)),
        TransactionError::InvalidWitnessLength
    );
    assert_eq!(*modules.calls.borrow(), ["stateless0", "stateless1"]);
    empty(&store);
    modules.infrastructure = true;
    assert!(matches!(
        check_submission(&store, &transaction, &modules, V21),
        Err(ExecutionError::Storage(_))
    ));
}
#[test]
fn module_error_keeps_routing_and_all_tentative_namespaces_rollback() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut modules = Modules::new(&[(2, 0)], &[(1, 0), (1, 0)]);
    modules.failure = Some(("output", 1));
    let transaction = modules.transaction();
    let mut tx = store.transaction().unwrap();
    assert_eq!(
        rejection(apply_consensus(&mut tx, &transaction, &modules, V21)),
        TransactionError::Output(DynamicValue {
            module_id: ModuleId(1),
            payload: vec![9, 0]
        })
    );
    drop(tx);
    empty(&store);
    assert_eq!(
        *modules.calls.borrow(),
        ["stateless0", "input0", "output0", "output1"]
    );
    modules.failure = Some(("submit-input", 0));
    assert_eq!(
        rejection(check_submission(&store, &transaction, &modules, V21)),
        TransactionError::Input(DynamicValue {
            module_id: ModuleId(0),
            payload: vec![9, 0]
        })
    );
    empty(&store);
}
#[test]
fn input_overflow_precedes_later_inputs_and_signature_validation() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    for input_meta in [
        vec![(u64::MAX, 0), (1, 0), (0, 0)],
        vec![(0, u64::MAX), (0, 1), (0, 0)],
    ] {
        let modules = Modules::new(&input_meta, &[]);
        let mut transaction = modules.transaction();
        transaction.signatures = TransactionSignatures::Unknown {
            tag: 7,
            payload: vec![],
        };
        assert_eq!(
            rejection(check_submission(&store, &transaction, &modules, V21)),
            TransactionError::UnbalancedTransaction {
                inputs: 0,
                outputs: 0,
                fee: 0
            }
        );
        assert_eq!(
            *modules.calls.borrow(),
            [
                "stateless0",
                "stateless1",
                "stateless2",
                "submit-input0",
                "input0",
                "submit-input1",
                "input1"
            ]
        );
        empty(&store);
    }
}
#[test]
fn signatures_after_inputs_before_outputs_and_duplicate_keys_need_each_witness() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = Modules::new(&[(1, 0), (1, 0)], &[(2, 0)]);
    let mut transaction = modules.transaction();
    if let TransactionSignatures::Schnorr(signatures) = &mut transaction.signatures {
        signatures.pop();
    }
    assert_eq!(
        rejection(check_submission(&store, &transaction, &modules, V21)),
        TransactionError::InvalidWitnessLength
    );
    assert!(!modules.calls.borrow().iter().any(|c| c.contains("output")));
    empty(&store);
    transaction = modules.transaction();
    if let TransactionSignatures::Schnorr(signatures) = &mut transaction.signatures {
        signatures[1] = [0; 64];
    }
    assert!(matches!(
        rejection(check_submission(&store, &transaction, &modules, V21)),
        TransactionError::InvalidSignature { .. }
    ));
    empty(&store);
    transaction.signatures = TransactionSignatures::Unknown {
        tag: 7,
        payload: vec![],
    };
    assert_eq!(
        rejection(check_submission(&store, &transaction, &modules, V21)),
        TransactionError::UnsupportedSignatureScheme(7)
    );
}
#[test]
fn output_overflow_and_final_funding_checks_use_correct_totals() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    for (inputs, outputs) in [
        (vec![], vec![(u64::MAX, 0), (1, 0), (0, 0)]),
        (vec![], vec![(0, u64::MAX), (0, 1), (0, 0)]),
        (vec![], vec![(u64::MAX, 1)]),
    ] {
        let modules = Modules::new(&inputs, &outputs);
        let transaction = modules.transaction();
        assert_eq!(
            rejection(check_submission(&store, &transaction, &modules, V21)),
            TransactionError::UnbalancedTransaction {
                inputs: 0,
                outputs: 0,
                fee: 0
            }
        );
        assert!(!modules.calls.borrow().iter().any(|c| c == "output2"));
        empty(&store);
    }
    let modules = Modules::new(&[(11, 1)], &[(8, 1)]);
    let transaction = modules.transaction();
    assert!(check_submission(&store, &transaction, &modules, V21).is_ok());
    assert_eq!(
        rejection(check_submission(
            &store,
            &transaction,
            &modules,
            Version { major: 2, minor: 0 }
        )),
        TransactionError::UnbalancedTransaction {
            inputs: 11,
            outputs: 8,
            fee: 2
        }
    );
    let modules = Modules::new(&[(9, 1)], &[(8, 1)]);
    assert_eq!(
        rejection(check_submission(
            &store,
            &modules.transaction(),
            &modules,
            V21
        )),
        TransactionError::UnbalancedTransaction {
            inputs: 9,
            outputs: 8,
            fee: 2
        }
    );
    empty(&store);
}
#[test]
fn zero_inputs_require_empty_signatures_and_audit_is_fatal() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = Modules::new(&[], &[]);
    let transaction = modules.transaction();
    let mut tx = store.transaction().unwrap();
    let id = apply_consensus(&mut tx, &transaction, &modules, V21).unwrap();
    let error: ExecutionError = audit::require_nonnegative([-1]).unwrap_err().into();
    assert!(matches!(
        error,
        ExecutionError::FatalAudit(AuditError::Negative {
            net_assets_msat: -1
        })
    ));
    drop(tx);
    empty(&store);
    assert_eq!(
        accepted_output_modules(&store.snapshot().unwrap(), &id).unwrap(),
        None
    );
    assert_eq!(
        audit::require_nonnegative([i64::MAX, 1, -1]),
        Err(AuditError::Overflow)
    );
    assert_eq!(
        audit::require_nonnegative([i64::MIN, -1]),
        Err(AuditError::Overflow)
    );
    assert_eq!(audit::require_nonnegative([-7, 7]), Ok(0));
    let mut transaction = transaction;
    transaction.signatures = TransactionSignatures::Schnorr(vec![[0; 64]]);
    assert_eq!(
        rejection(check_submission(&store, &transaction, &modules, V21)),
        TransactionError::InvalidWitnessLength
    );
}

#[test]
fn independent_id_fixture_and_durable_ordered_output_ids() {
    use minimint_ng::codec::{
        decode_whole,
        text::{hex_decode, hex_encode},
    };
    // Numbered-spec public core vector; not calculated by this implementation.
    let fixture: Transaction =
        decode_whole(&hex_decode("00000000000000000000000100").unwrap()).unwrap();
    assert_eq!(
        hex_encode(&transaction_id(&fixture)),
        "01d448afd928065458cf670b60f5a594d735af0172c8d67f22a81680132681ca"
    );
    let dir = fixture::TestDir::new();
    let modules = Modules::new(&[(2, 0)], &[(1, 0), (1, 0)]);
    let mut transaction = modules.transaction();
    transaction.outputs[0].module_id = ModuleId(42);
    let id = transaction_id(&transaction);
    transaction.signatures =
        TransactionSignatures::Schnorr(vec![modules.key.schnorr_sign(&id).unwrap()]);
    {
        let store = Store::open(dir.path()).unwrap();
        let mut writer = store.transaction().unwrap();
        assert_eq!(
            apply_consensus(&mut writer, &transaction, &modules, V21).unwrap(),
            id
        );
        writer.commit().unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        accepted_output_modules(&store.snapshot().unwrap(), &id).unwrap(),
        Some(vec![ModuleId(42), ModuleId(1)])
    );
}

#[test]
fn fatal_module_invariants_propagate_from_every_transition_stage() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    for stage in [
        "stateless",
        "submit-input",
        "input",
        "submit-output",
        "output",
    ] {
        let mut modules = Modules::new(&[(1, 0)], &[(1, 0)]);
        modules.failure = Some((stage, 0));
        modules.fatal = true;
        let error = check_submission(&store, &modules.transaction(), &modules, V21).unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::FatalInvariant("mint-counter-underflow")
        ));
        assert_eq!(error.to_string(), "fatal module invariant failure");
        empty(&store);
    }
    let mut modules = Modules::new(&[(1, 0)], &[(1, 0)]);
    modules.failure = Some(("output", 0));
    modules.fatal = true;
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        apply_consensus(&mut tx, &modules.transaction(), &modules, V21),
        Err(ExecutionError::FatalInvariant("mint-counter-underflow"))
    ));
    drop(tx);
    empty(&store);
}
