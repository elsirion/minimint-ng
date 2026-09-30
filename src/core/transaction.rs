//! TX-004 ordered execution inside the caller's tentative state update.
//! On any error, discard the caller's entire writer. Success does not commit:
//! the session adds its accepted-item record and performs CON-005 audit first.
use super::audit::AuditError;
use crate::{
    codec::{ConsensusEncode, decode_whole, text::hex_encode},
    crypto::{secp, sha256},
    protocol::{
        DynamicValue, ModuleId, OutPoint, Transaction, TransactionError, TransactionSignatures,
        Version,
    },
    storage::{Namespace, Snapshot, Store, StoreError, WriteTransaction},
};

pub struct InputMeta {
    pub amount_msat: u64,
    pub fee_msat: u64,
    pub public_key: [u8; 33],
}
pub struct OutputMeta {
    pub amount_msat: u64,
    pub fee_msat: u64,
}
#[derive(Debug)]
pub enum TransitionError {
    /// Static invariant identifier only; never include private state values.
    FatalInvariant(&'static str),
    Storage(StoreError),
    Module(Vec<u8>),
}
impl From<StoreError> for TransitionError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}

/// Internal dispatch boundary for the closed Mint/Wallet module dispatcher.
/// Payloads must already have passed the configured module decoding gate.
pub trait ModuleTransitions {
    fn stateless_input(&self, value: &DynamicValue) -> Result<(), TransitionError>;
    fn submission_input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        outpoint: OutPoint,
    ) -> Result<(), TransitionError>;
    fn submission_output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        outpoint: OutPoint,
    ) -> Result<(), TransitionError>;
    fn input(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        outpoint: OutPoint,
    ) -> Result<InputMeta, TransitionError>;
    fn output(
        &self,
        tx: &mut WriteTransaction<'_>,
        value: &DynamicValue,
        outpoint: OutPoint,
    ) -> Result<OutputMeta, TransitionError>;
}
#[derive(Debug)]
pub enum ExecutionError {
    Rejected(TransactionError),
    AlreadyAccepted,
    Storage(StoreError),
    CorruptAcceptedRecord,
    FatalAudit(AuditError),
    FatalInvariant(&'static str),
}
impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected(_) => "transaction rejected",
            Self::AlreadyAccepted => "transaction already accepted",
            Self::Storage(_) => "transaction storage operation failed",
            Self::CorruptAcceptedRecord => "invalid accepted transaction record",
            Self::FatalAudit(_) => "fatal audit invariant failure",
            Self::FatalInvariant(_) => "fatal module invariant failure",
        })
    }
}
impl std::error::Error for ExecutionError {}
impl From<StoreError> for ExecutionError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
impl From<AuditError> for ExecutionError {
    fn from(e: AuditError) -> Self {
        Self::FatalAudit(e)
    }
}

// Private replicated schema: this prefix followed by exactly 32 digest bytes.
// Value: common-encoded ordered Vec<ModuleId>. This includes empty output lists.
const ACCEPTED_PREFIX: &[u8] = b"core/accepted-tx/v1/";
fn accepted_key(id: &[u8; 32]) -> Vec<u8> {
    [ACCEPTED_PREFIX, id].concat()
}
pub fn transaction_id(transaction: &Transaction) -> [u8; 32] {
    sha256(&transaction.commitment_bytes())
}
pub fn accepted_output_modules(
    snapshot: &Snapshot,
    id: &[u8; 32],
) -> Result<Option<Vec<ModuleId>>, ExecutionError> {
    snapshot
        .get(Namespace::Replicated, &accepted_key(id))?
        .map(|bytes| decode_whole(&bytes).map_err(|_| ExecutionError::CorruptAcceptedRecord))
        .transpose()
}
pub fn apply_consensus(
    tx: &mut WriteTransaction<'_>,
    transaction: &Transaction,
    modules: &impl ModuleTransitions,
    version: Version,
) -> Result<[u8; 32], ExecutionError> {
    let id = transaction_id(transaction);
    if tx.get(Namespace::Replicated, &accepted_key(&id))?.is_some() {
        return Err(ExecutionError::AlreadyAccepted);
    }
    execute(tx, transaction, modules, version, id, false)?;
    let output_ids: Vec<_> = transaction.outputs.iter().map(|v| v.module_id).collect();
    tx.put(
        Namespace::Replicated,
        &accepted_key(&id),
        &output_ids.consensus_encode(),
    )?;
    Ok(id)
}
/// Idempotent API check. Every tentative module write is dropped on all paths.
pub fn check_submission(
    store: &Store,
    transaction: &Transaction,
    modules: &impl ModuleTransitions,
    version: Version,
) -> Result<[u8; 32], ExecutionError> {
    let id = transaction_id(transaction);
    if store
        .snapshot()?
        .get(Namespace::Replicated, &accepted_key(&id))?
        .is_some()
    {
        return Ok(id);
    }
    let mut tx = store.transaction()?;
    // Consensus could have accepted it between the snapshot and writer lock.
    if tx.get(Namespace::Replicated, &accepted_key(&id))?.is_some() {
        return Ok(id);
    }
    execute(&mut tx, transaction, modules, version, id, true)?;
    Ok(id)
}
fn overflow() -> ExecutionError {
    ExecutionError::Rejected(TransactionError::UnbalancedTransaction {
        inputs: 0,
        outputs: 0,
        fee: 0,
    })
}
fn module_error(error: TransitionError, value: &DynamicValue, input: bool) -> ExecutionError {
    match error {
        TransitionError::FatalInvariant(name) => ExecutionError::FatalInvariant(name),
        TransitionError::Storage(error) => ExecutionError::Storage(error),
        TransitionError::Module(payload) => {
            let routed = DynamicValue {
                module_id: value.module_id,
                payload,
            };
            ExecutionError::Rejected(if input {
                TransactionError::Input(routed)
            } else {
                TransactionError::Output(routed)
            })
        }
    }
}
fn execute(
    tx: &mut WriteTransaction<'_>,
    transaction: &Transaction,
    modules: &impl ModuleTransitions,
    version: Version,
    id: [u8; 32],
    submission: bool,
) -> Result<(), ExecutionError> {
    for input in &transaction.inputs {
        modules
            .stateless_input(input)
            .map_err(|error| match error {
                TransitionError::FatalInvariant(name) => ExecutionError::FatalInvariant(name),
                TransitionError::Storage(error) => ExecutionError::Storage(error),
                TransitionError::Module(_) => {
                    ExecutionError::Rejected(TransactionError::InvalidWitnessLength)
                }
            })?;
    }
    let (mut inputs, mut outputs, mut fees) = (0_u64, 0_u64, 0_u64);
    let mut keys = Vec::new();
    for (index, input) in transaction.inputs.iter().enumerate() {
        let outpoint = OutPoint {
            txid: id,
            out_idx: index as u64,
        };
        if submission {
            modules
                .submission_input(tx, input, outpoint)
                .map_err(|e| module_error(e, input, true))?;
        }
        let meta = modules
            .input(tx, input, outpoint)
            .map_err(|e| module_error(e, input, true))?;
        inputs = inputs.checked_add(meta.amount_msat).ok_or_else(overflow)?;
        fees = fees.checked_add(meta.fee_msat).ok_or_else(overflow)?;
        keys.push(meta.public_key);
    }
    let signatures = match &transaction.signatures {
        TransactionSignatures::Schnorr(signatures) => signatures,
        TransactionSignatures::Unknown { tag, .. } => {
            return Err(ExecutionError::Rejected(
                TransactionError::UnsupportedSignatureScheme(*tag),
            ));
        }
    };
    if signatures.len() != keys.len() {
        return Err(ExecutionError::Rejected(
            TransactionError::InvalidWitnessLength,
        ));
    }
    for (public_key, signature) in keys.iter().zip(signatures) {
        if secp::x_only(public_key)
            .and_then(|key| secp::schnorr_verify(&key, &id, signature))
            .is_err()
        {
            return Err(ExecutionError::Rejected(
                TransactionError::InvalidSignature {
                    transaction: hex_encode(&transaction.consensus_encode()),
                    hash: hex_encode(&id),
                    signature: hex_encode(signature),
                    public_key: hex_encode(public_key),
                },
            ));
        }
    }
    for (index, output) in transaction.outputs.iter().enumerate() {
        let outpoint = OutPoint {
            txid: id,
            out_idx: index as u64,
        };
        if submission {
            modules
                .submission_output(tx, output, outpoint)
                .map_err(|e| module_error(e, output, false))?;
        }
        let meta = modules
            .output(tx, output, outpoint)
            .map_err(|e| module_error(e, output, false))?;
        outputs = outputs.checked_add(meta.amount_msat).ok_or_else(overflow)?;
        fees = fees.checked_add(meta.fee_msat).ok_or_else(overflow)?;
    }
    let required = outputs.checked_add(fees).ok_or_else(overflow)?;
    let funded = if version >= (Version { major: 2, minor: 1 }) {
        inputs >= required
    } else {
        inputs == required
    };
    if !funded {
        return Err(ExecutionError::Rejected(
            TransactionError::UnbalancedTransaction {
                inputs,
                outputs,
                fee: fees,
            },
        ));
    }
    Ok(())
}
