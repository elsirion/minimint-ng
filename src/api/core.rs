//! Polling core acceptance/history handlers. The daemon owns waiting and routes
//! proposals to the active session. Register wakeups before polling, and wake on
//! every accepted-item commit, completion, session switch, or queue availability.
use super::rpc::RpcError;
use crate::{
    codec::{
        rpc,
        text::{hex_decode, hex_encode},
    },
    core::{
        session,
        transaction::{self, ExecutionError},
    },
    json,
    modules::Modules,
    protocol::{ConsensusItem, OutPoint, SessionStatusV2, Transaction, TransactionError, Version},
    storage::{Snapshot, Store, StoreError},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json as value};
use std::ops::Range;
/// The daemon handles Fatal/Storage before serializing their sanitized RPC error.
#[derive(Debug)]
pub enum CoreFailure {
    Rpc(RpcError),
    Fatal(&'static str),
    Storage(StoreError),
}
impl CoreFailure {
    pub fn rpc_error(&self) -> RpcError {
        match self {
            Self::Rpc(error) => *error,
            Self::Fatal(_) | Self::Storage(_) => RpcError::INTERNAL,
        }
    }
}
impl std::fmt::Display for CoreFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.rpc_error().message)
    }
}
impl std::error::Error for CoreFailure {}
impl From<RpcError> for CoreFailure {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}
impl From<StoreError> for CoreFailure {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}
impl From<ExecutionError> for CoreFailure {
    fn from(error: ExecutionError) -> Self {
        match error {
            ExecutionError::Storage(error) => Self::Storage(error),
            ExecutionError::FatalInvariant(name) => Self::Fatal(name),
            ExecutionError::FatalAudit(_) => Self::Fatal("transaction-audit"),
            ExecutionError::CorruptAcceptedRecord => Self::Fatal("corrupt-accepted-record"),
            ExecutionError::Rejected(_) | ExecutionError::AlreadyAccepted => {
                Self::Fatal("unexpected-transaction-result")
            }
        }
    }
}
impl From<session::SessionError> for CoreFailure {
    fn from(error: session::SessionError) -> Self {
        match error {
            session::SessionError::Storage(error) => Self::Storage(error),
            session::SessionError::Fatal(name) => Self::Fatal(name),
            session::SessionError::Rejected | session::SessionError::Retry => {
                Self::Fatal("unexpected-session-read-result")
            }
        }
    }
}
const BAD_REQUEST: RpcError = RpcError {
    code: 400,
    message: "Invalid core request",
};
const MISSING_OUTPUT: RpcError = RpcError {
    code: 400,
    message: "Output outcome unavailable",
};
const STATUS_POLICY: RpcError = RpcError {
    code: 500,
    message: "Session status policy unavailable",
};
fn uint(value: &Value) -> Result<u64, RpcError> {
    json::unsigned(value).map_err(|_| BAD_REQUEST)
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, RpcError> {
    value
        .as_object()
        .and_then(|o| o.get(&name))
        .ok_or(BAD_REQUEST)
}
fn hash(value: &Value) -> Result<[u8; 32], RpcError> {
    let text = value.as_str().ok_or(BAD_REQUEST)?;
    if text.len() != 64 {
        return Err(BAD_REQUEST);
    }
    hex_decode(text)
        .map_err(|_| BAD_REQUEST)?
        .try_into()
        .map_err(|_| BAD_REQUEST)
}
fn outpoint(value: &Value) -> Result<OutPoint, RpcError> {
    Ok(OutPoint {
        txid: hash(field(value, "txid")?)?,
        out_idx: uint(field(value, "out_idx")?)?,
    })
}
/// No Debug: submission values can contain private transaction witnesses.
pub enum CoreRequest {
    Submit(Transaction),
    AwaitTransaction([u8; 32]),
    AwaitOutput(OutPoint),
    AwaitOutputs { txid: [u8; 32], range: Range<u64> },
    SessionCount,
    AwaitSession { index: u64, signed: bool },
    SessionStatus { index: u64, signed: bool },
}
impl CoreRequest {
    pub fn decode(method: &str, params: &Value, modules: &Modules) -> Result<Self, RpcError> {
        match method {
            "submit_transaction" => {
                let array = params
                    .as_array()
                    .filter(|a| a.len() == 1)
                    .ok_or(BAD_REQUEST)?;
                let text = array[0].as_str().ok_or(BAD_REQUEST)?.to_owned();
                let tx: Transaction = rpc::decode_hex(&[text]).map_err(|_| BAD_REQUEST)?;
                tx.validate_modules(modules).map_err(|_| BAD_REQUEST)?;
                Ok(Self::Submit(tx))
            }
            "await_transaction" => Ok(Self::AwaitTransaction(hash(params)?)),
            "await_output_outcome" => Ok(Self::AwaitOutput(outpoint(params)?)),
            "await_outputs_outcomes" => {
                let txid = hash(field(params, "txid")?)?;
                let bounds = field(params, "idx_range")?;
                let start = uint(field(bounds, "start")?)?;
                let end = uint(field(bounds, "end")?)?;
                if end < start || end - start > 1024 {
                    return Err(BAD_REQUEST);
                }
                Ok(Self::AwaitOutputs {
                    txid,
                    range: start..end,
                })
            }
            "session_count" => {
                if !params.is_null() {
                    return Err(BAD_REQUEST);
                }
                Ok(Self::SessionCount)
            }
            "await_session_outcome" | "await_signed_session_outcome" => Ok(Self::AwaitSession {
                index: uint(params)?,
                signed: method == "await_signed_session_outcome",
            }),
            "session_status" | "signed_session_status" => Ok(Self::SessionStatus {
                index: uint(params)?,
                signed: method == "signed_session_status",
            }),
            _ => Err(RpcError::METHOD),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusRevision {
    pub session: u64,
    pub accepted_items: u64,
}
impl ConsensusRevision {
    pub fn read(snapshot: &Snapshot) -> Result<Self, CoreFailure> {
        let session = session::session_count(snapshot)?;
        let accepted_items = match session::persisted_status(snapshot, session)? {
            Some(SessionStatusV2::Pending(items)) => items.len() as u64,
            None => 0,
            Some(_) => return Err(CoreFailure::Fatal("invalid-consensus-revision")),
        };
        Ok(Self {
            session,
            accepted_items,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalUnavailable {
    Full,
    SignaturePhase,
    Closed,
}
pub enum CorePoll {
    Ready(Value),
    Pending,
}
pub struct CoreOperation {
    request: CoreRequest,
    checked: Option<ConsensusRevision>,
    proposed_session: Option<u64>,
    result: Option<Value>,
}
impl CoreOperation {
    pub fn new(request: CoreRequest) -> Self {
        Self {
            request,
            checked: None,
            proposed_session: None,
            result: None,
        }
    }
    /// Return Pending until durable acceptance/completion. Queueing is never a
    /// successful submission result. A full queue is retried even without a new
    /// consensus revision; signature-phase requests retry on session-switch wakeup.
    pub fn poll(
        &mut self,
        store: &Store,
        modules: &Modules,
        version: Version,
        propose: &mut impl FnMut(ConsensusItem) -> Result<(), ProposalUnavailable>,
    ) -> Result<CorePoll, CoreFailure> {
        if let Some(result) = &self.result {
            return Ok(CorePoll::Ready(result.clone()));
        }
        let snapshot = store.snapshot()?;
        let result = match &self.request {
            CoreRequest::Submit(tx) => {
                let id = transaction::transaction_id(tx);
                if accepted(&snapshot, &id)?.is_some() {
                    Some(submission(Ok(id)))
                } else {
                    let revision = ConsensusRevision::read(&snapshot)?;
                    if self.checked != Some(revision) {
                        tx.validate_modules(modules).map_err(|_| BAD_REQUEST)?;
                        match transaction::check_submission(store, tx, modules, version) {
                            Ok(_) => self.checked = Some(revision),
                            Err(ExecutionError::Rejected(error)) => {
                                let result = submission(Err(error));
                                self.result = Some(result.clone());
                                return Ok(CorePoll::Ready(result));
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    if self.proposed_session != Some(revision.session) {
                        match propose(ConsensusItem::Transaction(tx.clone())) {
                            Ok(()) => self.proposed_session = Some(revision.session),
                            Err(
                                ProposalUnavailable::Full | ProposalUnavailable::SignaturePhase,
                            ) => {}
                            Err(ProposalUnavailable::Closed) => {
                                return Err(CoreFailure::Rpc(RpcError::INTERNAL));
                            }
                        }
                    }
                    None
                }
            }
            CoreRequest::AwaitTransaction(id) => {
                accepted(&snapshot, id)?.map(|_| value!(hex_encode(id)))
            }
            CoreRequest::AwaitOutput(point) => {
                if let Some(ids) = accepted(&snapshot, &point.txid)? {
                    let index = usize::try_from(point.out_idx).map_err(|_| MISSING_OUTPUT)?;
                    let id = ids.get(index).ok_or(MISSING_OUTPUT)?;
                    validate_output_module(modules, *id)?;
                    // MINT-013 and WAL-009: both built-in generic outcomes absent.
                    return Err(MISSING_OUTPUT.into());
                }
                None
            }
            CoreRequest::AwaitOutputs { txid, range } => {
                // CoreRequest can also be constructed directly by a typed caller.
                if range.end < range.start || range.end - range.start > 1024 {
                    return Err(BAD_REQUEST.into());
                }
                if let Some(ids) = accepted(&snapshot, txid)? {
                    if !range.is_empty() && range.end > ids.len() as u64 {
                        return Err(MISSING_OUTPUT.into());
                    }
                    if !range.is_empty() {
                        for id in &ids[range.start as usize..range.end as usize] {
                            validate_output_module(modules, *id)?;
                        }
                    }
                    Some(value!(vec![
                        Option::<Value>::None;
                        (range.end - range.start) as usize
                    ]))
                } else {
                    None
                }
            }
            CoreRequest::SessionCount => Some(value!(session::session_count(&snapshot)?)),
            CoreRequest::AwaitSession { index, signed } => session::completed(&snapshot, *index)?
                .map(|outcome| {
                    if *signed {
                        value!(rpc::hex(&outcome))
                    } else {
                        value!(rpc::hex(&outcome.outcome))
                    }
                }),
            CoreRequest::SessionStatus { index, signed } => {
                let status = session::persisted_status(&snapshot, *index)?.ok_or(STATUS_POLICY)?;
                Some(if *signed {
                    value!(rpc::base64(&status))
                } else {
                    value!(rpc::hex(&crate::protocol::SessionStatus::from(status)))
                })
            }
        };
        if let Some(result) = result {
            self.result = Some(result.clone());
            Ok(CorePoll::Ready(result))
        } else {
            Ok(CorePoll::Pending)
        }
    }
}
fn accepted(
    snapshot: &Snapshot,
    id: &[u8; 32],
) -> Result<Option<Vec<crate::protocol::ModuleId>>, CoreFailure> {
    transaction::accepted_output_modules(snapshot, id).map_err(CoreFailure::from)
}
fn validate_output_module(
    modules: &Modules,
    id: crate::protocol::ModuleId,
) -> Result<(), CoreFailure> {
    if id == modules.mint().instance() || id == modules.wallet().module_id() {
        Ok(())
    } else {
        Err(CoreFailure::Fatal("unknown-accepted-output-module"))
    }
}
fn submission(result: Result<[u8; 32], TransactionError>) -> Value {
    value!(rpc::hex(&result))
}
