//! Native module API values. Authentication and JSON-RPC envelopes belong to the
//! server; handlers read only the caller's committed snapshot.
use crate::{
    bitcoin,
    codec::text::{hex_decode, hex_encode},
    json,
    modules::{
        Modules,
        mint::{self, G1Bytes, RecoveryItem},
        wallet::{self, ChainRecord},
    },
    protocol::OutPoint,
    storage::Snapshot,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleApiError {
    MethodNotFound,
    InvalidParams,
    MissingBlindedShare,
    StateUnavailable,
    FatalInvariant,
}
impl ModuleApiError {
    pub fn code(self) -> i32 {
        match self {
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::MissingBlindedShare => 400,
            Self::StateUnavailable | Self::FatalInvariant => -32603,
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::MissingBlindedShare => "No blinded signature share found",
            Self::StateUnavailable => "Module state unavailable",
            Self::FatalInvariant => "Module invariant failure",
        }
    }
}
impl std::fmt::Display for ModuleApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for ModuleApiError {}
impl From<mint::ReadError> for ModuleApiError {
    fn from(error: mint::ReadError) -> Self {
        match error {
            mint::ReadError::InvalidRange => Self::InvalidParams,
            mint::ReadError::MissingShare => Self::MissingBlindedShare,
            mint::ReadError::Storage(_) => Self::StateUnavailable,
            mint::ReadError::CorruptState => Self::FatalInvariant,
        }
    }
}
impl From<wallet::WalletError> for ModuleApiError {
    fn from(error: wallet::WalletError) -> Self {
        match error {
            wallet::WalletError::Invariant(_)
            | wallet::WalletError::UnsupportedArithmeticDomain => Self::FatalInvariant,
            _ => Self::StateUnavailable,
        }
    }
}
fn uint(value: &Value) -> Result<u64, ModuleApiError> {
    json::unsigned(value).map_err(|_| ModuleApiError::InvalidParams)
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, ModuleApiError> {
    value
        .as_object()
        .and_then(|object| object.get(&name))
        .ok_or(ModuleApiError::InvalidParams)
}
fn bytes<const N: usize>(value: &Value) -> Result<[u8; N], ModuleApiError> {
    let text = value.as_str().ok_or(ModuleApiError::InvalidParams)?;
    hex_decode(text)
        .map_err(|_| ModuleApiError::InvalidParams)?
        .try_into()
        .map_err(|_| ModuleApiError::InvalidParams)
}
fn null(value: &Value) -> Result<(), ModuleApiError> {
    if value.is_null() {
        Ok(())
    } else {
        Err(ModuleApiError::InvalidParams)
    }
}
fn range(start: &Value, end: &Value) -> Result<Range<u64>, ModuleApiError> {
    let (start, end) = (uint(start)?, uint(end)?);
    if end < start {
        Err(ModuleApiError::InvalidParams)
    } else {
        Ok(start..end)
    }
}
fn pair_range(value: &Value) -> Result<Range<u64>, ModuleApiError> {
    let values = value.as_array().ok_or(ModuleApiError::InvalidParams)?;
    if values.len() != 2 {
        return Err(ModuleApiError::InvalidParams);
    }
    range(&values[0], &values[1])
}
fn bitcoin_outpoint(point: bitcoin::OutPoint) -> Value {
    // Native Bitcoin outpoints follow the observed reference daemon format.
    // Fedimint output locations retain their distinct {txid, out_idx} schema.
    json!(format!("{}:{}", point.txid.display_hex(), point.vout))
}
fn chain(record: &ChainRecord) -> Value {
    json!({"index": record.index, "txid": record.txid.display_hex(), "input": record.input_sat,
        "output": record.output_sat, "fee": record.fee_sat, "vbytes": record.vbytes, "created": record.created})
}
fn recovery(item: RecoveryItem) -> Value {
    match item {
        RecoveryItem::Output {
            denomination,
            nonce_hash,
            tweak,
        } => json!({"Output": {
            "denomination": denomination, "nonce_hash": hex_encode(&nonce_hash), "tweak": tweak}}),
        RecoveryItem::Input { nonce_hash } => {
            json!({"Input": {"nonce_hash": hex_encode(&nonce_hash)}})
        }
    }
}

pub fn dispatch(
    modules: &Modules,
    snapshot: &Snapshot,
    method: &str,
    params: &Value,
) -> Result<Value, ModuleApiError> {
    let mint_prefix = format!("module_{}_", modules.mint().instance().0);
    if let Some(method) = method.strip_prefix(&mint_prefix) {
        let mint = modules.mint();
        return match method {
            "signature_shares" => {
                let txid = bytes(field(params, "txid")?)?;
                let indices = field(params, "idx_range")?;
                let range = range(field(indices, "start")?, field(indices, "end")?)?;
                let shares: Vec<_> = mint
                    .signature_shares(snapshot, txid, range)?
                    .into_iter()
                    .map(|v| hex_encode(&v.to_bytes()))
                    .collect();
                Ok(json!(shares))
            }
            "recovery_signature_shares" => {
                let messages = params
                    .as_array()
                    .ok_or(ModuleApiError::InvalidParams)?
                    .iter()
                    .map(|v| {
                        G1Bytes::from_bytes(bytes(v)?).map_err(|_| ModuleApiError::InvalidParams)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let shares: Vec<_> = mint
                    .recovery_signature_shares(snapshot, &messages)?
                    .into_iter()
                    .map(|v| hex_encode(&v.to_bytes()))
                    .collect();
                Ok(json!(shares))
            }
            "recovery_count" => {
                null(params)?;
                Ok(json!(mint.recovery_count(snapshot)?))
            }
            "recovery_slice" => {
                let items: Vec<_> = mint
                    .recovery_slice(snapshot, pair_range(params)?)?
                    .into_iter()
                    .map(recovery)
                    .collect();
                Ok(json!(items))
            }
            "recovery_slice_hash" => Ok(json!(hex_encode(
                &mint.recovery_slice_hash(snapshot, pair_range(params)?)?
            ))),
            _ => Err(ModuleApiError::MethodNotFound),
        };
    }
    let wallet_prefix = format!("module_{}_", modules.wallet().module_id().0);
    let method = method
        .strip_prefix(&wallet_prefix)
        .ok_or(ModuleApiError::MethodNotFound)?;
    let wallet = modules.wallet();
    // Quotes are independent of ordinary state reads, including at pending=33.
    match method {
        "receive_fee" => {
            null(params)?;
            return Ok(json!(wallet.receive_fee(snapshot)?));
        }
        "send_fee" => {
            null(params)?;
            return Ok(json!(wallet.send_fee(snapshot)?));
        }
        "transaction_id" | "output_info_slice" => {}
        "consensus_block_count"
        | "consensus_feerate"
        | "federation_wallet"
        | "pending_transaction_chain"
        | "transaction_chain" => null(params)?,
        _ => return Err(ModuleApiError::MethodNotFound),
    }
    let view = wallet.snapshot(snapshot)?;
    match method {
        "consensus_block_count" => Ok(json!(view.block_count)),
        "consensus_feerate" => Ok(json!(view.consensus_fee_rate)),
        "federation_wallet" => Ok(match view.wallet {
            Some(wallet) => {
                json!({"value": wallet.value_sat, "outpoint": bitcoin_outpoint(wallet.outpoint), "tweak": hex_encode(&wallet.tweak)})
            }
            None => json!(null),
        }),
        "transaction_id" => {
            let point = OutPoint {
                txid: bytes(field(params, "txid")?)?,
                out_idx: uint(field(params, "out_idx")?)?,
            };
            Ok(json!(
                view.transaction_id(point).map(|txid| txid.display_hex())
            ))
        }
        "output_info_slice" => {
            let range = pair_range(params)?;
            let items: Vec<_> = view.output_info_slice(range.start, range.end).into_iter().map(|item| json!({
                "index": item.index, "script": hex_encode(&item.script), "value": item.value_sat,
                "spent": item.spent, "outpoint": item.outpoint.map(bitcoin_outpoint)
            })).collect();
            Ok(json!(items))
        }
        "transaction_chain" => Ok(json!(view.chain.iter().map(chain).collect::<Vec<_>>())),
        "pending_transaction_chain" => Ok(json!(
            view.pending_chain.iter().map(chain).collect::<Vec<_>>()
        )),
        _ => Err(ModuleApiError::MethodNotFound),
    }
}
