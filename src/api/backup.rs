//! REC-007/008 guardian storage of signed opaque client backups. This module
//! neither derives client keys nor interprets or decrypts payload bytes.
use crate::{
    codec::{
        ConsensusDecode, ConsensusEncode, DecodeError, Reader, decode_whole,
        text::{hex_decode, hex_encode},
    },
    crypto::{secp, sha256},
    json,
    storage::{Namespace, Snapshot, Store, StoreError},
};
use sonic_rs::{JsonValueTrait, Value, json};
pub const MAX_PAYLOAD_BYTES: usize = 131_072;
const PREFIX: &[u8] = b"backup/v1/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupTimestamp {
    pub secs_since_epoch: u64,
    pub nanos_since_epoch: u32,
}
impl BackupTimestamp {
    /// No OS timestamp conversion. Producers use normalized nanoseconds.
    /// For nonnormalized pairs, comparison by represented time is our explicit
    /// interpretation; upstream parse-normalization behavior remains unverified.
    fn total_nanos(self) -> u128 {
        u128::from(self.secs_since_epoch) * 1_000_000_000 + u128::from(self.nanos_since_epoch)
    }
    pub fn json(self) -> Value {
        json!({"secs_since_epoch":self.secs_since_epoch,"nanos_since_epoch":self.nanos_since_epoch})
    }
    fn from_json(value: &Value) -> Result<Self, BackupError> {
        Ok(Self {
            secs_since_epoch: json::unsigned(field(value, "secs_since_epoch")?)
                .map_err(|_| BackupError::InvalidParams)?,
            nanos_since_epoch: json::unsigned(field(value, "nanos_since_epoch")?)
                .map_err(|_| BackupError::InvalidParams)?
                .try_into()
                .map_err(|_| BackupError::InvalidParams)?,
        })
    }
}
impl ConsensusEncode for BackupTimestamp {
    fn consensus_encode(&self) -> Vec<u8> {
        [
            self.secs_since_epoch.consensus_encode(),
            self.nanos_since_epoch.consensus_encode(),
        ]
        .concat()
    }
}
impl ConsensusDecode for BackupTimestamp {
    fn consensus_decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            secs_since_epoch: u64::consensus_decode(reader)?,
            nanos_since_epoch: u32::consensus_decode(reader)?,
        })
    }
}
// Opaque backup payloads are intentionally absent from derived diagnostics.
pub struct SignedBackup {
    pub id: [u8; 33],
    pub payload: Vec<u8>,
    pub timestamp: BackupTimestamp,
    pub signature: [u8; 64],
}
impl SignedBackup {
    pub fn commitment_bytes(&self) -> Vec<u8> {
        [
            self.id.to_vec(),
            self.payload.consensus_encode(),
            self.timestamp.consensus_encode(),
        ]
        .concat()
    }
    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.commitment_bytes())
    }
    pub fn verify(&self) -> Result<(), BackupError> {
        let public = secp::x_only(&self.id).map_err(|_| BackupError::InvalidIdentity)?;
        secp::schnorr_verify(&public, &self.digest(), &self.signature)
            .map_err(|_| BackupError::InvalidSignature)
    }
    pub fn from_json(value: &Value) -> Result<Self, BackupError> {
        let id = fixed(field(value, "id")?)?;
        secp::validate_public_key(&id).map_err(|_| BackupError::InvalidIdentity)?;
        let payload_text = field(value, "payload")?
            .as_str()
            .ok_or(BackupError::InvalidParams)?;
        if payload_text.len() > MAX_PAYLOAD_BYTES * 2 {
            return Err(BackupError::PayloadTooLarge);
        }
        let payload = hex_decode(payload_text).map_err(|_| BackupError::InvalidParams)?;
        Ok(Self {
            id,
            payload,
            timestamp: BackupTimestamp::from_json(field(value, "timestamp")?)?,
            signature: fixed(field(value, "signature")?)?,
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct BackupSnapshot {
    pub timestamp: BackupTimestamp,
    pub data: Vec<u8>,
}
impl BackupSnapshot {
    pub fn json(&self) -> Value {
        json!({"timestamp":self.timestamp.json(),"data":hex_encode(&self.data)})
    }
}
impl ConsensusEncode for BackupSnapshot {
    fn consensus_encode(&self) -> Vec<u8> {
        [
            self.timestamp.consensus_encode(),
            self.data.consensus_encode(),
        ]
        .concat()
    }
}
impl ConsensusDecode for BackupSnapshot {
    fn consensus_decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            timestamp: BackupTimestamp::consensus_decode(reader)?,
            data: Vec::consensus_decode(reader)?,
        })
    }
}
#[derive(Debug)]
pub enum BackupError {
    MethodNotFound,
    InvalidParams,
    InvalidIdentity,
    InvalidSignature,
    PayloadTooLarge,
    TimestampNotIncreasing,
    CorruptState,
    Storage(StoreError),
}
impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MethodNotFound => "Backup method not found",
            Self::InvalidParams => "Invalid backup parameters",
            Self::InvalidIdentity => "Invalid backup identity",
            Self::InvalidSignature => "Invalid backup signature",
            Self::PayloadTooLarge => "Backup payload too large",
            Self::TimestampNotIncreasing => "Backup timestamp must increase",
            Self::CorruptState => "Invalid stored backup",
            Self::Storage(_) => "Backup storage failed",
        })
    }
}
impl std::error::Error for BackupError {}
impl From<StoreError> for BackupError {
    fn from(error: StoreError) -> Self {
        Self::Storage(error)
    }
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, BackupError> {
    if !value.is_object() {
        return Err(BackupError::InvalidParams);
    }
    value.get(name).ok_or(BackupError::InvalidParams)
}
fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], BackupError> {
    let text = value.as_str().ok_or(BackupError::InvalidParams)?;
    if text.len() != N * 2 {
        return Err(BackupError::InvalidParams);
    }
    hex_decode(text)
        .map_err(|_| BackupError::InvalidParams)?
        .try_into()
        .map_err(|_| BackupError::InvalidParams)
}
fn key(id: &[u8; 33]) -> Vec<u8> {
    [PREFIX, id].concat()
}
fn stored(bytes: &[u8]) -> Result<BackupSnapshot, BackupError> {
    let snapshot: BackupSnapshot = decode_whole(bytes).map_err(|_| BackupError::CorruptState)?;
    if snapshot.data.len() > MAX_PAYLOAD_BYTES {
        return Err(BackupError::CorruptState);
    }
    Ok(snapshot)
}
/// Signature and size checks precede locking. The timestamp comparison and
/// replacement share the same synced writer, including concurrent uploads.
pub fn upload(store: &Store, request: &SignedBackup) -> Result<(), BackupError> {
    if request.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(BackupError::PayloadTooLarge);
    }
    request.verify()?;
    let key = key(&request.id);
    let mut writer = store.transaction()?;
    if let Some(previous) = writer.get(Namespace::ClientBackup, &key)?
        && request.timestamp.total_nanos() <= stored(&previous)?.timestamp.total_nanos()
    {
        return Err(BackupError::TimestampNotIncreasing);
    }
    let snapshot = BackupSnapshot {
        timestamp: request.timestamp,
        data: request.payload.clone(),
    };
    writer.put(Namespace::ClientBackup, &key, &snapshot.consensus_encode())?;
    writer.commit()?;
    Ok(())
}
pub fn recover(snapshot: &Snapshot, id: &[u8; 33]) -> Result<Option<BackupSnapshot>, BackupError> {
    secp::validate_public_key(id).map_err(|_| BackupError::InvalidIdentity)?;
    snapshot
        .get(Namespace::ClientBackup, &key(id))?
        .map(|bytes| stored(&bytes))
        .transpose()
}
/// Native REC JSON inside the outer JSON-RPC `params` value; no RPC_HEX wrapper.
/// Transport access authorization remains the enclosing server's responsibility.
pub fn dispatch(store: &Store, method: &str, params: &Value) -> Result<Value, BackupError> {
    match method {
        "backup" => {
            upload(store, &SignedBackup::from_json(params)?)?;
            Ok(json!(null))
        }
        "recover" => Ok(recover(&store.snapshot()?, &fixed(params)?)?
            .map(|snapshot| snapshot.json())
            .unwrap_or_else(|| json!(null))),
        _ => Err(BackupError::MethodNotFound),
    }
}
