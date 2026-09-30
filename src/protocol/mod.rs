//! Raw wire records. Successful decoding does not imply authorization.
use crate::codec::{ConsensusDecode, ConsensusEncode, DecodeError, Reader, encode_enum};

macro_rules! id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u16);
        impl ConsensusEncode for $name {
            fn consensus_encode(&self) -> Vec<u8> {
                self.0.consensus_encode()
            }
        }
        impl ConsensusDecode for $name {
            fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                Ok(Self(r.u16()?))
            }
        }
    };
}
id!(PeerId);
id!(ModuleId);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub out_idx: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicValue {
    pub module_id: ModuleId,
    pub payload: Vec<u8>,
}
macro_rules! record {
    ($name:ident, $($field:ident),+) => {
        impl ConsensusEncode for $name { fn consensus_encode(&self)->Vec<u8> { let mut out=Vec::new(); $(out.extend(self.$field.consensus_encode());)+ out } }
        impl ConsensusDecode for $name { fn consensus_decode(r:&mut Reader<'_>)->Result<Self,DecodeError> { Ok(Self { $($field: ConsensusDecode::consensus_decode(r)?),+ }) } }
    }
}
record!(Version, major, minor);
record!(OutPoint, txid, out_idx);
record!(DynamicValue, module_id, payload);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleValueKind {
    Input,
    Output,
    ConsensusItem,
    InputError,
    OutputError,
    Outcome,
}
/// Configured dispatch supplies the exact schema, including nested known variants.
/// Returning success must mean schema validity; framing consumption is enforced here.
pub trait ModuleRegistry {
    fn decode_payload(
        &self,
        id: ModuleId,
        kind: ModuleValueKind,
        reader: &mut Reader<'_>,
    ) -> Result<(), DecodeError>;
}
impl DynamicValue {
    pub fn validate(
        &self,
        registry: &impl ModuleRegistry,
        kind: ModuleValueKind,
    ) -> Result<(), DecodeError> {
        let mut reader = Reader::new(&self.payload);
        registry.decode_payload(self.module_id, kind, &mut reader)?;
        reader.finish()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionSignatures {
    Schnorr(Vec<[u8; 64]>),
    Unknown { tag: u64, payload: Vec<u8> },
}
impl ConsensusEncode for TransactionSignatures {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::Schnorr(v) => encode_enum(0, &v.consensus_encode()),
            Self::Unknown { tag, payload } => encode_enum(*tag, payload),
        }
    }
}
impl ConsensusDecode for TransactionSignatures {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut body) = r.variant()?;
        let value = if tag == 0 {
            Self::Schnorr(Vec::consensus_decode(&mut body)?)
        } else {
            Self::Unknown {
                tag,
                payload: body.take(body.remaining())?.to_vec(),
            }
        };
        body.finish()?;
        Ok(value)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<DynamicValue>,
    pub outputs: Vec<DynamicValue>,
    pub nonce: [u8; 8],
    pub signatures: TransactionSignatures,
}
record!(Transaction, inputs, outputs, nonce, signatures);
impl Transaction {
    pub fn commitment_bytes(&self) -> Vec<u8> {
        [
            self.inputs.consensus_encode(),
            self.outputs.consensus_encode(),
            self.nonce.to_vec(),
        ]
        .concat()
    }
    /// Strict schema decoding for execution. Authorization still checks signatures.
    pub fn decode_for_execution(
        r: &mut Reader<'_>,
        registry: &impl ModuleRegistry,
    ) -> Result<Self, DecodeError> {
        let tx = Self::consensus_decode(r)?;
        tx.validate_modules(registry)?;
        Ok(tx)
    }
    pub fn validate_modules(&self, registry: &impl ModuleRegistry) -> Result<(), DecodeError> {
        for input in &self.inputs {
            input.validate(registry, ModuleValueKind::Input)?;
        }
        for output in &self.outputs {
            output.validate(registry, ModuleValueKind::Output)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusItem {
    Transaction(Transaction),
    Module(DynamicValue),
    Unknown { tag: u64, payload: Vec<u8> },
}
impl ConsensusEncode for ConsensusItem {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::Transaction(v) => encode_enum(0, &v.consensus_encode()),
            Self::Module(v) => encode_enum(1, &v.consensus_encode()),
            Self::Unknown { tag, payload } => encode_enum(*tag, payload),
        }
    }
}
impl ConsensusDecode for ConsensusItem {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut body) = r.variant()?;
        let value = match tag {
            0 => Self::Transaction(Transaction::consensus_decode(&mut body)?),
            1 => Self::Module(DynamicValue::consensus_decode(&mut body)?),
            _ => Self::Unknown {
                tag,
                payload: body.take(body.remaining())?.to_vec(),
            },
        };
        body.finish()?;
        Ok(value)
    }
}
impl ConsensusItem {
    /// Unknown consensus variants remain inspectable; executor must reject them.
    pub fn validate_modules(&self, registry: &impl ModuleRegistry) -> Result<(), DecodeError> {
        match self {
            Self::Transaction(tx) => tx.validate_modules(registry),
            Self::Module(v) => v.validate(registry, ModuleValueKind::ConsensusItem),
            Self::Unknown { .. } => Ok(()),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedItem {
    pub item: ConsensusItem,
    pub peer: PeerId,
}
record!(AcceptedItem, item, peer);
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    UnbalancedTransaction {
        inputs: u64,
        outputs: u64,
        fee: u64,
    },
    InvalidSignature {
        transaction: String,
        hash: String,
        signature: String,
        public_key: String,
    },
    UnsupportedSignatureScheme(u64),
    InvalidWitnessLength,
    Input(DynamicValue),
    Output(DynamicValue),
}
impl ConsensusEncode for TransactionError {
    fn consensus_encode(&self) -> Vec<u8> {
        let (tag, body) = match self {
            Self::UnbalancedTransaction {
                inputs,
                outputs,
                fee,
            } => (
                0,
                [
                    inputs.consensus_encode(),
                    outputs.consensus_encode(),
                    fee.consensus_encode(),
                ]
                .concat(),
            ),
            Self::InvalidSignature {
                transaction,
                hash,
                signature,
                public_key,
            } => (
                1,
                [
                    transaction.consensus_encode(),
                    hash.consensus_encode(),
                    signature.consensus_encode(),
                    public_key.consensus_encode(),
                ]
                .concat(),
            ),
            Self::UnsupportedSignatureScheme(v) => (2, v.consensus_encode()),
            Self::InvalidWitnessLength => (3, vec![]),
            Self::Input(v) => (4, v.consensus_encode()),
            Self::Output(v) => (5, v.consensus_encode()),
        };
        encode_enum(tag, &body)
    }
}
impl ConsensusDecode for TransactionError {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let v = match tag {
            0 => Self::UnbalancedTransaction {
                inputs: b.u64()?,
                outputs: b.u64()?,
                fee: b.u64()?,
            },
            1 => Self::InvalidSignature {
                transaction: b.string()?.to_owned(),
                hash: b.string()?.to_owned(),
                signature: b.string()?.to_owned(),
                public_key: b.string()?.to_owned(),
            },
            2 => Self::UnsupportedSignatureScheme(b.u64()?),
            3 => Self::InvalidWitnessLength,
            4 => Self::Input(DynamicValue::consensus_decode(&mut b)?),
            5 => Self::Output(DynamicValue::consensus_decode(&mut b)?),
            _ => return Err(DecodeError::UnknownVariant),
        };
        b.finish()?;
        Ok(v)
    }
}

/// Session index is supplied separately, never serialized in an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOutcome {
    pub items: Vec<AcceptedItem>,
}
record!(SessionOutcome, items);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSessionOutcome {
    pub outcome: SessionOutcome,
    pub signatures: std::collections::BTreeMap<PeerId, [u8; 64]>,
}
record!(SignedSessionOutcome, outcome, signatures);
impl SessionOutcome {
    pub fn validate_modules(&self, registry: &impl ModuleRegistry) -> Result<(), DecodeError> {
        for accepted in &self.items {
            accepted.item.validate_modules(registry)?;
        }
        Ok(())
    }
}
/// Whole batch schema gate used before ordered per-item execution. Unknown core
/// variants survive this gate so the executor can reject only that item.
pub fn decode_batch(
    bytes: &[u8],
    registry: &impl ModuleRegistry,
) -> Result<Vec<ConsensusItem>, DecodeError> {
    let items: Vec<ConsensusItem> = crate::codec::decode_whole(bytes)?;
    for item in &items {
        item.validate_modules(registry)?;
    }
    Ok(items)
}
impl SignedSessionOutcome {
    /// This checks wire/module schemas only; quorum and signatures are separate.
    pub fn decode_with_registry(
        bytes: &[u8],
        registry: &impl ModuleRegistry,
    ) -> Result<Self, DecodeError> {
        let outcome: Self = crate::codec::decode_whole(bytes)?;
        outcome.outcome.validate_modules(registry)?;
        Ok(outcome)
    }
}
mod session_status;
pub use session_status::{SessionStatus, SessionStatusV2};
