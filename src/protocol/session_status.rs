//! CON-001 status envelopes. Only Complete v2 contains a certificate; neither
//! the status tag nor its envelope is included in the CON-003 signing digest.
use super::{AcceptedItem, ModuleRegistry, SessionOutcome, SignedSessionOutcome};
use crate::codec::{
    ConsensusDecode, ConsensusEncode, DecodeError, Reader, decode_whole, encode_enum,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Initial,
    Pending(Vec<AcceptedItem>),
    Complete(SessionOutcome),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatusV2 {
    Initial,
    Pending(Vec<AcceptedItem>),
    Complete(SignedSessionOutcome),
}
macro_rules! status_codec {
    ($name:ident,$complete:ty) => {
        impl ConsensusEncode for $name {
            fn consensus_encode(&self) -> Vec<u8> {
                match self {
                    Self::Initial => encode_enum(0, &[]),
                    Self::Pending(items) => encode_enum(1, &items.consensus_encode()),
                    Self::Complete(outcome) => encode_enum(2, &outcome.consensus_encode()),
                }
            }
        }
        impl ConsensusDecode for $name {
            fn consensus_decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
                let (tag, mut body) = reader.variant()?;
                let value = match tag {
                    0 => Self::Initial,
                    1 => Self::Pending(Vec::<AcceptedItem>::consensus_decode(&mut body)?),
                    2 => Self::Complete(<$complete>::consensus_decode(&mut body)?),
                    _ => return Err(DecodeError::UnknownVariant),
                };
                body.finish()?;
                Ok(value)
            }
        }
    };
}
status_codec!(SessionStatus, SessionOutcome);
status_codec!(SessionStatusV2, SignedSessionOutcome);
impl From<SessionStatusV2> for SessionStatus {
    fn from(value: SessionStatusV2) -> Self {
        match value {
            SessionStatusV2::Initial => Self::Initial,
            SessionStatusV2::Pending(items) => Self::Pending(items),
            SessionStatusV2::Complete(signed) => Self::Complete(signed.outcome),
        }
    }
}
impl SessionStatusV2 {
    /// Schema validation only. Authenticate Complete against the requested
    /// session index and trusted broadcast keys using HistoryVerifier separately.
    pub fn decode_with_registry(
        bytes: &[u8],
        registry: &impl ModuleRegistry,
    ) -> Result<Self, DecodeError> {
        let status: Self = decode_whole(bytes)?;
        match &status {
            Self::Initial => {}
            Self::Pending(items) => {
                for accepted in items {
                    accepted.item.validate_modules(registry)?;
                }
            }
            Self::Complete(signed) => signed.outcome.validate_modules(registry)?,
        }
        Ok(status)
    }
}
