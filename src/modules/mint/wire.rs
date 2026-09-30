use crate::{
    codec::{ConsensusDecode, ConsensusEncode, DecodeError, Reader, encode_enum},
    crypto::{bls::G1, secp},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct G1Bytes([u8; 48]);
impl G1Bytes {
    pub fn from_bytes(bytes: [u8; 48]) -> Result<Self, DecodeError> {
        G1::from_bytes(&bytes).map_err(|_| DecodeError::InvalidValue)?;
        Ok(Self(bytes))
    }
    pub fn to_bytes(self) -> [u8; 48] {
        self.0
    }
    pub(super) fn point(self) -> G1 {
        G1::from_bytes(&self.0).expect("validated canonical G1")
    }
}
impl ConsensusEncode for G1Bytes {
    fn consensus_encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
impl ConsensusDecode for G1Bytes {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Self::from_bytes(r.array()?)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nonce([u8; 33]);
impl Nonce {
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, DecodeError> {
        secp::validate_public_key(&bytes).map_err(|_| DecodeError::InvalidValue)?;
        Ok(Self(bytes))
    }
    pub fn to_bytes(self) -> [u8; 33] {
        self.0
    }
}
impl ConsensusEncode for Nonce {
    fn consensus_encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
impl ConsensusDecode for Nonce {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Self::from_bytes(r.array()?)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub denomination: u8,
    pub nonce: Nonce,
    pub signature: G1Bytes,
}
impl ConsensusEncode for Note {
    fn consensus_encode(&self) -> Vec<u8> {
        [
            vec![self.denomination],
            self.nonce.consensus_encode(),
            self.signature.consensus_encode(),
        ]
        .concat()
    }
}
impl ConsensusDecode for Note {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            denomination: r.byte()?,
            nonce: Nonce::consensus_decode(r)?,
            signature: G1Bytes::consensus_decode(r)?,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputV0 {
    pub denomination: u8,
    pub blinded_message: G1Bytes,
    pub tweak: [u8; 16],
}
impl ConsensusEncode for OutputV0 {
    fn consensus_encode(&self) -> Vec<u8> {
        [
            vec![self.denomination],
            self.blinded_message.consensus_encode(),
            self.tweak.to_vec(),
        ]
        .concat()
    }
}
impl ConsensusDecode for OutputV0 {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            denomination: r.byte()?,
            blinded_message: G1Bytes::consensus_decode(r)?,
            tweak: r.array()?,
        })
    }
}
macro_rules! versioned {
    ($name:ident,$inner:ty) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            V0($inner),
            Unknown { version: u64, payload: Vec<u8> },
        }
        impl ConsensusEncode for $name {
            fn consensus_encode(&self) -> Vec<u8> {
                match self {
                    Self::V0(value) => encode_enum(0, &value.consensus_encode()),
                    Self::Unknown { version, payload } => encode_enum(*version, payload),
                }
            }
        }
        impl ConsensusDecode for $name {
            fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                let (version, mut b) = r.variant()?;
                let value = if version == 0 {
                    Self::V0(<$inner>::consensus_decode(&mut b)?)
                } else {
                    Self::Unknown {
                        version,
                        payload: b.take(b.remaining())?.to_vec(),
                    }
                };
                b.finish()?;
                Ok(value)
            }
        }
    };
}
versioned!(Input, Note);
versioned!(Output, OutputV0);
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    UnknownInputVariant(u64),
    SpentCoin,
    InvalidDenomination,
    InvalidSignature,
}
impl ConsensusEncode for InputError {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::UnknownInputVariant(v) => encode_enum(0, &v.consensus_encode()),
            Self::SpentCoin => encode_enum(1, &[]),
            Self::InvalidDenomination => encode_enum(2, &[]),
            Self::InvalidSignature => encode_enum(3, &[]),
        }
    }
}
impl ConsensusDecode for InputError {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let value = match tag {
            0 => Self::UnknownInputVariant(b.u64()?),
            1 => Self::SpentCoin,
            2 => Self::InvalidDenomination,
            3 => Self::InvalidSignature,
            _ => return Err(DecodeError::UnknownVariant),
        };
        b.finish()?;
        Ok(value)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputError {
    UnknownOutputVariant(u64),
    InvalidDenomination,
}
impl ConsensusEncode for OutputError {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::UnknownOutputVariant(v) => encode_enum(0, &v.consensus_encode()),
            Self::InvalidDenomination => encode_enum(1, &[]),
        }
    }
}
impl ConsensusDecode for OutputError {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let value = match tag {
            0 => Self::UnknownOutputVariant(b.u64()?),
            1 => Self::InvalidDenomination,
            _ => return Err(DecodeError::UnknownVariant),
        };
        b.finish()?;
        Ok(value)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryItem {
    Output {
        denomination: u8,
        nonce_hash: [u8; 20],
        tweak: [u8; 16],
    },
    Input {
        nonce_hash: [u8; 20],
    },
}
impl ConsensusEncode for RecoveryItem {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::Output {
                denomination,
                nonce_hash,
                tweak,
            } => encode_enum(
                0,
                &[vec![*denomination], nonce_hash.to_vec(), tweak.to_vec()].concat(),
            ),
            Self::Input { nonce_hash } => encode_enum(1, nonce_hash),
        }
    }
}
impl ConsensusDecode for RecoveryItem {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let value = match tag {
            0 => Self::Output {
                denomination: b.byte()?,
                nonce_hash: b.array()?,
                tweak: b.array()?,
            },
            1 => Self::Input {
                nonce_hash: b.array()?,
            },
            _ => return Err(DecodeError::UnknownVariant),
        };
        b.finish()?;
        Ok(value)
    }
}
