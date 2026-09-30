use crate::{
    bitcoin,
    codec::{ConsensusDecode, ConsensusEncode, DecodeError, Reader, encode_enum},
    crypto::secp,
};
macro_rules! record {($name:ident,$($field:ident),+)=>{
    impl ConsensusEncode for $name{fn consensus_encode(&self)->Vec<u8>{let mut out=Vec::new();$(out.extend(self.$field.consensus_encode());)+out}}
    impl ConsensusDecode for $name{fn consensus_decode(r:&mut Reader<'_>)->Result<Self,DecodeError>{Ok(Self{$($field:ConsensusDecode::consensus_decode(r)?),+})}}
}}
pub(super) use record;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    V0 {
        output_index: u64,
        claimant: [u8; 33],
        mining_fee_sat: u64,
    },
    Unknown {
        version: u64,
        payload: Vec<u8>,
    },
}
impl ConsensusEncode for Input {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::V0 {
                output_index,
                claimant,
                mining_fee_sat,
            } => encode_enum(
                0,
                &[
                    output_index.consensus_encode(),
                    claimant.to_vec(),
                    mining_fee_sat.consensus_encode(),
                ]
                .concat(),
            ),
            Self::Unknown { version, payload } => encode_enum(*version, payload),
        }
    }
}
impl ConsensusDecode for Input {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let v = if tag == 0 {
            let output_index = b.u64()?;
            let claimant = b.array()?;
            secp::validate_public_key(&claimant).map_err(|_| DecodeError::InvalidValue)?;
            Self::V0 {
                output_index,
                claimant,
                mining_fee_sat: b.u64()?,
            }
        } else {
            Self::Unknown {
                version: tag,
                payload: b.take(b.remaining())?.to_vec(),
            }
        };
        b.finish()?;
        Ok(v)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    P2wpkh([u8; 20]),
    P2wsh([u8; 32]),
    P2tr([u8; 32]),
    Unknown { tag: u64, payload: Vec<u8> },
}
impl ConsensusEncode for Destination {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::P2pkh(v) => encode_enum(0, v),
            Self::P2sh(v) => encode_enum(1, v),
            Self::P2wpkh(v) => encode_enum(2, v),
            Self::P2wsh(v) => encode_enum(3, v),
            Self::P2tr(v) => encode_enum(4, v),
            Self::Unknown { tag, payload } => encode_enum(*tag, payload),
        }
    }
}
impl ConsensusDecode for Destination {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let v = match tag {
            0 => Self::P2pkh(b.array()?),
            1 => Self::P2sh(b.array()?),
            2 => Self::P2wpkh(b.array()?),
            3 => Self::P2wsh(b.array()?),
            4 => Self::P2tr(b.array()?),
            _ => Self::Unknown {
                tag,
                payload: b.take(b.remaining())?.to_vec(),
            },
        };
        b.finish()?;
        Ok(v)
    }
}
impl Destination {
    pub fn script_pubkey(&self) -> Option<Vec<u8>> {
        Some(match self {
            Self::P2pkh(h) => [vec![0x76, 0xa9, 20], h.to_vec(), vec![0x88, 0xac]].concat(),
            Self::P2sh(h) => [vec![0xa9, 20], h.to_vec(), vec![0x87]].concat(),
            Self::P2wpkh(h) => [vec![0, 20], h.to_vec()].concat(),
            Self::P2wsh(h) => [vec![0, 32], h.to_vec()].concat(),
            Self::P2tr(h) => [vec![0x51, 32], h.to_vec()].concat(),
            Self::Unknown { .. } => return None,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    V0 {
        destination: Destination,
        value_sat: u64,
        mining_fee_sat: u64,
    },
    Unknown {
        version: u64,
        payload: Vec<u8>,
    },
}
impl ConsensusEncode for Output {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::V0 {
                destination,
                value_sat,
                mining_fee_sat,
            } => encode_enum(
                0,
                &[
                    destination.consensus_encode(),
                    value_sat.consensus_encode(),
                    mining_fee_sat.consensus_encode(),
                ]
                .concat(),
            ),
            Self::Unknown { version, payload } => encode_enum(*version, payload),
        }
    }
}
impl ConsensusDecode for Output {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let v = if tag == 0 {
            Self::V0 {
                destination: Destination::consensus_decode(&mut b)?,
                value_sat: b.u64()?,
                mining_fee_sat: b.u64()?,
            }
        } else {
            Self::Unknown {
                version: tag,
                payload: b.take(b.remaining())?.to_vec(),
            }
        };
        b.finish()?;
        Ok(v)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusItem {
    BlockCount(u64),
    FeeRate(Option<u64>),
    Signatures {
        txid: bitcoin::Txid,
        signatures: Vec<[u8; 64]>,
    },
    Unknown {
        tag: u64,
        payload: Vec<u8>,
    },
}
impl ConsensusEncode for ConsensusItem {
    fn consensus_encode(&self) -> Vec<u8> {
        match self {
            Self::BlockCount(v) => encode_enum(0, &v.consensus_encode()),
            Self::FeeRate(v) => encode_enum(1, &v.consensus_encode()),
            Self::Signatures { txid, signatures } => encode_enum(
                2,
                &[txid.consensus_encode(), signatures.consensus_encode()].concat(),
            ),
            Self::Unknown { tag, payload } => encode_enum(*tag, payload),
        }
    }
}
impl ConsensusDecode for ConsensusItem {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut b) = r.variant()?;
        let v = match tag {
            0 => Self::BlockCount(b.u64()?),
            1 => Self::FeeRate(Option::consensus_decode(&mut b)?),
            2 => Self::Signatures {
                txid: bitcoin::Txid::consensus_decode(&mut b)?,
                signatures: Vec::consensus_decode(&mut b)?,
            },
            _ => return Err(DecodeError::UnknownVariant),
        };
        b.finish()?;
        Ok(v)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationWallet {
    pub value_sat: u64,
    pub outpoint: bitcoin::OutPoint,
    pub tweak: [u8; 32],
}
record!(FederationWallet, value_sat, outpoint, tweak);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    pub index: u64,
    pub script: Vec<u8>,
    pub value_sat: u64,
    pub spent: bool,
    pub outpoint: Option<bitcoin::OutPoint>,
}
record!(Discovery, index, script, value_sat, spent, outpoint);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRecord {
    pub index: u64,
    pub txid: bitcoin::Txid,
    pub input_sat: u64,
    pub output_sat: u64,
    pub fee_sat: u64,
    pub vbytes: u64,
    pub created: u64,
}
record!(
    ChainRecord,
    index,
    txid,
    input_sat,
    output_sat,
    fee_sat,
    vbytes,
    created
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    UnknownVersion(u64),
    AlreadySpent,
    UnknownIndex,
    WrongTweak,
    NoFeeRate,
    InsufficientFee,
    ArithmeticOverflow,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputError {
    UnknownVersion(u64),
    UnderDust,
    NoWallet,
    NoFeeRate,
    InsufficientFee,
    ChangeUnderDust,
    ArithmeticOverflow,
    UnknownScript,
}
macro_rules! errors{
    ($name:ident,$($variant:ident=$tag:literal),+) => {
        impl ConsensusEncode for $name{fn consensus_encode(&self)->Vec<u8>{match self{Self::UnknownVersion(version)=>encode_enum(0,&version.consensus_encode()),$(Self::$variant=>encode_enum($tag,&[]),)+}}}
        impl ConsensusDecode for $name{fn consensus_decode(r:&mut Reader<'_>)->Result<Self,DecodeError>{let(tag,mut body)=r.variant()?;let value=match tag{0=>Self::UnknownVersion(body.u64()?),$($tag=>Self::$variant,)+_=>return Err(DecodeError::UnknownVariant)};body.finish()?;Ok(value)}}
    }
}
errors!(
    InputError,
    AlreadySpent = 1,
    UnknownIndex = 2,
    WrongTweak = 3,
    NoFeeRate = 4,
    InsufficientFee = 5,
    ArithmeticOverflow = 6
);
errors!(
    OutputError,
    UnderDust = 1,
    NoWallet = 2,
    NoFeeRate = 3,
    InsufficientFee = 4,
    ChangeUnderDust = 5,
    ArithmeticOverflow = 6,
    UnknownScript = 7
);
