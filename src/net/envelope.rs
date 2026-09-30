//! NET-003 common-first receive and legacy send envelopes. Signed outcome bytes
//! remain opaque here; their module decoding and authentication are downstream.
use crate::{
    codec::{
        ConsensusEncode, DecodeError, Reader,
        boundary::{common_first, legacy_bytes, read_legacy_bytes},
        encode_enum, text,
    },
    crypto::bls::{G1, G2, Scalar},
};
use zeroize::Zeroizing;

/// A share is private transport data; no Debug implementation is provided.
#[derive(Clone)]
pub enum DkgMessage<P> {
    Hash([u8; 32]),
    Commitments(Vec<P>),
    Share(Scalar),
}
#[derive(Clone)]
pub enum Envelope {
    Agreement(Vec<u8>),
    SessionSignature([u8; 64]),
    SessionIndex(u64),
    SignedSessionOutcome(Vec<u8>),
    Checksum([u8; 32]),
    DkgG1(DkgMessage<G1>),
    DkgG2(DkgMessage<G2>),
    SetupExchange(Vec<u8>),
    Unknown { tag: u64, payload: Vec<u8> },
}
fn encode_dkg<P>(message: &DkgMessage<P>, point: impl Fn(&P) -> Vec<u8>) -> Vec<u8> {
    match message {
        DkgMessage::Hash(hash) => encode_enum(0, hash),
        DkgMessage::Commitments(points) => {
            let mut bytes = (points.len() as u64).consensus_encode();
            for p in points {
                bytes.extend(point(p));
            }
            encode_enum(1, &bytes)
        }
        DkgMessage::Share(scalar) => {
            let bytes = Zeroizing::new(scalar.to_bytes());
            encode_enum(2, bytes.as_slice())
        }
    }
}
fn decode_dkg<P>(
    r: &mut Reader<'_>,
    point: impl Fn(&mut Reader<'_>) -> Result<P, DecodeError>,
) -> Result<DkgMessage<P>, DecodeError> {
    let (tag, mut body) = r.variant()?;
    let result = match tag {
        0 => DkgMessage::Hash(body.array()?),
        1 => DkgMessage::Commitments(body.sequence(point)?),
        2 => {
            let bytes = Zeroizing::new(body.array()?);
            DkgMessage::Share(Scalar::from_bytes(&bytes).map_err(|_| DecodeError::InvalidValue)?)
        }
        _ => return Err(DecodeError::UnknownVariant),
    };
    body.finish()?;
    Ok(result)
}
fn read_g1(r: &mut Reader<'_>) -> Result<G1, DecodeError> {
    G1::from_bytes(&r.array()?).map_err(|_| DecodeError::InvalidValue)
}
fn read_g2(r: &mut Reader<'_>) -> Result<G2, DecodeError> {
    G2::from_bytes(&r.array()?).map_err(|_| DecodeError::InvalidValue)
}
fn read_hex(r: &mut Reader<'_>) -> Result<Vec<u8>, DecodeError> {
    let bytes = read_legacy_bytes(r)?;
    let string = std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidValue)?;
    text::hex_decode(string).map_err(|_| DecodeError::InvalidValue)
}
fn legacy_hex(bytes: Vec<u8>) -> Vec<u8> {
    let bytes = Zeroizing::new(bytes);
    let hex = Zeroizing::new(text::hex_encode(&bytes));
    legacy_bytes(hex.as_bytes())
}
impl Envelope {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        common_first(bytes, Self::decode_common, Self::decode_legacy)
    }
    fn decode_common(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let (tag, mut body) = r.variant()?;
        let result = match tag {
            0 => Self::Agreement(body.bytes()?.to_vec()),
            1 => Self::SessionSignature(body.array()?),
            2 => Self::SessionIndex(body.u64()?),
            3 => Self::SignedSessionOutcome(body.bytes()?.to_vec()),
            4 => Self::Checksum(body.array()?),
            5 => Self::DkgG1(decode_dkg(&mut body, read_g1)?),
            6 => Self::DkgG2(decode_dkg(&mut body, read_g2)?),
            7 => Self::SetupExchange(body.bytes()?.to_vec()),
            _ => Self::Unknown {
                tag,
                payload: body.take(body.remaining())?.to_vec(),
            },
        };
        body.finish()?;
        Ok(result)
    }
    fn decode_legacy(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let tag = u32::from_le_bytes(r.array()?);
        Ok(match tag {
            0 => Self::Agreement(read_legacy_bytes(r)?.to_vec()),
            1 => Self::SessionSignature(
                read_legacy_bytes(r)?
                    .try_into()
                    .map_err(|_| DecodeError::InvalidValue)?,
            ),
            2 => Self::SessionIndex(u64::from_le_bytes(r.array()?)),
            3 => {
                let bytes = Zeroizing::new(read_hex(r)?);
                let mut inner = Reader::new(&bytes);
                let outcome = inner.bytes()?.to_vec();
                inner.finish()?;
                Self::SignedSessionOutcome(outcome)
            }
            4 => Self::Checksum(
                read_legacy_bytes(r)?
                    .try_into()
                    .map_err(|_| DecodeError::InvalidValue)?,
            ),
            5 => {
                let bytes = Zeroizing::new(read_hex(r)?);
                let mut inner = Reader::new(&bytes);
                let message = decode_dkg(&mut inner, read_g1)?;
                inner.finish()?;
                Self::DkgG1(message)
            }
            6 => {
                let bytes = Zeroizing::new(read_hex(r)?);
                let mut inner = Reader::new(&bytes);
                let message = decode_dkg(&mut inner, read_g2)?;
                inner.finish()?;
                Self::DkgG2(message)
            }
            7 => Self::SetupExchange(read_legacy_bytes(r)?.to_vec()),
            8 => Self::Unknown {
                tag: u64::from_le_bytes(r.array()?),
                payload: read_legacy_bytes(r)?.to_vec(),
            },
            _ => return Err(DecodeError::UnknownVariant),
        })
    }
    pub fn encode_common(&self) -> Result<Vec<u8>, DecodeError> {
        let (tag, body) = match self {
            Self::Agreement(bytes) => (0, bytes.consensus_encode()),
            Self::SessionSignature(sig) => (1, sig.to_vec()),
            Self::SessionIndex(index) => (2, index.consensus_encode()),
            Self::SignedSessionOutcome(bytes) => (3, bytes.consensus_encode()),
            Self::Checksum(hash) => (4, hash.to_vec()),
            Self::DkgG1(message) => (5, encode_dkg(message, |p| p.to_bytes().to_vec())),
            Self::DkgG2(message) => (6, encode_dkg(message, |p| p.to_bytes().to_vec())),
            Self::SetupExchange(bytes) => (7, bytes.consensus_encode()),
            Self::Unknown { tag, payload } => {
                if *tag < 8 {
                    return Err(DecodeError::InvalidValue);
                }
                (*tag, payload.clone())
            }
        };
        let body = Zeroizing::new(body);
        Ok(encode_enum(tag, &body))
    }
    pub fn encode_legacy(&self) -> Result<Vec<u8>, DecodeError> {
        let (tag, body): (u32, Vec<u8>) = match self {
            Self::Agreement(bytes) => (0, legacy_bytes(bytes)),
            Self::SessionSignature(sig) => (1, legacy_bytes(sig)),
            Self::SessionIndex(index) => (2, index.to_le_bytes().to_vec()),
            Self::SignedSessionOutcome(bytes) => (3, legacy_hex(bytes.consensus_encode())),
            Self::Checksum(hash) => (4, legacy_bytes(hash)),
            Self::DkgG1(message) => (
                5,
                legacy_hex(encode_dkg(message, |p| p.to_bytes().to_vec())),
            ),
            Self::DkgG2(message) => (
                6,
                legacy_hex(encode_dkg(message, |p| p.to_bytes().to_vec())),
            ),
            Self::SetupExchange(bytes) => (7, legacy_bytes(bytes)),
            Self::Unknown { tag, payload } => (
                8,
                [tag.to_le_bytes().to_vec(), legacy_bytes(payload)].concat(),
            ),
        };
        let body = Zeroizing::new(body);
        let mut out = tag.to_le_bytes().to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }
}
