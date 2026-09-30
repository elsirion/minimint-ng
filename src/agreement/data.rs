//! NET-005 attached data; its SCALE encoding is independent of consensus E.
use parity_scale_codec::{Decode, Encode, EncodeLike, Error, Input, Output};
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Data {
    Batch(Vec<u8>),
    Signature([u8; 64]),
}
impl Data {
    pub fn within_limit(&self) -> bool {
        match self {
            Self::Batch(bytes) => bytes.len() <= 50_000,
            Self::Signature(_) => true,
        }
    }
}
impl Encode for Data {
    fn size_hint(&self) -> usize {
        match self {
            Self::Batch(bytes) => bytes.len() + 6,
            Self::Signature(_) => 65,
        }
    }
    fn encode_to<T: Output + ?Sized>(&self, out: &mut T) {
        match self {
            Self::Batch(bytes) => {
                out.push_byte(0);
                bytes.encode_to(out)
            }
            Self::Signature(sig) => {
                out.push_byte(1);
                sig.encode_to(out)
            }
        }
    }
}
impl EncodeLike for Data {}
impl Decode for Data {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        match input.read_byte()? {
            0 => Ok(Self::Batch(Vec::decode(input)?)),
            1 => Ok(Self::Signature(<[u8; 64]>::decode(input)?)),
            _ => Err("unknown attached agreement data variant".into()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolHasher;
impl fedimint_aleph_bft::Hasher for ProtocolHasher {
    type Hash = [u8; 32];
    fn hash(bytes: &[u8]) -> Self::Hash {
        use crate::codec::ConsensusEncode;
        crate::crypto::sha256(&bytes.consensus_encode())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedUnit {
    pub creator: crate::protocol::PeerId,
    pub round: u16,
    pub data: Option<Data>,
}
