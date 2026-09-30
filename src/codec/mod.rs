//! Consensus, Bitcoin, SCALE and legacy encodings must remain distinct.
mod common;
pub use common::{DecodeError, Reader, bigsize, encode_bytes, encode_enum, encode_string};
pub mod text;
mod traits;
pub use traits::{ConsensusDecode, ConsensusEncode, decode_whole};
pub mod boundary;
pub mod rpc;
