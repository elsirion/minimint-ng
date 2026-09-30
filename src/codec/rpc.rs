//! Typed RPC array contents; the API's general JSON serializer owns JSON syntax.
//! Direct configuration blobs use `text::hex_encode(E(config))` without this layer.
use super::{
    ConsensusDecode, ConsensusEncode, DecodeError, Reader, decode_whole, encode_bytes, text,
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    Text(text::TextError),
    Binary(DecodeError),
    InvalidArrayLength,
}
impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(e) => e.fmt(f),
            Self::Binary(e) => e.fmt(f),
            Self::InvalidArrayLength => f.write_str("RPC wrapper requires one array element"),
        }
    }
}
impl std::error::Error for RpcError {}
pub fn hex<T: ConsensusEncode>(value: &T) -> [String; 1] {
    [text::hex_encode(&encode_bytes(&value.consensus_encode()))]
}
pub fn base64<T: ConsensusEncode>(value: &T) -> [String; 1] {
    [text::base64url_encode(&encode_bytes(
        &value.consensus_encode(),
    ))]
}
fn unwrap<T: ConsensusDecode>(bytes: &[u8]) -> Result<T, RpcError> {
    let mut reader = Reader::new(bytes);
    let payload = reader.bytes().map_err(RpcError::Binary)?;
    reader.finish().map_err(RpcError::Binary)?;
    decode_whole(payload).map_err(RpcError::Binary)
}
pub fn decode_hex<T: ConsensusDecode>(array: &[String]) -> Result<T, RpcError> {
    let [value] = array else {
        return Err(RpcError::InvalidArrayLength);
    };
    unwrap(&text::hex_decode(value).map_err(RpcError::Text)?)
}
pub fn decode_base64<T: ConsensusDecode>(array: &[String]) -> Result<T, RpcError> {
    let [value] = array else {
        return Err(RpcError::InvalidArrayLength);
    };
    unwrap(&text::base64url_decode(value).map_err(RpcError::Text)?)
}
