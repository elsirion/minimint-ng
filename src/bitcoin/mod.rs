//! Bitcoin wire bytes and the narrow backend boundary used by the Wallet module.
//! Hash arrays are internal digest order; only display hex reverses them.
pub mod esplora;
pub mod http;
pub mod rpc;
use crate::{
    codec::{
        ConsensusDecode, ConsensusEncode, DecodeError, Reader,
        boundary::{compact_size, read_compact_size},
        text,
    },
    crypto::sha256,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Txid(pub [u8; 32]);
impl Txid {
    pub fn display_hex(self) -> String {
        let mut bytes = self.0;
        bytes.reverse();
        text::hex_encode(&bytes)
    }
}
impl ConsensusEncode for Txid {
    fn consensus_encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
impl ConsensusDecode for Txid {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self(r.array()?))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}
impl ConsensusEncode for OutPoint {
    fn consensus_encode(&self) -> Vec<u8> {
        [self.txid.0.to_vec(), self.vout.to_le_bytes().to_vec()].concat()
    }
}
impl ConsensusDecode for OutPoint {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            txid: Txid(r.array()?),
            vout: u32::from_le_bytes(r.array()?),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value_sat: u64,
    pub script_pubkey: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}
fn script_bytes(script: &[u8]) -> Vec<u8> {
    [compact_size(script.len() as u64), script.to_vec()].concat()
}
fn read_bytes(r: &mut Reader<'_>) -> Result<Vec<u8>, DecodeError> {
    let n = read_compact_size(r)?;
    if n > r.remaining() as u64 {
        return Err(DecodeError::Truncated);
    }
    Ok(r.take(n as usize)?.to_vec())
}
fn count(r: &mut Reader<'_>, minimum: usize) -> Result<usize, DecodeError> {
    let n = read_compact_size(r)?;
    if n > (r.remaining() / minimum) as u64 {
        return Err(DecodeError::Truncated);
    }
    usize::try_from(n).map_err(|_| DecodeError::Overflow)
}
impl TxOut {
    pub fn encode(&self) -> Vec<u8> {
        [
            self.value_sat.to_le_bytes().to_vec(),
            script_bytes(&self.script_pubkey),
        ]
        .concat()
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            value_sat: u64::from_le_bytes(r.array()?),
            script_pubkey: read_bytes(r)?,
        })
    }
}
impl Transaction {
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_witness(true)
    }
    pub fn encode_without_witness(&self) -> Vec<u8> {
        self.encode_with_witness(false)
    }
    fn encode_with_witness(&self, allow: bool) -> Vec<u8> {
        let witness = allow && self.inputs.iter().any(|i| !i.witness.is_empty());
        let mut out = self.version.to_le_bytes().to_vec();
        if witness {
            out.extend([0, 1]);
        }
        out.extend(compact_size(self.inputs.len() as u64));
        for input in &self.inputs {
            out.extend(input.previous_output.consensus_encode());
            out.extend(script_bytes(&input.script_sig));
            out.extend(input.sequence.to_le_bytes());
        }
        out.extend(compact_size(self.outputs.len() as u64));
        for output in &self.outputs {
            out.extend(output.encode());
        }
        if witness {
            for input in &self.inputs {
                out.extend(compact_size(input.witness.len() as u64));
                for item in &input.witness {
                    out.extend(script_bytes(item));
                }
            }
        }
        out.extend(self.lock_time.to_le_bytes());
        out
    }
    pub fn txid(&self) -> Txid {
        Txid(double_sha256(&self.encode_without_witness()))
    }
    pub fn wtxid(&self) -> Txid {
        Txid(double_sha256(&self.encode()))
    }
    pub fn weight(&self) -> u64 {
        (3 * self.encode_without_witness().len() + self.encode().len()) as u64
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let tx = Self::read(&mut r)?;
        r.finish()?;
        Ok(tx)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let version = i32::from_le_bytes(r.array()?);
        let mut inputs_count = count(r, 41)?;
        let witness = inputs_count == 0;
        if witness {
            if r.byte()? != 1 {
                return Err(DecodeError::InvalidValue);
            }
            inputs_count = count(r, 41)?;
            if inputs_count == 0 {
                return Err(DecodeError::InvalidValue);
            }
        }
        let mut inputs = Vec::new();
        for _ in 0..inputs_count {
            inputs.push(TxIn {
                previous_output: OutPoint::consensus_decode(r)?,
                script_sig: read_bytes(r)?,
                sequence: u32::from_le_bytes(r.array()?),
                witness: Vec::new(),
            });
        }
        let n = count(r, 9)?;
        let mut outputs = Vec::new();
        for _ in 0..n {
            outputs.push(TxOut::decode(r)?);
        }
        if witness {
            for input in &mut inputs {
                let n = count(r, 1)?;
                for _ in 0..n {
                    input.witness.push(read_bytes(r)?);
                }
            }
            if inputs.iter().all(|i| i.witness.is_empty()) {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time: u32::from_le_bytes(r.array()?),
        })
    }
    /// BIP143 SIGHASH_ALL for the supplied v0 scriptCode. Wallet scripts never
    /// contain OP_CODESEPARATOR; no script interpreter or other hash type is implied.
    pub fn sighash_all(
        &self,
        input_index: usize,
        script_code: &[u8],
        value_sat: u64,
    ) -> Result<[u8; 32], DecodeError> {
        let input = self
            .inputs
            .get(input_index)
            .ok_or(DecodeError::InvalidValue)?;
        let prevouts: Vec<u8> = self
            .inputs
            .iter()
            .flat_map(|i| i.previous_output.consensus_encode())
            .collect();
        let sequences: Vec<u8> = self
            .inputs
            .iter()
            .flat_map(|i| i.sequence.to_le_bytes())
            .collect();
        let outputs: Vec<u8> = self.outputs.iter().flat_map(TxOut::encode).collect();
        Ok(double_sha256(
            &[
                self.version.to_le_bytes().to_vec(),
                double_sha256(&prevouts).to_vec(),
                double_sha256(&sequences).to_vec(),
                input.previous_output.consensus_encode(),
                script_bytes(script_code),
                value_sat.to_le_bytes().to_vec(),
                input.sequence.to_le_bytes().to_vec(),
                double_sha256(&outputs).to_vec(),
                self.lock_time.to_le_bytes().to_vec(),
                1_u32.to_le_bytes().to_vec(),
            ]
            .concat(),
        ))
    }
}
pub fn double_sha256(bytes: &[u8]) -> [u8; 32] {
    sha256(&sha256(bytes))
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: [u8; 80],
    pub transactions: Vec<Transaction>,
}
impl Block {
    pub fn hash(&self) -> [u8; 32] {
        double_sha256(&self.header)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let header = r.array()?;
        let n = count(&mut r, 10)?;
        let mut transactions = Vec::new();
        for _ in 0..n {
            transactions.push(Transaction::read(&mut r)?);
        }
        r.finish()?;
        Ok(Self {
            header,
            transactions,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendError;
impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Bitcoin backend unavailable or invalid response")
    }
}
impl std::error::Error for BackendError {}
/// Implementations wait/retry unavailable canonical block reads. Counts include genesis.
/// All hashes here are internal byte order; HTTP/RPC formatting belongs to an adapter.
pub trait BitcoinBackend {
    fn block_count(&self) -> Result<u64, BackendError>;
    fn wait_for_count(&self, count: u64) -> Result<(), BackendError>;
    fn block_hash(&self, height: u64) -> Result<[u8; 32], BackendError>;
    fn block(&self, hash: [u8; 32]) -> Result<Block, BackendError>;
    fn fee_rate(&self) -> Result<Option<u64>, BackendError>;
    fn broadcast(&self, transaction: &Transaction) -> Result<(), BackendError>;
}
