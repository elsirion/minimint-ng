//! CON-002/003 commitments and signature policies. Verification authenticates
//! history bytes; session adoption separately checks the prefix and executes it.
use crate::{
    codec::ConsensusEncode,
    crypto::{secp, sha256},
    protocol::{PeerId, SessionOutcome, SignedSessionOutcome},
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryError {
    InvalidKeys,
    InvalidSigner,
    InvalidSignature,
    WrongSignatureCount,
}
impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidKeys => "invalid history broadcast-key configuration",
            Self::InvalidSigner => "unknown history signer",
            Self::InvalidSignature => "invalid history signature",
            Self::WrongSignatureCount => "invalid history signature count",
        })
    }
}
impl std::error::Error for HistoryError {}

#[derive(Debug, Clone, Copy)]
pub enum SignaturePolicy {
    Generic,
    GuardianAdoption,
}

pub fn merkle_root(leaves: impl IntoIterator<Item = impl AsRef<[u8]>>) -> [u8; 32] {
    let mut level: Vec<_> = leaves
        .into_iter()
        .map(|bytes| sha256(bytes.as_ref()))
        .collect();
    if level.is_empty() {
        return [0; 32];
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let mut bytes = [0; 64];
                bytes[..32].copy_from_slice(&pair[0]);
                bytes[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
                sha256(&bytes)
            })
            .collect();
    }
    level[0]
}
pub fn header(session: u64, outcome: &SessionOutcome) -> [u8; 40] {
    let mut header = [0; 40];
    header[..8].copy_from_slice(&session.to_be_bytes());
    header[8..].copy_from_slice(&merkle_root(
        outcome.items.iter().map(ConsensusEncode::consensus_encode),
    ));
    header
}

#[derive(Clone)]
pub struct HistoryVerifier {
    keys: BTreeMap<PeerId, [u8; 33]>,
    key_tag: [u8; 32],
    quorum: usize,
}
impl HistoryVerifier {
    pub fn new(keys: BTreeMap<PeerId, [u8; 33]>) -> Result<Self, HistoryError> {
        let n = keys.len();
        if n != 1 && n < 4 || n > u16::MAX as usize + 1 {
            return Err(HistoryError::InvalidKeys);
        }
        for (expected, (id, key)) in keys.iter().enumerate() {
            if usize::from(id.0) != expected || secp::validate_public_key(key).is_err() {
                return Err(HistoryError::InvalidKeys);
            }
        }
        Ok(Self {
            key_tag: sha256(&keys.consensus_encode()),
            keys,
            quorum: n - (n - 1) / 3,
        })
    }
    pub fn quorum(&self) -> usize {
        self.quorum
    }
    pub fn digest(&self, session: u64, outcome: &SessionOutcome) -> [u8; 32] {
        let mut bytes = [0; 72];
        bytes[..32].copy_from_slice(&self.key_tag);
        bytes[32..].copy_from_slice(&header(session, outcome));
        sha256(&bytes)
    }
    pub fn verify_signature(
        &self,
        session: u64,
        outcome: &SessionOutcome,
        peer: PeerId,
        signature: &[u8; 64],
    ) -> Result<(), HistoryError> {
        let key = self.keys.get(&peer).ok_or(HistoryError::InvalidSigner)?;
        let x = secp::x_only(key).map_err(|_| HistoryError::InvalidKeys)?;
        secp::schnorr_verify(&x, &self.digest(session, outcome), signature)
            .map_err(|_| HistoryError::InvalidSignature)
    }
    pub fn sign(
        &self,
        session: u64,
        outcome: &SessionOutcome,
        peer: PeerId,
        key: &secp::SecretKey,
    ) -> Result<[u8; 64], HistoryError> {
        if self.keys.get(&peer) != Some(&key.public_key()) {
            return Err(HistoryError::InvalidSigner);
        }
        key.schnorr_sign(&self.digest(session, outcome))
            .map_err(|_| HistoryError::InvalidSignature)
    }
    pub fn verify(
        &self,
        session: u64,
        signed: &SignedSessionOutcome,
        policy: SignaturePolicy,
    ) -> Result<(), HistoryError> {
        let count = signed.signatures.len();
        if count < self.quorum
            || matches!(policy, SignaturePolicy::GuardianAdoption) && count != self.quorum
        {
            return Err(HistoryError::WrongSignatureCount);
        }
        // Validate every present signature, including extras in generic mode.
        for (peer, signature) in &signed.signatures {
            self.verify_signature(session, &signed.outcome, *peer, signature)?;
        }
        Ok(())
    }
}
