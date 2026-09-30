//! Fresh guardian setup. Public commitments and confidential private shares are
//! separate objects; no secret-bearing setup type implements Debug.
mod admin;
mod dkg;
mod generation;
mod persist;
mod transport;
use crate::{net::envelope::Envelope, protocol::PeerId};
pub use admin::*;
pub use dkg::*;
pub use generation::*;
pub use persist::*;
pub use transport::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupError {
    InvalidConfiguration,
    UnsupportedProfile,
    UnknownPeer,
    MissingPrerequisite,
    Duplicate,
    CommitmentMismatch,
    WrongCoefficientCount,
    InvalidShare,
    Incomplete,
    Aborted,
    Transport,
    UnexpectedEnvelope,
    ChecksumMismatch,
    Crypto,
    InvalidPublicKey,
}
impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid setup configuration",
            Self::UnsupportedProfile => "unsupported setup profile",
            Self::UnknownPeer => "unexpected setup peer",
            Self::MissingPrerequisite => "setup message missing prerequisite",
            Self::Duplicate => "duplicate setup contribution",
            Self::CommitmentMismatch => "DKG commitment hash mismatch",
            Self::WrongCoefficientCount => "wrong DKG coefficient count",
            Self::InvalidShare => "invalid DKG private share",
            Self::Incomplete => "setup incomplete",
            Self::Aborted => "setup invocation aborted",
            Self::Transport => "setup transport closed or unavailable",
            Self::UnexpectedEnvelope => "unexpected setup envelope",
            Self::ChecksumMismatch => "setup checksum mismatch",
            Self::Crypto => "setup cryptographic operation failed",
            Self::InvalidPublicKey => "invalid exchanged public key",
        })
    }
}
impl std::error::Error for SetupError {}
/// Identity comes from authenticated connections, never a claimed sender field.
/// Receivers buffer other peers while awaiting the chosen peer and preserve each
/// peer's FIFO. Production implementations do not add a protocol timeout rule.
pub trait SetupTransport {
    fn wait_for_all(&mut self, peers: &[PeerId]) -> Result<(), SetupError>;
    fn send(&mut self, peer: PeerId, message: Envelope) -> Result<(), SetupError>;
    fn receive_from(&mut self, peer: PeerId) -> Result<Envelope, SetupError>;
}
