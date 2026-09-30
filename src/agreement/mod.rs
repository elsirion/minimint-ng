//! Public adapters around the exactly pinned agreement engine.
pub mod backup;
mod config;
mod data;
mod keychain;
mod provider;
pub mod runtime;
pub use config::{ordinary_delays, session_config};
pub use data::{Data, FinalizedUnit, ProtocolHasher};
pub use keychain::GuardianKeychain;
pub use provider::{BatchProvider, ProposalQueue};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgreementError {
    InvalidConfig,
    Failed,
    QueueFull,
    OversizedData,
    SignaturePhase,
    MalformedPayload,
}
impl std::fmt::Display for AgreementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid agreement configuration",
            Self::Failed => "agreement task failed",
            Self::QueueFull => "agreement queue full",
            Self::OversizedData => "agreement item exceeds batch limit",
            Self::MalformedPayload => "malformed agreement payload",
            Self::SignaturePhase => "agreement is already proposing signatures",
        })
    }
}
impl std::error::Error for AgreementError {}
mod network;
mod session;
pub use network::{EngineNetworkData, Outbound, decode_payload};
pub use session::{EngineIo, EngineSession};
