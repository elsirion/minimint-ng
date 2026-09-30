//! Guardian TLS and bounded message framing. Connection scheduling is separate.
pub mod tls;
use std::io::{self, Read, Write};
pub const MAX_FRAME_LEN: usize = 8_388_608;
#[derive(Debug)]
pub enum TransportError {
    Io(io::ErrorKind),
    FrameTooLarge,
    InvalidIdentity,
    UnknownPeer,
    Tls,
    InvalidEnvelope,
    Closed,
    QueueFull,
}
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io(_) => "transport I/O failed",
            Self::FrameTooLarge => "transport frame exceeds limit",
            Self::InvalidIdentity => "invalid transport identity or configuration",
            Self::UnknownPeer => "unexpected transport peer",
            Self::Tls => "TLS authentication failed",
            Self::InvalidEnvelope => "invalid guardian envelope",
            Self::Closed => "transport connection closed",
            Self::QueueFull => "transport queue full",
        })
    }
}
impl std::error::Error for TransportError {}
impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<openssl::error::ErrorStack> for TransportError {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Self::Tls
    }
}
/// Reads one BE64 frame, validating its length before allocation. EOF inside a
/// header/body is an error. Callers must discard the stream after any error.
pub fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, TransportError> {
    let mut header = [0; 8];
    reader.read_exact(&mut header)?;
    let length = u64::from_be_bytes(header);
    if length > MAX_FRAME_LEN as u64 {
        return Err(TransportError::FrameTooLarge);
    }
    let mut body = vec![0; length as usize];
    reader.read_exact(&mut body)?;
    Ok(body)
}
/// Emits one complete frame. Failed writes are not retried as new frames.
pub fn write_frame(writer: &mut impl Write, body: &[u8]) -> Result<(), TransportError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(TransportError::FrameTooLarge);
    }
    writer.write_all(&(body.len() as u64).to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}
pub mod envelope;
pub mod iroh;
mod iroh_peer;
mod peer;
pub use peer::PeerNetwork;
/// A guardian's private transport identity: a TLS certificate/key for the TCP
/// profile, or the two Iroh endpoint secrets. Never part of consensus. No Debug.
pub enum TransportIdentity {
    Tls(tls::Identity),
    Iroh(iroh::IrohIdentity),
}
impl From<tls::Identity> for TransportIdentity {
    fn from(identity: tls::Identity) -> Self {
        Self::Tls(identity)
    }
}
impl From<iroh::IrohIdentity> for TransportIdentity {
    fn from(identity: iroh::IrohIdentity) -> Self {
        Self::Iroh(identity)
    }
}
impl TransportIdentity {
    pub fn tls(&self) -> Option<&tls::Identity> {
        match self {
            Self::Tls(identity) => Some(identity),
            Self::Iroh(_) => None,
        }
    }
    pub fn iroh(&self) -> Option<&iroh::IrohIdentity> {
        match self {
            Self::Iroh(identity) => Some(identity),
            Self::Tls(_) => None,
        }
    }
    /// TLS profile only: the configured certificate (Iroh has none).
    pub fn certificate_der(&self) -> Result<Vec<u8>, TransportError> {
        self.tls()
            .ok_or(TransportError::InvalidIdentity)?
            .certificate_der()
    }
    /// TLS profile only: the private PKCS#8 key (Iroh has none).
    pub fn private_key_der(&self) -> Result<Vec<u8>, TransportError> {
        self.tls()
            .ok_or(TransportError::InvalidIdentity)?
            .private_key_der()
    }
    /// Independent owned copy for a one-shot handoff (TLS through DER).
    pub fn duplicate(&self) -> Result<Self, TransportError> {
        Ok(match self {
            Self::Tls(identity) => {
                let certificate = identity.certificate_der()?;
                let private = zeroize::Zeroizing::new(identity.private_key_der()?);
                Self::Tls(tls::Identity::from_der(&certificate, &private)?)
            }
            Self::Iroh(identity) => Self::Iroh(identity.clone()),
        })
    }
}
