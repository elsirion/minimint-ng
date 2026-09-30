//! Public wire configuration. Raw records do not establish valid guardian keys,
//! local secret-share correspondence, endpoint authentication, or API capability.
use crate::{
    codec::{ConsensusDecode, ConsensusEncode, DecodeError, Reader},
    crypto::sha256,
    protocol::{DynamicValue, ModuleId, PeerId, Version},
};
use std::collections::BTreeMap;
mod invite;
mod modules;
mod setup;
mod versions;
pub use invite::*;
pub use modules::*;
pub use setup::*;
pub use versions::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    UnsupportedUrl,
    InvalidProfile,
    InvalidSetup,
    InvalidInvite,
    Binary(DecodeError),
    Text,
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedUrl => "URL is outside supported canonical simple URL profile",
            Self::InvalidProfile => "invalid daemon configuration profile",
            Self::InvalidSetup => "invalid setup parameters",
            Self::InvalidInvite => "invalid invite",
            Self::Binary(_) => "invalid binary configuration",
            Self::Text => "invalid encoded configuration text",
        })
    }
}
impl std::error::Error for ConfigError {}
impl From<DecodeError> for ConfigError {
    fn from(e: DecodeError) -> Self {
        Self::Binary(e)
    }
}

/// Already canonical simple URL, where full serialization equals consensus display.
/// Complex URLs require a reviewed general parser; this type rejects them explicitly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalUrl(String);
impl CanonicalUrl {
    pub fn simple(input: &str) -> Result<Self, ConfigError> {
        // A non-special scheme with a host and an empty path serializes without
        // a trailing slash. The Iroh API form is exactly 64 lowercase hex digits.
        if let Some(key) = input.strip_prefix("iroh://") {
            return if key.len() == 64 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                Ok(Self(input.to_owned()))
            } else {
                Err(ConfigError::UnsupportedUrl)
            };
        }
        let (scheme, rest) = input.split_once("://").ok_or(ConfigError::UnsupportedUrl)?;
        if !matches!(scheme, "http" | "https" | "ws" | "wss" | "tcp" | "fedimint")
            || !input.is_ascii()
        {
            return Err(ConfigError::UnsupportedUrl);
        }
        let (authority, path) = rest.split_once('/').ok_or(ConfigError::UnsupportedUrl)?;
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        if host.is_empty()
            || host.starts_with('.')
            || host.ends_with('.')
            || host.contains("..")
            || !host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            return Err(ConfigError::UnsupportedUrl);
        }
        for label in host.split('.') {
            if label.starts_with('-') || label.ends_with('-') {
                return Err(ConfigError::UnsupportedUrl);
            }
        }
        // Numeric hosts have additional URL-parser IPv4 normalization rules.
        if host
            .rsplit('.')
            .next()
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()) || s.starts_with("0x"))
            && host
                .parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.to_string() != host)
                .unwrap_or(true)
        {
            return Err(ConfigError::UnsupportedUrl);
        }
        if let Some(port) = port {
            let n = port
                .parse::<u16>()
                .map_err(|_| ConfigError::UnsupportedUrl)?;
            if n.to_string() != port
                || n == 0
                || (matches!(scheme, "http" | "ws") && n == 80)
                || (matches!(scheme, "https" | "wss") && n == 443)
            {
                return Err(ConfigError::UnsupportedUrl);
            }
        }
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
            || path.split('/').any(|s| s == "." || s == "..")
        {
            return Err(ConfigError::UnsupportedUrl);
        }
        Ok(Self(input.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Client-facing Iroh API URL for an endpoint public key: `iroh://` + hex.
    pub fn iroh(api_key: &[u8; 32]) -> Self {
        Self(format!(
            "iroh://{}",
            crate::codec::text::hex_encode(api_key)
        ))
    }
    /// The Iroh API endpoint key named by an `iroh://` URL, if this is one.
    pub fn iroh_key(&self) -> Option<[u8; 32]> {
        let hex = self.0.strip_prefix("iroh://")?;
        crate::codec::text::hex_decode(hex).ok()?.try_into().ok()
    }
}
impl ConsensusEncode for CanonicalUrl {
    fn consensus_encode(&self) -> Vec<u8> {
        self.0.consensus_encode()
    }
}
impl ConsensusDecode for CanonicalUrl {
    fn consensus_decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Self::simple(r.string()?).map_err(|_| DecodeError::InvalidValue)
    }
}
macro_rules! record {
    ($name:ident,$($field:ident),+) => {
        impl ConsensusEncode for $name { fn consensus_encode(&self)->Vec<u8> { let mut out=Vec::new(); $(out.extend(self.$field.consensus_encode());)+ out } }
        impl ConsensusDecode for $name { fn consensus_decode(r:&mut Reader<'_>)->Result<Self,DecodeError> { Ok(Self{$($field:ConsensusDecode::consensus_decode(r)?),+}) } }
    }
}
pub(crate) use record;
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    pub url: CanonicalUrl,
    pub name: String,
}
record!(Endpoint, url, name);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientModuleConfig {
    pub kind: String,
    pub version: Version,
    pub config: DynamicValue,
}
record!(ClientModuleConfig, kind, version, config);
impl ClientModuleConfig {
    /// CFG-002 JSON config field: direct dynamic bytes, no RPC byte-vector layer.
    pub fn config_hex(&self) -> String {
        crate::codec::text::hex_encode(&self.config.consensus_encode())
    }
    pub fn from_config_hex(kind: String, version: Version, hex: &str) -> Result<Self, ConfigError> {
        let bytes = crate::codec::text::hex_decode(hex).map_err(|_| ConfigError::Text)?;
        Ok(Self {
            kind,
            version,
            config: crate::codec::decode_whole(&bytes)?,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawClientConfig {
    pub api_endpoints: BTreeMap<PeerId, Endpoint>,
    pub broadcast_public_keys: Option<BTreeMap<PeerId, [u8; 33]>>,
    pub consensus_version: Version,
    pub meta: BTreeMap<String, String>,
    pub modules: BTreeMap<ModuleId, ClientModuleConfig>,
}
record!(
    RawClientConfig,
    api_endpoints,
    broadcast_public_keys,
    consensus_version,
    meta,
    modules
);
pub fn federation_id(endpoints: &BTreeMap<PeerId, Endpoint>) -> [u8; 32] {
    sha256(&endpoints.consensus_encode())
}
impl RawClientConfig {
    pub fn federation_id(&self) -> [u8; 32] {
        federation_id(&self.api_endpoints)
    }
    pub fn full_hash(&self) -> [u8; 32] {
        sha256(&self.consensus_encode())
    }
    pub fn check_module_routing(&self) -> Result<(), ConfigError> {
        if self
            .modules
            .iter()
            .any(|(id, module)| *id != module.config.module_id)
        {
            return Err(ConfigError::InvalidProfile);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerModuleConfig {
    pub kind: String,
    pub version: Version,
    pub config: Vec<u8>,
}
record!(ServerModuleConfig, kind, version, config);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohEndpoint {
    pub name: String,
    pub api_key: [u8; 32],
    pub p2p_key: [u8; 32],
}
record!(IrohEndpoint, name, api_key, p2p_key);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawServerConfig {
    pub code_release: String,
    pub consensus_version: Version,
    pub broadcast_public_keys: BTreeMap<PeerId, [u8; 33]>,
    pub rounds_per_session: u16,
    pub api_endpoints: BTreeMap<PeerId, Endpoint>,
    pub iroh_endpoints: BTreeMap<PeerId, IrohEndpoint>,
    pub tls_certificates: BTreeMap<PeerId, String>,
    pub modules: BTreeMap<ModuleId, ServerModuleConfig>,
    pub meta: BTreeMap<String, String>,
}
record!(
    RawServerConfig,
    code_release,
    consensus_version,
    broadcast_public_keys,
    rounds_per_session,
    api_endpoints,
    iroh_endpoints,
    tls_certificates,
    modules,
    meta
);
impl RawServerConfig {
    /// API-009's legacy server commitment omits the Iroh map entirely. This is
    /// distinct from both SET-006's current checksum and the full client hash.
    pub fn legacy_server_consensus_hash(&self) -> [u8; 32] {
        sha256(
            &[
                normalize_release(&self.code_release).consensus_encode(),
                self.consensus_version.consensus_encode(),
                self.broadcast_public_keys.consensus_encode(),
                self.rounds_per_session.consensus_encode(),
                self.api_endpoints.consensus_encode(),
                self.tls_certificates.consensus_encode(),
                self.modules.consensus_encode(),
                self.meta.consensus_encode(),
            ]
            .concat(),
        )
    }
    pub fn consensus_hash(&self) -> [u8; 32] {
        sha256(&self.consensus_encode())
    }
    /// Client-facing API endpoints. An Iroh federation leaves the TCP map empty
    /// and advertises each guardian's API key as `iroh://<hex>` under its name;
    /// the federation ID commits to this derived map.
    pub fn client_api_endpoints(&self) -> BTreeMap<PeerId, Endpoint> {
        if self.iroh_endpoints.is_empty() {
            return self.api_endpoints.clone();
        }
        self.iroh_endpoints
            .iter()
            .map(|(peer, endpoint)| {
                (
                    *peer,
                    Endpoint {
                        url: CanonicalUrl::iroh(&endpoint.api_key),
                        name: endpoint.name.clone(),
                    },
                )
            })
            .collect()
    }
    pub fn client_config(&self) -> RawClientConfig {
        RawClientConfig {
            api_endpoints: self.client_api_endpoints(),
            broadcast_public_keys: Some(self.broadcast_public_keys.clone()),
            consensus_version: self.consensus_version,
            meta: self.meta.clone(),
            modules: self
                .modules
                .iter()
                .map(|(id, m)| {
                    (
                        *id,
                        ClientModuleConfig {
                            kind: m.kind.clone(),
                            version: m.version,
                            config: DynamicValue {
                                module_id: *id,
                                payload: m.config.clone(),
                            },
                        },
                    )
                })
                .collect(),
        }
    }
}
/// Metadata signatures commit to original UTF-8 JSON bytes, never reserialization.
pub fn guardian_metadata_digest(content: &str) -> [u8; 32] {
    sha256(&[b"fedimint-guardian-metadata".as_slice(), content.as_bytes()].concat())
}
pub fn api_announcement_digest(url: &CanonicalUrl, nonce: u64) -> [u8; 32] {
    sha256(
        &[
            b"fedimint-api-announcement".to_vec(),
            url.consensus_encode(),
            nonce.consensus_encode(),
        ]
        .concat(),
    )
}
