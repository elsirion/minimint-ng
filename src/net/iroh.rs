//! Iroh transport profile shared by guardian P2P (Iroh 1.0.3) and the
//! client-facing API (Iroh 0.35.0). Both versions are pinned because the
//! reference guardian speaks P2P over the former and serves wallets over the
//! latter; the two stacks are not wire compatible with each other. Discovery,
//! relays and QUIC identity handshakes belong to the dependency (NET-G3).
//!
//! The local policy here: endpoint identities are two independent random
//! Ed25519 secrets, never derived from consensus or TLS keys. Discovery uses
//! the n0 DNS/pkarr services and default relays unless disabled; explicit
//! direct-address overrides make isolated local federations independent of
//! public infrastructure.
use super::TransportError;
use crate::{codec::text, crypto::random_bytes, json};
use sonic_rs::{JsonContainerTrait, JsonValueTrait};
use std::{collections::BTreeMap, net::SocketAddr};
use zeroize::Zeroizing;

/// NET-002 application protocol for guardian messages.
pub const P2P_ALPN: &[u8] = b"FEDIMINT_P2P_ALPN";
/// API-002 application protocol for client requests.
pub const API_ALPN: &[u8] = b"FEDIMINT_API_ALPN";
/// NET-002: a receiver rejects a stream body larger than this.
pub const MAX_P2P_MESSAGE_BYTES: usize = 10_000_000;
/// API-002: the baseline server reads at most this many request bytes.
pub const MAX_API_REQUEST_BYTES: usize = 100_000;
/// Local bound on an address-override file; it holds only public data.
const MAX_ADDRESS_FILE_BYTES: usize = 1024 * 1024;

/// Independent API (Iroh 0.35) and P2P (Iroh 1.0) endpoint secrets. Contains
/// private keys: no Debug, and byte exports are zeroized by their owners.
#[derive(Clone)]
pub struct IrohIdentity {
    api: Zeroizing<[u8; 32]>,
    p2p: Zeroizing<[u8; 32]>,
}
impl IrohIdentity {
    /// SET-002: generate separate API and P2P identity keys.
    pub fn generate() -> Result<Self, TransportError> {
        let api =
            Zeroizing::new(random_bytes::<32>().map_err(|_| TransportError::InvalidIdentity)?);
        let p2p =
            Zeroizing::new(random_bytes::<32>().map_err(|_| TransportError::InvalidIdentity)?);
        if *api == *p2p {
            return Err(TransportError::InvalidIdentity);
        }
        Ok(Self { api, p2p })
    }
    /// Import two 32-byte Ed25519 secret seeds (API first, then P2P).
    pub fn from_secret_bytes(api: &[u8; 32], p2p: &[u8; 32]) -> Result<Self, TransportError> {
        if api == p2p {
            return Err(TransportError::InvalidIdentity);
        }
        Ok(Self {
            api: Zeroizing::new(*api),
            p2p: Zeroizing::new(*p2p),
        })
    }
    /// Operator seed file: 128 lowercase or uppercase hex digits encoding the
    /// API secret followed by the P2P secret. Errors never echo the input.
    pub fn from_hex(input: &str) -> Result<Self, TransportError> {
        let lower = Zeroizing::new(input.to_ascii_lowercase());
        let bytes =
            Zeroizing::new(text::hex_decode(&lower).map_err(|_| TransportError::InvalidIdentity)?);
        if bytes.len() != 64 {
            return Err(TransportError::InvalidIdentity);
        }
        let mut api = Zeroizing::new([0; 32]);
        let mut p2p = Zeroizing::new([0; 32]);
        api.copy_from_slice(&bytes[..32]);
        p2p.copy_from_slice(&bytes[32..]);
        Self::from_secret_bytes(&api, &p2p)
    }
    pub fn api_public(&self) -> [u8; 32] {
        *self.api_secret().public().as_bytes()
    }
    pub fn p2p_public(&self) -> [u8; 32] {
        *self.p2p_secret().public().as_bytes()
    }
    pub(crate) fn api_secret(&self) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&self.api)
    }
    pub(crate) fn p2p_secret(&self) -> iroh_next::SecretKey {
        iroh_next::SecretKey::from_bytes(&self.p2p)
    }
    /// Private persistence export, API secret then P2P secret.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0; 64]);
        out[..32].copy_from_slice(self.api.as_slice());
        out[32..].copy_from_slice(self.p2p.as_slice());
        out
    }
}

/// Local discovery and routing choices; none of this enters consensus.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IrohOptions {
    /// n0 DNS/pkarr discovery and default relays. When false the endpoint
    /// neither publishes nor resolves, and relays are disabled.
    pub discovery: bool,
    /// Public endpoint key to direct UDP address overrides, used when dialing.
    pub addresses: BTreeMap<[u8; 32], SocketAddr>,
}
impl IrohOptions {
    /// Parses `{"<64 hex endpoint key>": "IP:PORT", ...}`. Keys are public.
    pub fn parse_addresses(bytes: &[u8]) -> Result<BTreeMap<[u8; 32], SocketAddr>, TransportError> {
        let value = json::parse(bytes, MAX_ADDRESS_FILE_BYTES, 4)
            .map_err(|_| TransportError::InvalidIdentity)?;
        let object = value.as_object().ok_or(TransportError::InvalidIdentity)?;
        let mut addresses = BTreeMap::new();
        for (key, address) in object.iter() {
            let key: [u8; 32] = text::hex_decode(&key.to_ascii_lowercase())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(TransportError::InvalidIdentity)?;
            let address: SocketAddr = address
                .as_str()
                .and_then(|text| text.parse().ok())
                .ok_or(TransportError::InvalidIdentity)?;
            if addresses.insert(key, address).is_some() {
                return Err(TransportError::InvalidIdentity);
            }
        }
        Ok(addresses)
    }
}

/// A small owned runtime per Iroh component. Iroh requires Tokio; the rest of
/// the guardian keeps its thread-based design and never enters this runtime.
pub(crate) fn runtime(name: &str) -> Result<tokio::runtime::Runtime, TransportError> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(name)
        .enable_all()
        .build()
        .map_err(TransportError::from)
}

/// Guardian P2P endpoint (Iroh 1.0.3). Only `FEDIMINT_P2P_ALPN` is accepted.
pub(crate) async fn bind_p2p(
    secret: iroh_next::SecretKey,
    bind: SocketAddr,
    options: &IrohOptions,
) -> Result<iroh_next::Endpoint, TransportError> {
    use iroh_next::endpoint::presets::{Minimal, N0};
    let builder = if options.discovery {
        iroh_next::Endpoint::builder(N0)
    } else {
        iroh_next::Endpoint::builder(Minimal).relay_mode(iroh_next::RelayMode::Disabled)
    };
    builder
        .secret_key(secret)
        .alpns(vec![P2P_ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr(bind)
        .map_err(|_| TransportError::InvalidIdentity)?
        .bind()
        .await
        .map_err(|_| TransportError::Io(std::io::ErrorKind::AddrNotAvailable))
}

/// Client-facing API endpoint (Iroh 0.35.0). A serving endpoint accepts
/// `FEDIMINT_API_ALPN`; a dial-only endpoint (catch-up) accepts nothing and
/// does not publish its ephemeral identity.
pub(crate) async fn bind_api(
    secret: iroh::SecretKey,
    bind: Option<SocketAddr>,
    options: &IrohOptions,
    serve: bool,
) -> Result<iroh::Endpoint, TransportError> {
    let mut builder = iroh::Endpoint::builder().secret_key(secret);
    if serve {
        builder = builder.alpns(vec![API_ALPN.to_vec()]);
    }
    builder = match bind {
        Some(SocketAddr::V4(address)) => builder.bind_addr_v4(address),
        Some(SocketAddr::V6(address)) => builder.bind_addr_v6(address),
        None => builder,
    };
    builder = match (options.discovery, serve) {
        (true, true) => builder.discovery_n0().relay_mode(iroh::RelayMode::Default),
        (true, false) => builder
            .add_discovery(|_| Some(iroh::discovery::dns::DnsDiscovery::n0_dns()))
            .relay_mode(iroh::RelayMode::Default),
        (false, _) => builder.relay_mode(iroh::RelayMode::Disabled),
    };
    builder
        .bind()
        .await
        .map_err(|_| TransportError::Io(std::io::ErrorKind::AddrNotAvailable))
}

/// Dial target for an API key, using an explicit direct address if supplied.
pub(crate) fn api_node_addr(
    key: &[u8; 32],
    options: &IrohOptions,
) -> Result<iroh::NodeAddr, TransportError> {
    let id = iroh::NodeId::from_bytes(key).map_err(|_| TransportError::InvalidIdentity)?;
    Ok(match options.addresses.get(key) {
        Some(address) => iroh::NodeAddr::new(id).with_direct_addresses([*address]),
        None => iroh::NodeAddr::new(id),
    })
}

/// Dial target for a guardian P2P key, using an explicit direct address if supplied.
pub(crate) fn p2p_endpoint_addr(
    key: &[u8; 32],
    options: &IrohOptions,
) -> Result<iroh_next::EndpointAddr, TransportError> {
    let id = iroh_next::EndpointId::from_bytes(key).map_err(|_| TransportError::InvalidIdentity)?;
    Ok(match options.addresses.get(key) {
        Some(address) => {
            iroh_next::EndpointAddr::from_parts(id, [iroh_next::TransportAddr::Ip(*address)])
        }
        None => iroh_next::EndpointAddr::from(id),
    })
}
