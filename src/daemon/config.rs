//! Validated startup objects for the implemented Mint/Wallet guardian over the
//! TCP/mTLS or Iroh transport.
//! DNS and listener binding are separate local I/O decisions. No API capability
//! advertisement is inferred from successful configuration validation.
use crate::{
    codec::{decode_whole, text::hex_encode},
    config::{self, CanonicalUrl, RawMintConfig, RawServerConfig, RawWalletConfig, SetupEndpoints},
    core::{history::HistoryVerifier, session::SessionConfig},
    crypto::secp::SecretKey,
    modules::{Modules, mint::Mint, wallet::Wallet},
    net::{
        TransportIdentity,
        iroh::IrohIdentity,
        tls::{PeerCertificate, TlsConfig},
    },
    protocol::PeerId,
    setup::PersistedSetup,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{SocketAddr, ToSocketAddrs},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigError {
    UnsupportedProfile,
    InvalidPeers,
    InvalidKeys,
    InvalidTls,
    InvalidModule,
    InvalidEndpoint,
    Resolution,
}
impl std::fmt::Display for RuntimeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedProfile => "Unsupported guardian profile",
            Self::InvalidPeers => "Invalid guardian membership",
            Self::InvalidKeys => "Invalid guardian keys",
            Self::InvalidTls => "Invalid guardian TLS configuration",
            Self::InvalidModule => "Invalid guardian module configuration",
            Self::InvalidEndpoint => "Invalid guardian endpoint",
            Self::Resolution => "Guardian address resolution failed",
        })
    }
}
impl std::error::Error for RuntimeConfigError {}
/// All private keys stay behind non-Debug objects. This object is immutable and
/// can be shared through Arc by the API and the single consensus executor.
pub struct RuntimeConfig {
    server: RawServerConfig,
    peer: PeerId,
    remote_urls: BTreeMap<PeerId, CanonicalUrl>,
    modules: Modules,
    transport: Transport,
    broadcast: SecretKey,
}
enum Transport {
    Tcp(TlsConfig),
    /// Local endpoint secrets plus every guardian's committed P2P key.
    Iroh {
        identity: IrohIdentity,
        p2p_keys: BTreeMap<PeerId, [u8; 32]>,
    },
}
pub(crate) fn tcp_authority(url: &CanonicalUrl) -> Result<&str, RuntimeConfigError> {
    let authority = url
        .as_str()
        .strip_prefix("fedimint://")
        .and_then(|text| text.strip_suffix('/'))
        .ok_or(RuntimeConfigError::InvalidEndpoint)?;
    if authority.contains('/') || authority.rsplit_once(':').is_none() {
        return Err(RuntimeConfigError::InvalidEndpoint);
    }
    Ok(authority)
}
impl RuntimeConfig {
    pub fn from_persisted(persisted: PersistedSetup) -> Result<Self, RuntimeConfigError> {
        let generated = persisted.generated;
        let server = generated.server;
        let records = generated.setup_records;
        let peer = generated.peer;
        // <=20 is the current Wallet CHECKMULTISIG construction domain (WAL012),
        // rather than a generic Aleph or peer-ID limit. R+1000 is NET009's u16 bound.
        let n = records.len();
        if !(n == 1 || (4..=20).contains(&n))
            || server.consensus_version != config::CORE_CONSENSUS
            || server.code_release != "0.13.0"
            || server.rounds_per_session == 0
            || server.rounds_per_session.checked_add(1000).is_none()
            || server.modules.len() != 2
        {
            return Err(RuntimeConfigError::UnsupportedProfile);
        }
        config::validate_setup_set(&records).map_err(|_| RuntimeConfigError::InvalidPeers)?;
        let local = records.get(&peer).ok_or(RuntimeConfigError::InvalidPeers)?;
        let iroh = matches!(local.endpoints, SetupEndpoints::Iroh { .. });
        // SET-006: exactly one of the TCP (API + TLS) and Iroh maps is populated.
        let (tcp_maps, iroh_map) = if iroh {
            (
                server.api_endpoints.is_empty() && server.tls_certificates.is_empty(),
                records.keys().eq(server.iroh_endpoints.keys()),
            )
        } else {
            (
                records.keys().eq(server.api_endpoints.keys())
                    && records.keys().eq(server.tls_certificates.keys()),
                server.iroh_endpoints.is_empty(),
            )
        };
        if !tcp_maps || !iroh_map || records.keys().ne(server.broadcast_public_keys.keys()) {
            return Err(RuntimeConfigError::InvalidPeers);
        }
        HistoryVerifier::new(server.broadcast_public_keys.clone())
            .map_err(|_| RuntimeConfigError::InvalidKeys)?;
        if server.broadcast_public_keys.get(&peer)
            != Some(&generated.secrets.broadcast.public_key())
        {
            return Err(RuntimeConfigError::InvalidKeys);
        }
        let federation_name = records
            .values()
            .find_map(|record| record.federation_name.as_ref())
            .ok_or(RuntimeConfigError::InvalidPeers)?;
        if server.meta.get("federation_name") != Some(federation_name)
            || records.values().any(|record| {
                config::normalize_release(&record.release) != server.code_release
                    || record.enabled_modules.as_ref().is_some_and(|modules| {
                        modules != &BTreeSet::from(["mintv2".to_owned(), "walletv2".to_owned()])
                    })
            })
        {
            return Err(RuntimeConfigError::UnsupportedProfile);
        }
        let transport = if iroh {
            let TransportIdentity::Iroh(identity) = persisted.identity else {
                return Err(RuntimeConfigError::InvalidKeys);
            };
            let mut p2p_keys = BTreeMap::new();
            let mut api_keys = BTreeSet::new();
            for (id, record) in &records {
                let SetupEndpoints::Iroh { api_key, p2p_key } = &record.endpoints else {
                    return Err(RuntimeConfigError::UnsupportedProfile);
                };
                let endpoint = &server.iroh_endpoints[id];
                if endpoint.name != record.name
                    || endpoint.api_key != *api_key
                    || endpoint.p2p_key != *p2p_key
                    || p2p_keys.values().any(|key| key == p2p_key)
                    || !api_keys.insert(*api_key)
                    || iroh_next::EndpointId::from_bytes(p2p_key).is_err()
                    || iroh::NodeId::from_bytes(api_key).is_err()
                {
                    return Err(RuntimeConfigError::InvalidPeers);
                }
                p2p_keys.insert(*id, *p2p_key);
            }
            let own = &server.iroh_endpoints[&peer];
            if own.api_key != identity.api_public() || own.p2p_key != identity.p2p_public() {
                return Err(RuntimeConfigError::InvalidKeys);
            }
            Transport::Iroh { identity, p2p_keys }
        } else {
            let TransportIdentity::Tls(identity) = persisted.identity else {
                return Err(RuntimeConfigError::InvalidTls);
            };
            Transport::Tcp(Self::tcp(&records, &server, peer, &identity)?)
        };
        let mut remote_urls = BTreeMap::new();
        for (id, record) in &records {
            if let SetupEndpoints::Tcp { p2p_url, .. } = &record.endpoints
                && *id != peer
            {
                remote_urls.insert(*id, p2p_url.clone());
            }
        }
        let (mut mint_config, mut wallet_config) = (None, None);
        for (id, module) in &server.modules {
            if module.version != config::MODULE_CONSENSUS {
                return Err(RuntimeConfigError::UnsupportedProfile);
            }
            match module.kind.as_str() {
                "mintv2" if mint_config.is_none() => {
                    mint_config = Some((
                        *id,
                        decode_whole::<RawMintConfig>(&module.config)
                            .map_err(|_| RuntimeConfigError::InvalidModule)?,
                    ));
                }
                "walletv2" if wallet_config.is_none() => {
                    let wallet = decode_whole::<RawWalletConfig>(&module.config)
                        .map_err(|_| RuntimeConfigError::InvalidModule)?;
                    if wallet.bitcoin_pks.keys().ne(records.keys())
                        || wallet.network != local.network
                    {
                        return Err(RuntimeConfigError::InvalidModule);
                    }
                    wallet_config = Some((*id, wallet));
                }
                _ => return Err(RuntimeConfigError::UnsupportedProfile),
            }
        }
        let (mint_id, mint) = mint_config.ok_or(RuntimeConfigError::UnsupportedProfile)?;
        let (wallet_id, wallet) = wallet_config.ok_or(RuntimeConfigError::UnsupportedProfile)?;
        // Preserve MINT012's local required-share checks; do not add aggregate
        // reconstruction or equal-map predicates to the Mint's acceptance rules.
        let mint = Mint::new(mint_id, peer, mint, generated.secrets.mint)
            .map_err(|_| RuntimeConfigError::InvalidModule)?;
        let wallet = Wallet::new(wallet_id, peer, wallet, generated.secrets.wallet)
            .map_err(|_| RuntimeConfigError::InvalidModule)?;
        let modules = Modules::new(mint, wallet).map_err(|_| RuntimeConfigError::InvalidModule)?;
        Ok(Self {
            server,
            peer,
            remote_urls,
            modules,
            transport,
            broadcast: generated.secrets.broadcast,
        })
    }
    /// TCP profile checks: WS API and `fedimint://` P2P URLs, exact committed
    /// API endpoints and certificates, and the local TLS identity.
    fn tcp(
        records: &BTreeMap<PeerId, crate::config::SetupRecord>,
        server: &RawServerConfig,
        peer: PeerId,
        identity: &crate::net::tls::Identity,
    ) -> Result<TlsConfig, RuntimeConfigError> {
        let mut certificates = BTreeMap::new();
        for (id, record) in records {
            let SetupEndpoints::Tcp {
                api_url,
                p2p_url,
                certificate,
            } = &record.endpoints
            else {
                return Err(RuntimeConfigError::UnsupportedProfile);
            };
            tcp_authority(p2p_url)?;
            if !matches!(
                api_url.as_str().split_once("://").map(|(scheme, _)| scheme),
                Some("ws" | "wss")
            ) {
                return Err(RuntimeConfigError::InvalidEndpoint);
            }
            let endpoint = &server.api_endpoints[id];
            if endpoint.name != record.name
                || endpoint.url != *api_url
                || server.tls_certificates[id] != hex_encode(certificate)
            {
                return Err(RuntimeConfigError::InvalidPeers);
            }
            certificates.insert(
                *id,
                PeerCertificate {
                    name: record.name.clone(),
                    certificate_der: certificate.clone(),
                },
            );
        }
        if identity
            .certificate_der()
            .map_err(|_| RuntimeConfigError::InvalidTls)?
            != certificates[&peer].certificate_der
        {
            return Err(RuntimeConfigError::InvalidTls);
        }
        // The shared TLS constructor checks canonical, distinct DER certificates
        // and installs the exact trust/name policy. Its authenticated handshake
        // remains the certificate-chain, server-name and validity-time boundary.
        TlsConfig::new(identity, certificates).map_err(|_| RuntimeConfigError::InvalidTls)
    }
    pub fn peer(&self) -> PeerId {
        self.peer
    }
    pub fn modules(&self) -> &Modules {
        &self.modules
    }
    pub fn server_config(&self) -> &RawServerConfig {
        &self.server
    }
    /// TLS trust configuration; `None` for an Iroh federation.
    pub fn tls_config(&self) -> Option<TlsConfig> {
        match &self.transport {
            Transport::Tcp(tls) => Some(tls.clone()),
            Transport::Iroh { .. } => None,
        }
    }
    pub fn is_iroh(&self) -> bool {
        matches!(self.transport, Transport::Iroh { .. })
    }
    /// Local Iroh endpoint secrets and all committed guardian P2P keys.
    pub fn iroh_peers(&self) -> Option<(&IrohIdentity, &BTreeMap<PeerId, [u8; 32]>)> {
        match &self.transport {
            Transport::Iroh { identity, p2p_keys } => Some((identity, p2p_keys)),
            Transport::Tcp(_) => None,
        }
    }
    /// Remote TCP P2P URLs; empty for an Iroh federation.
    pub fn remote_peer_urls(&self) -> &BTreeMap<PeerId, CanonicalUrl> {
        &self.remote_urls
    }
    pub fn session_config(&self) -> Result<SessionConfig, RuntimeConfigError> {
        let bytes = Zeroizing::new(self.broadcast.to_bytes());
        Ok(SessionConfig {
            broadcast_keys: self.server.broadcast_public_keys.clone(),
            local_peer: self.peer,
            local_key: SecretKey::from_bytes(&bytes)
                .map_err(|_| RuntimeConfigError::InvalidKeys)?,
            version: self.server.consensus_version,
            rounds: self.server.rounds_per_session,
        })
    }
    /// DNS is local startup I/O and may fail or change between invocations. This
    /// selects one address per peer, preferring IPv4 when both families resolve.
    /// The local advertised endpoint is never used as the listener bind address.
    pub fn resolve_peer_addresses(
        &self,
    ) -> Result<BTreeMap<PeerId, SocketAddr>, RuntimeConfigError> {
        self.remote_urls
            .iter()
            .map(|(peer, url)| {
                let address = tcp_authority(url)?
                    .to_socket_addrs()
                    .map_err(|_| RuntimeConfigError::Resolution)?
                    .min_by_key(|address| (address.is_ipv6(), *address))
                    .ok_or(RuntimeConfigError::Resolution)?;
                Ok((*peer, address))
            })
            .collect()
    }
}
