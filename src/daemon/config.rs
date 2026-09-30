//! Validated startup objects for the implemented TCP Mint/Wallet guardian.
//! DNS and listener binding are separate local I/O decisions. No API capability
//! advertisement is inferred from successful configuration validation.
use crate::{
    codec::{decode_whole, text::hex_encode},
    config::{self, CanonicalUrl, RawMintConfig, RawServerConfig, RawWalletConfig, SetupEndpoints},
    core::{history::HistoryVerifier, session::SessionConfig},
    crypto::secp::SecretKey,
    modules::{Modules, mint::Mint, wallet::Wallet},
    net::tls::{PeerCertificate, TlsConfig},
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
    tls: TlsConfig,
    broadcast: SecretKey,
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
            || !server.iroh_endpoints.is_empty()
            || server.modules.len() != 2
        {
            return Err(RuntimeConfigError::UnsupportedProfile);
        }
        config::validate_setup_set(&records).map_err(|_| RuntimeConfigError::InvalidPeers)?;
        let local = records.get(&peer).ok_or(RuntimeConfigError::InvalidPeers)?;
        if records.keys().ne(server.api_endpoints.keys())
            || records.keys().ne(server.broadcast_public_keys.keys())
            || records.keys().ne(server.tls_certificates.keys())
        {
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
        let mut remote_urls = BTreeMap::new();
        let mut certificates = BTreeMap::new();
        for (id, record) in &records {
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
            if *id != peer {
                remote_urls.insert(*id, p2p_url.clone());
            }
            certificates.insert(
                *id,
                PeerCertificate {
                    name: record.name.clone(),
                    certificate_der: certificate.clone(),
                },
            );
        }
        if persisted
            .identity
            .certificate_der()
            .map_err(|_| RuntimeConfigError::InvalidTls)?
            != certificates[&peer].certificate_der
        {
            return Err(RuntimeConfigError::InvalidTls);
        }
        // The shared TLS constructor checks canonical, distinct DER certificates
        // and installs the exact trust/name policy. Its authenticated handshake
        // remains the certificate-chain, server-name and validity-time boundary.
        let tls = TlsConfig::new(&persisted.identity, certificates)
            .map_err(|_| RuntimeConfigError::InvalidTls)?;
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
            tls,
            broadcast: generated.secrets.broadcast,
        })
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
    pub fn tls_config(&self) -> TlsConfig {
        self.tls.clone()
    }
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
