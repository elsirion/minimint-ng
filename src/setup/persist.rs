//! Versioned local storage only, not an upstream guardian archive format.
use super::{GeneratedConfig, GeneratedSecrets};
use crate::{
    codec::{ConsensusDecode, ConsensusEncode, Reader, decode_whole},
    config::{self, RawMintConfig, RawServerConfig, RawWalletConfig},
    crypto::{bls::Scalar, secp::SecretKey},
    net::{TransportIdentity, iroh::IrohIdentity, tls::Identity},
    protocol::{ModuleId, PeerId},
    storage::{Namespace, Store, StoreError},
};
use zeroize::Zeroizing;
#[derive(Debug)]
pub enum PersistenceError {
    Storage(StoreError),
    InvalidConfiguration,
    CorruptRecord,
    AlreadyStored,
}
impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Storage(_) => "setup storage failed",
            Self::InvalidConfiguration => "invalid generated local configuration",
            Self::CorruptRecord => "invalid stored setup record",
            Self::AlreadyStored => "generated setup already stored",
        })
    }
}
impl std::error::Error for PersistenceError {}
impl From<StoreError> for PersistenceError {
    fn from(e: StoreError) -> Self {
        Self::Storage(e)
    }
}
pub struct PersistedSetup {
    pub generated: GeneratedConfig,
    pub identity: TransportIdentity,
}
const KEY: &[u8] = b"setup/generated/v1";
/// Record layout versions: 1 ends with the TLS certificate and PKCS#8 key; 2
/// ends with the Iroh API and P2P endpoint secrets. Earlier fields are shared.
const TLS_RECORD: u8 = 1;
const IROH_RECORD: u8 = 2;
fn validate_local(
    generated: &GeneratedConfig,
    identity: &TransportIdentity,
) -> Result<(), PersistenceError> {
    let invalid = || PersistenceError::InvalidConfiguration;
    let server = &generated.server;
    config::validate_setup_set(&generated.setup_records).map_err(|_| invalid())?;
    let n = generated.setup_records.len();
    let tcp = matches!(identity, TransportIdentity::Tls(_));
    let (tcp_entries, iroh_entries) = if tcp { (n, 0) } else { (0, n) };
    if server.api_endpoints.len() != tcp_entries
        || server.tls_certificates.len() != tcp_entries
        || server.iroh_endpoints.len() != iroh_entries
        || server.broadcast_public_keys.len() != n
    {
        return Err(invalid());
    }
    for (peer, record) in &generated.setup_records {
        crate::crypto::secp::validate_public_key(
            server.broadcast_public_keys.get(peer).ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        match &record.endpoints {
            config::SetupEndpoints::Tcp {
                api_url,
                certificate,
                ..
            } if tcp => {
                if server.api_endpoints.get(peer)
                    != Some(&config::Endpoint {
                        url: api_url.clone(),
                        name: record.name.clone(),
                    })
                    || server.tls_certificates.get(peer)
                        != Some(&crate::codec::text::hex_encode(certificate))
                {
                    return Err(invalid());
                }
            }
            config::SetupEndpoints::Iroh { api_key, p2p_key } if !tcp => {
                if server.iroh_endpoints.get(peer)
                    != Some(&config::IrohEndpoint {
                        name: record.name.clone(),
                        api_key: *api_key,
                        p2p_key: *p2p_key,
                    })
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
    }
    if server.consensus_version != config::CORE_CONSENSUS
        || server.modules.len() != 2
        || server.broadcast_public_keys.get(&generated.peer)
            != Some(&generated.secrets.broadcast.public_key())
    {
        return Err(invalid());
    }
    match identity {
        TransportIdentity::Tls(identity) => {
            let certificate = identity.certificate_der().map_err(|_| invalid())?;
            if server.tls_certificates.get(&generated.peer)
                != Some(&crate::codec::text::hex_encode(&certificate))
            {
                return Err(invalid());
            }
        }
        TransportIdentity::Iroh(identity) => {
            let local = server
                .iroh_endpoints
                .get(&generated.peer)
                .ok_or_else(invalid)?;
            if local.api_key != identity.api_public() || local.p2p_key != identity.p2p_public() {
                return Err(invalid());
            }
        }
    }
    let mint = server
        .modules
        .get(&ModuleId(0))
        .filter(|m| m.kind == "mintv2" && m.version == config::MODULE_CONSENSUS)
        .ok_or_else(invalid)?;
    let wallet = server
        .modules
        .get(&ModuleId(1))
        .filter(|m| m.kind == "walletv2" && m.version == config::MODULE_CONSENSUS)
        .ok_or_else(invalid)?;
    let mint: RawMintConfig = decode_whole(&mint.config).map_err(|_| invalid())?;
    let wallet: RawWalletConfig = decode_whole(&wallet.config).map_err(|_| invalid())?;
    crate::modules::mint::Mint::new(
        ModuleId(0),
        generated.peer,
        mint,
        generated.secrets.mint.clone(),
    )
    .map_err(|_| invalid())?;
    let secret = Zeroizing::new(generated.secrets.wallet.to_bytes());
    crate::modules::wallet::Wallet::new(
        ModuleId(1),
        generated.peer,
        wallet,
        SecretKey::from_bytes(&secret).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    Ok(())
}
/// One synced transaction contains public config, transport identity and all
/// generated secrets. Restricted Store directory protects bytes; encryption is
/// not claimed.
pub fn persist_generated(
    store: &Store,
    generated: &GeneratedConfig,
    identity: &TransportIdentity,
) -> Result<(), PersistenceError> {
    validate_local(generated, identity)?;
    let version = match identity {
        TransportIdentity::Tls(_) => TLS_RECORD,
        TransportIdentity::Iroh(_) => IROH_RECORD,
    };
    let mut bytes = Zeroizing::new(vec![version]);
    bytes.extend(generated.server.consensus_encode());
    bytes.extend(generated.setup_records.consensus_encode());
    bytes.extend(generated.peer.consensus_encode());
    bytes.extend_from_slice(Zeroizing::new(generated.secrets.broadcast.to_bytes()).as_slice());
    bytes.extend_from_slice(Zeroizing::new(generated.secrets.wallet.to_bytes()).as_slice());
    bytes.extend((generated.secrets.mint.len() as u64).consensus_encode());
    for (d, secret) in &generated.secrets.mint {
        bytes.push(*d);
        bytes.extend_from_slice(Zeroizing::new(secret.to_bytes()).as_slice());
    }
    match identity {
        TransportIdentity::Tls(identity) => {
            bytes.extend(
                identity
                    .certificate_der()
                    .map_err(|_| PersistenceError::InvalidConfiguration)?
                    .consensus_encode(),
            );
            let private = Zeroizing::new(
                identity
                    .private_key_der()
                    .map_err(|_| PersistenceError::InvalidConfiguration)?,
            );
            bytes.extend((private.len() as u64).consensus_encode());
            bytes.extend_from_slice(&private);
        }
        TransportIdentity::Iroh(identity) => {
            bytes.extend_from_slice(identity.secret_bytes().as_slice());
        }
    }
    let mut tx = store.transaction()?;
    if tx.get(Namespace::Local, KEY)?.is_some() {
        return Err(PersistenceError::AlreadyStored);
    }
    tx.put(Namespace::Local, KEY, &bytes)?;
    tx.commit()?;
    Ok(())
}
pub fn load_generated(store: &Store) -> Result<Option<PersistedSetup>, PersistenceError> {
    let Some(bytes) = store.snapshot()?.get(Namespace::Local, KEY)? else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    decode_stored(&bytes).map(Some)
}
fn decode_stored(bytes: &[u8]) -> Result<PersistedSetup, PersistenceError> {
    let corrupt = || PersistenceError::CorruptRecord;
    let mut r = Reader::new(bytes);
    let version = r.byte().map_err(|_| corrupt())?;
    if !matches!(version, TLS_RECORD | IROH_RECORD) {
        return Err(corrupt());
    }
    let server = RawServerConfig::consensus_decode(&mut r).map_err(|_| corrupt())?;
    let setup_records =
        std::collections::BTreeMap::consensus_decode(&mut r).map_err(|_| corrupt())?;
    let peer = PeerId::consensus_decode(&mut r).map_err(|_| corrupt())?;
    let broadcast = SecretKey::from_bytes(&Zeroizing::new(r.array().map_err(|_| corrupt())?))
        .map_err(|_| corrupt())?;
    let wallet = SecretKey::from_bytes(&Zeroizing::new(r.array().map_err(|_| corrupt())?))
        .map_err(|_| corrupt())?;
    let mint = r
        .ordered_map(
            |r| r.byte(),
            |r| {
                Scalar::from_bytes(&Zeroizing::new(r.array()?))
                    .map_err(|_| crate::codec::DecodeError::InvalidValue)
            },
        )
        .map_err(|_| corrupt())?
        .into_iter()
        .collect();
    let identity: TransportIdentity = if version == TLS_RECORD {
        let certificate = r.bytes().map_err(|_| corrupt())?;
        let private = r.bytes().map_err(|_| corrupt())?;
        Identity::from_der(certificate, private)
            .map_err(|_| corrupt())?
            .into()
    } else {
        let api = Zeroizing::new(r.array::<32>().map_err(|_| corrupt())?);
        let p2p = Zeroizing::new(r.array::<32>().map_err(|_| corrupt())?);
        IrohIdentity::from_secret_bytes(&api, &p2p)
            .map_err(|_| corrupt())?
            .into()
    };
    r.finish().map_err(|_| corrupt())?;
    let generated = GeneratedConfig {
        server,
        setup_records,
        peer,
        secrets: GeneratedSecrets {
            broadcast,
            wallet,
            mint,
        },
    };
    validate_local(&generated, &identity)?;
    Ok(PersistedSetup {
        generated,
        identity,
    })
}
