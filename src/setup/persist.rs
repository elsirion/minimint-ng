//! Versioned local storage only, not an upstream guardian archive format.
use super::{GeneratedConfig, GeneratedSecrets};
use crate::{
    codec::{ConsensusDecode, ConsensusEncode, Reader, decode_whole},
    config::{self, RawMintConfig, RawServerConfig, RawWalletConfig},
    crypto::{bls::Scalar, secp::SecretKey},
    net::tls::Identity,
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
    pub identity: Identity,
}
const KEY: &[u8] = b"setup/generated/v1";
fn validate_local(
    generated: &GeneratedConfig,
    identity: &Identity,
) -> Result<(), PersistenceError> {
    let invalid = || PersistenceError::InvalidConfiguration;
    let server = &generated.server;
    config::validate_setup_set(&generated.setup_records).map_err(|_| invalid())?;
    if server.api_endpoints.len() != generated.setup_records.len()
        || server.tls_certificates.len() != generated.setup_records.len()
        || server.broadcast_public_keys.len() != generated.setup_records.len()
        || !server.iroh_endpoints.is_empty()
    {
        return Err(invalid());
    }
    for (peer, record) in &generated.setup_records {
        crate::crypto::secp::validate_public_key(
            server.broadcast_public_keys.get(peer).ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let config::SetupEndpoints::Tcp {
            api_url,
            certificate,
            ..
        } = &record.endpoints
        else {
            return Err(invalid());
        };
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
    if server.consensus_version != config::CORE_CONSENSUS
        || server.modules.len() != 2
        || server.broadcast_public_keys.get(&generated.peer)
            != Some(&generated.secrets.broadcast.public_key())
    {
        return Err(invalid());
    }
    let certificate = identity.certificate_der().map_err(|_| invalid())?;
    if server.tls_certificates.get(&generated.peer)
        != Some(&crate::codec::text::hex_encode(&certificate))
    {
        return Err(invalid());
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
/// One synced transaction contains public config, TLS identity and all generated
/// secrets. Restricted Store directory protects bytes; encryption is not claimed.
pub fn persist_generated(
    store: &Store,
    generated: &GeneratedConfig,
    identity: &Identity,
) -> Result<(), PersistenceError> {
    validate_local(generated, identity)?;
    let mut bytes = Zeroizing::new(vec![1u8]);
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
    if r.byte().map_err(|_| corrupt())? != 1 {
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
    let certificate = r.bytes().map_err(|_| corrupt())?;
    let private = r.bytes().map_err(|_| corrupt())?;
    r.finish().map_err(|_| corrupt())?;
    let identity = Identity::from_der(certificate, private).map_err(|_| corrupt())?;
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
