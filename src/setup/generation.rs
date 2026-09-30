use super::{SetupError, SetupTransport, run_g2_dkg};
use crate::{
    codec::{ConsensusEncode, text},
    config::{
        self, DescriptorKind, Endpoint, Fee, IrohEndpoint, RawMintConfig, RawServerConfig,
        RawWalletConfig, ServerModuleConfig, SetupEndpoints, SetupRecord,
    },
    crypto::{
        bls::{self, Scalar},
        secp::{self, SecretKey},
    },
    net::envelope::Envelope,
    protocol::{ModuleId, PeerId},
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone)]
pub struct SetupDefaults {
    pub disable_base_fees: bool,
    pub enabled_modules: BTreeSet<String>,
}
impl Default for SetupDefaults {
    fn default() -> Self {
        Self {
            disable_base_fees: false,
            enabled_modules: BTreeSet::from(["mintv2".into(), "walletv2".into()]),
        }
    }
}
pub struct GeneratedSecrets {
    pub broadcast: SecretKey,
    pub wallet: SecretKey,
    pub mint: BTreeMap<u8, Scalar>,
}
pub struct GeneratedConfig {
    pub server: RawServerConfig,
    /// Retains TCP peer addresses or Iroh keys needed to reconnect after a restart.
    pub setup_records: BTreeMap<PeerId, SetupRecord>,
    pub peer: PeerId,
    pub secrets: GeneratedSecrets,
}
fn peers(local: PeerId, records: &BTreeMap<PeerId, SetupRecord>) -> Vec<PeerId> {
    records
        .keys()
        .copied()
        .filter(|peer| *peer != local)
        .collect()
}
fn checksum(
    transport: &mut impl SetupTransport,
    others: &[PeerId],
    hash: [u8; 32],
) -> Result<(), SetupError> {
    for peer in others {
        transport.send(*peer, Envelope::Checksum(hash))?;
    }
    for peer in others {
        match transport.receive_from(*peer)? {
            Envelope::Checksum(received) if received == hash => {}
            Envelope::Checksum(_) => return Err(SetupError::ChecksumMismatch),
            _ => return Err(SetupError::UnexpectedEnvelope),
        }
    }
    Ok(())
}
fn exchange_public_key(
    transport: &mut impl SetupTransport,
    local: PeerId,
    others: &[PeerId],
    key: [u8; 33],
) -> Result<BTreeMap<PeerId, [u8; 33]>, SetupError> {
    for peer in others {
        transport.send(*peer, Envelope::SetupExchange(key.to_vec()))?;
    }
    let mut keys = BTreeMap::from([(local, key)]);
    for peer in others {
        let Envelope::SetupExchange(bytes) = transport.receive_from(*peer)? else {
            return Err(SetupError::UnexpectedEnvelope);
        };
        let key: [u8; 33] = bytes.try_into().map_err(|_| SetupError::InvalidPublicKey)?;
        secp::validate_public_key(&key).map_err(|_| SetupError::InvalidPublicKey)?;
        keys.insert(*peer, key);
    }
    Ok(keys)
}
/// Fresh serial generation for the closed Mint/Wallet profile over either
/// transport. Neither module boundaries nor denomination numbers are added to
/// the peer message stream. SET-006: a TCP setup fills the API and TLS maps; an
/// Iroh setup leaves both empty and fills the Iroh endpoint map instead.
pub fn generate(
    local: PeerId,
    records: &BTreeMap<PeerId, SetupRecord>,
    defaults: &SetupDefaults,
    transport: &mut impl SetupTransport,
) -> Result<GeneratedConfig, SetupError> {
    config::validate_setup_set(records).map_err(|_| SetupError::InvalidConfiguration)?;
    let local_record = records
        .get(&local)
        .ok_or(SetupError::InvalidConfiguration)?;
    // validate_setup_set already requires one endpoint variant for all records.
    let modules = records
        .values()
        .find_map(|record| record.enabled_modules.as_ref())
        .unwrap_or(&defaults.enabled_modules);
    if modules != &BTreeSet::from(["mintv2".into(), "walletv2".into()]) {
        return Err(SetupError::UnsupportedProfile);
    }
    let disabled = records
        .values()
        .find_map(|record| record.disable_base_fees)
        .unwrap_or(defaults.disable_base_fees);
    let federation_name = records
        .values()
        .find_map(|record| record.federation_name.clone())
        .ok_or(SetupError::InvalidConfiguration)?;
    let (send_tx_vbytes, receive_tx_vbytes) = config::wallet_vbytes(
        records
            .len()
            .try_into()
            .map_err(|_| SetupError::InvalidConfiguration)?,
    )
    .map_err(|_| SetupError::UnsupportedProfile)?;
    let others = peers(local, records);
    if !others.is_empty() {
        transport.wait_for_all(&others)?;
        checksum(transport, &others, config::setup_checksum(records))?;
    }
    let broadcast = SecretKey::random().map_err(|_| SetupError::Crypto)?;
    let broadcast_public_keys =
        exchange_public_key(transport, local, &others, broadcast.public_key())?;
    let mut aggregate_keys = BTreeMap::new();
    let mut public_shares = BTreeMap::new();
    let mut private_mint = BTreeMap::new();
    for denomination in 0..42u8 {
        let result = run_g2_dkg(local, records.len(), transport)?;
        aggregate_keys.insert(denomination, result.public_coefficients[0].to_bytes());
        let shares = records
            .keys()
            .map(|peer| {
                bls::evaluate_commitments(&result.public_coefficients, peer.0)
                    .map(|point| (*peer, point.to_bytes()))
                    .map_err(|_| SetupError::Crypto)
            })
            .collect::<Result<_, _>>()?;
        public_shares.insert(denomination, shares);
        private_mint.insert(denomination, result.secret_share);
    }
    let mint = RawMintConfig {
        aggregate_keys,
        public_shares,
        fee: Fee::mint(if disabled { 0 } else { 100 }, 0)
            .map_err(|_| SetupError::InvalidConfiguration)?,
        amount_unit: 0,
    };
    let wallet = SecretKey::random().map_err(|_| SetupError::Crypto)?;
    let bitcoin_pks = exchange_public_key(transport, local, &others, wallet.public_key())?;
    let wallet_config = RawWalletConfig {
        bitcoin_pks,
        descriptor: DescriptorKind::Wsh,
        send_tx_vbytes,
        receive_tx_vbytes,
        feerate_base: 250,
        dust_limit: 10_000,
        fee_consensus: Fee::wallet(100_000, 0).map_err(|_| SetupError::InvalidConfiguration)?,
        network: local_record.network,
    };
    let mut api_endpoints = BTreeMap::new();
    let mut iroh_endpoints = BTreeMap::new();
    let mut tls_certificates = BTreeMap::new();
    for (peer, record) in records {
        match &record.endpoints {
            SetupEndpoints::Tcp {
                api_url,
                certificate,
                ..
            } => {
                api_endpoints.insert(
                    *peer,
                    Endpoint {
                        url: api_url.clone(),
                        name: record.name.clone(),
                    },
                );
                tls_certificates.insert(*peer, text::hex_encode(certificate));
            }
            SetupEndpoints::Iroh { api_key, p2p_key } => {
                iroh_endpoints.insert(
                    *peer,
                    IrohEndpoint {
                        name: record.name.clone(),
                        api_key: *api_key,
                        p2p_key: *p2p_key,
                    },
                );
            }
        }
    }
    let server = RawServerConfig {
        code_release: config::normalize_release(&local_record.release).into(),
        consensus_version: config::CORE_CONSENSUS,
        broadcast_public_keys,
        rounds_per_session: 3600,
        api_endpoints,
        iroh_endpoints,
        tls_certificates,
        modules: BTreeMap::from([
            (
                ModuleId(0),
                ServerModuleConfig {
                    kind: "mintv2".into(),
                    version: config::MODULE_CONSENSUS,
                    config: mint.consensus_encode(),
                },
            ),
            (
                ModuleId(1),
                ServerModuleConfig {
                    kind: "walletv2".into(),
                    version: config::MODULE_CONSENSUS,
                    config: wallet_config.consensus_encode(),
                },
            ),
        ]),
        meta: BTreeMap::from([("federation_name".into(), federation_name)]),
    };
    checksum(transport, &others, server.consensus_hash())?;
    Ok(GeneratedConfig {
        server,
        setup_records: records.clone(),
        peer: local,
        secrets: GeneratedSecrets {
            broadcast,
            wallet,
            mint: private_mint,
        },
    })
}
