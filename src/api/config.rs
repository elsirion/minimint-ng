//! CFG/VER endpoints and the observed closed regtest diagnostic profile.
use crate::{
    codec::{decode_whole, text::hex_encode},
    config::{ApiVersions, Invite, RawClientConfig, RawServerConfig, SupportSummary},
    protocol::{PeerId, Version},
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigApiError {
    InvalidConfiguration,
    InvalidParams,
    MethodNotFound,
}
impl std::fmt::Display for ConfigApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "Invalid API configuration",
            Self::InvalidParams => "Invalid params",
            Self::MethodNotFound => "Method not found",
        })
    }
}
impl std::error::Error for ConfigApiError {}
fn version(value: Version) -> Value {
    json!({"major":value.major,"minor":value.minor})
}
fn versions(value: &ApiVersions) -> Result<Value, ConfigApiError> {
    value
        .validate()
        .map_err(|_| ConfigApiError::InvalidConfiguration)?;
    Ok(json!(
        value
            .versions
            .iter()
            .copied()
            .map(version)
            .collect::<Vec<_>>()
    ))
}
/// Current CFG-002 flattened complete config. Dynamic module bytes include the
/// nested instance ID; no extra RPC byte-vector wrapper is inserted.
pub fn client_config_value(config: &RawClientConfig) -> Result<Value, ConfigApiError> {
    config
        .check_module_routing()
        .map_err(|_| ConfigApiError::InvalidConfiguration)?;
    let endpoints: BTreeMap<_, _> = config
        .api_endpoints
        .iter()
        .map(|(peer, endpoint)| {
            (
                peer.0.to_string(),
                json!({"url":endpoint.url.as_str(),"name":endpoint.name}),
            )
        })
        .collect();
    let broadcast_keys = config.broadcast_public_keys.as_ref().map(|keys| {
        keys.iter()
            .map(|(peer, key)| (peer.0.to_string(), hex_encode(key)))
            .collect::<BTreeMap<_, _>>()
    });
    let modules:BTreeMap<_,_>=config.modules.iter().map(|(id,module)|
        (id.0.to_string(),json!({"kind":module.kind,"version":version(module.version),"config":module.config_hex()}))).collect();
    Ok(
        json!({"api_endpoints":endpoints,"broadcast_public_keys":broadcast_keys,
        "consensus_version":version(config.consensus_version),"meta":config.meta,"modules":modules}),
    )
}
pub fn support_summary_value(summary: &SupportSummary) -> Result<Value, ConfigApiError> {
    let core = json!({"core_consensus":version(summary.core.core_consensus),"api":versions(&summary.core.api)?});
    let modules=summary.modules.iter().map(|(id,support)|Ok((id.0.to_string(),json!({
        "core_consensus":version(support.core_consensus),"module_consensus":version(support.module_consensus),"api":versions(&support.api)?
    })))).collect::<Result<BTreeMap<_,_>,ConfigApiError>>()?;
    Ok(json!({"core":core,"modules":modules}))
}

/// Diagnostic shape evidenced by paired native/reference public fixtures.
/// Other module kinds, versions and networks have no inferred schema.
pub fn diagnostic_client_config_value(config: &RawClientConfig) -> Result<Value, ConfigApiError> {
    use crate::config::{BitcoinNetwork, MODULE_CONSENSUS, RawMintConfig, RawWalletConfig};
    let native = client_config_value(config)?;
    let mut modules = BTreeMap::new();
    for (id, module) in &config.modules {
        if module.version != MODULE_CONSENSUS {
            return Err(ConfigApiError::InvalidConfiguration);
        }
        let value = match module.kind.as_str() {
            "mintv2" => {
                let mint: RawMintConfig = decode_whole(&module.config.payload)
                    .map_err(|_| ConfigApiError::InvalidConfiguration)?;
                let aggregate: BTreeMap<_, _> = mint
                    .aggregate_keys
                    .iter()
                    .map(|(d, key)| (d.to_string(), hex_encode(key)))
                    .collect();
                let shares: BTreeMap<_, _> = mint
                    .public_shares
                    .iter()
                    .map(|(d, peers)| {
                        (
                            d.to_string(),
                            peers
                                .iter()
                                .map(|(peer, key)| (peer.0.to_string(), hex_encode(key)))
                                .collect::<BTreeMap<_, _>>(),
                        )
                    })
                    .collect();
                json!({"kind":"mintv2", "amount_unit":mint.amount_unit,
                    "fee_consensus":{"base":mint.fee.base,"parts_per_million":mint.fee.parts_per_million},
                    "tbs_agg_pks":aggregate,"tbs_pks":shares})
            }
            "walletv2" => {
                let wallet: RawWalletConfig = decode_whole(&module.config.payload)
                    .map_err(|_| ConfigApiError::InvalidConfiguration)?;
                if wallet.network != BitcoinNetwork::Regtest {
                    return Err(ConfigApiError::InvalidConfiguration);
                }
                let keys: BTreeMap<_, _> = wallet
                    .bitcoin_pks
                    .iter()
                    .map(|(peer, key)| (peer.0.to_string(), hex_encode(key)))
                    .collect();
                json!({"kind":"walletv2","bitcoin_pks":keys,"descriptor":"Wsh","network":"regtest",
                    "dust_limit":wallet.dust_limit,"feerate_base":wallet.feerate_base,
                    "receive_tx_vbytes":wallet.receive_tx_vbytes,"send_tx_vbytes":wallet.send_tx_vbytes,
                    "fee_consensus":{"base":wallet.fee_consensus.base,"parts_per_million":wallet.fee_consensus.parts_per_million}})
            }
            _ => return Err(ConfigApiError::InvalidConfiguration),
        };
        modules.insert(id.0.to_string(), value);
    }
    Ok(
        json!({"global":{"api_endpoints":native["api_endpoints"].clone(),
        "broadcast_public_keys":native["broadcast_public_keys"].clone(),
        "consensus_version":native["consensus_version"].clone(),"meta":native["meta"].clone()},
        "modules":modules}),
    )
}

/// Immutable endpoint data; the invite may contain transport access credentials.
/// No Debug. The caller must validate guardian keys/private configuration and
/// provide an advertisement supported by its complete installed endpoint set.
pub struct ConfigApi {
    client: Value,
    diagnostic: Result<Value, ConfigApiError>,
    invite: Zeroizing<String>,
    federation_id: String,
    legacy_server_hash: String,
    support: Value,
    software_identity: String,
}
impl ConfigApi {
    pub fn new(
        server: RawServerConfig,
        local_peer: PeerId,
        invite_secret: Option<Zeroizing<String>>,
        software_identity: String,
        support: SupportSummary,
    ) -> Result<Self, ConfigApiError> {
        if !server.api_endpoints.contains_key(&local_peer)
            || software_identity.is_empty()
            || support.core.core_consensus != server.consensus_version
            || support.modules.keys().ne(server.modules.keys())
            || support.modules.iter().any(|(id, s)| {
                s.core_consensus != server.consensus_version
                    || s.module_consensus != server.modules[id].version
            })
        {
            return Err(ConfigApiError::InvalidConfiguration);
        }
        let client = server.client_config();
        let federation_id = client.federation_id();
        let invite = Invite::compact(
            &server.api_endpoints,
            federation_id,
            invite_secret.as_ref().map(|secret| secret.to_string()),
        )
        .map_err(|_| ConfigApiError::InvalidConfiguration)?;
        Ok(Self {
            client: client_config_value(&client)?,
            diagnostic: diagnostic_client_config_value(&client),
            invite: Zeroizing::new(invite.to_bech32m()),
            federation_id: hex_encode(&federation_id),
            legacy_server_hash: hex_encode(&server.legacy_server_consensus_hash()),
            support: support_summary_value(&support)?,
            software_identity,
        })
    }
    pub fn dispatch(&self, method: &str, params: &Value) -> Result<Value, ConfigApiError> {
        if !matches!(
            method,
            "client_config"
                | "client_config_json"
                | "invite_code"
                | "federation_id"
                | "server_config_consensus_hash"
                | "version"
                | "fedimintd_version"
        ) {
            return Err(ConfigApiError::MethodNotFound);
        }
        if !params.is_null() {
            return Err(ConfigApiError::InvalidParams);
        }
        Ok(match method {
            "client_config" => self.client.clone(),
            "client_config_json" => self.diagnostic.clone()?,
            "invite_code" => json!(&**self.invite),
            "federation_id" => json!(self.federation_id),
            "server_config_consensus_hash" => json!(self.legacy_server_hash),
            "version" => self.support.clone(),
            "fedimintd_version" => json!(self.software_identity),
            _ => unreachable!("method checked above"),
        })
    }
}
