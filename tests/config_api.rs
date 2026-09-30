use minimint_ng::{
    api::config::{ConfigApi, ConfigApiError, client_config_value, support_summary_value},
    codec::{
        decode_whole,
        text::{hex_decode, hex_encode},
    },
    config::{
        self, ApiVersions, CoreSupport, Invite, ModuleSupport, RawServerConfig, SupportSummary,
    },
    protocol::{ModuleId, PeerId, Version},
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::collections::BTreeMap;
fn fixture() -> Value {
    minimint_ng::json::parse(
        include_bytes!("fixtures/config/raw-commitments.json"),
        16384,
        16,
    )
    .unwrap()
}
fn server() -> RawServerConfig {
    decode_whole(&hex_decode(fixture()["server_hex"].as_str().unwrap()).unwrap()).unwrap()
}
fn support(server: &RawServerConfig) -> SupportSummary {
    SupportSummary {
        core: CoreSupport {
            core_consensus: server.consensus_version,
            api: ApiVersions {
                versions: vec![Version { major: 0, minor: 0 }],
            },
        },
        modules: server
            .modules
            .iter()
            .map(|(id, module)| {
                (
                    *id,
                    ModuleSupport {
                        core_consensus: server.consensus_version,
                        module_consensus: module.version,
                        api: ApiVersions {
                            versions: vec![config::MODULE_API],
                        },
                    },
                )
            })
            .collect(),
    }
}
fn api() -> ConfigApi {
    let server = server();
    let support = support(&server);
    ConfigApi::new(
        server,
        PeerId(0),
        None,
        "minimint-ng/0.1.0-test".into(),
        support,
    )
    .unwrap()
}
#[test]
fn fixed_cfg_json_is_flat_and_contains_entire_dynamic_encoding() {
    let api = api();
    assert_eq!(
        api.dispatch("client_config", &json!(null)).unwrap(),
        json!({
            "api_endpoints":{"0":{"url":"wss://example.com/","name":"Guardian 0"}},
            "broadcast_public_keys":{},"consensus_version":{"major":2,"minor":1},"meta":{},
            "modules":{"42":{"kind":"mintv2","version":{"major":1,"minor":0},"config":"2a0109"}}
        })
    );
    assert_eq!(
        api.dispatch("federation_id", &json!(null)).unwrap(),
        fixture()["endpoint_hash"]
    );
    assert_eq!(
        api.dispatch("server_config_consensus_hash", &json!(null))
            .unwrap(),
        fixture()["legacy_server_hash"]
    );
    assert_ne!(fixture()["legacy_server_hash"], fixture()["server_hash"]);
    assert_ne!(fixture()["legacy_server_hash"], fixture()["client_hash"]);
    assert_eq!(
        api.dispatch("invite_code", &json!(null)).unwrap(),
        json!(
            "fed11qgqpgynhwden5te0v4uxzmtsd3jjucm0d5hsqqfqghwwxek94y4tdfvfk7ddtf6pr39hmu9kr0qguhflmj2xcvyx6mmsjtre29"
        )
    );
}
#[test]
fn version_summary_uses_decimal_ids_arrays_and_explicit_capabilities() {
    assert_eq!(
        api().dispatch("version", &json!(null)).unwrap(),
        json!({
            "core":{"core_consensus":{"major":2,"minor":1},"api":[{"major":0,"minor":0}]},
            "modules":{"42":{"core_consensus":{"major":2,"minor":1},"module_consensus":{"major":1,"minor":0},"api":[{"major":0,"minor":1}]}}
        })
    );
    // Software identity is independently supplied, never the normalized upstream
    // compatibility release from the consensus configuration.
    assert_eq!(
        api().dispatch("fedimintd_version", &json!(null)).unwrap(),
        json!("minimint-ng/0.1.0-test")
    );
    let mut summary = support(&server());
    for versions in [
        vec![
            Version { major: 0, minor: 1 },
            Version { major: 0, minor: 2 },
        ],
        vec![
            Version { major: 1, minor: 0 },
            Version { major: 0, minor: 9 },
        ],
    ] {
        summary.core.api.versions = versions;
        assert_eq!(
            support_summary_value(&summary),
            Err(ConfigApiError::InvalidConfiguration)
        );
    }
}
#[test]
fn compact_invite_selects_first_f_plus_one_peers_and_retains_access_secret_only_there() {
    let mut server = server();
    server.api_endpoints = (0..4)
        .map(|id| {
            (
                PeerId(id),
                config::Endpoint {
                    url: config::CanonicalUrl::simple(&format!("wss://guardian{id}.example.com/"))
                        .unwrap(),
                    name: format!("Guardian {id}"),
                },
            )
        })
        .collect();
    let expected_id = config::federation_id(&server.api_endpoints);
    let support = support(&server);
    let api = ConfigApi::new(
        server,
        PeerId(3),
        Some(zeroize::Zeroizing::new("transport-secret".into())),
        "independent-build".into(),
        support,
    )
    .unwrap();
    let value = api.dispatch("invite_code", &json!(null)).unwrap();
    let invite = Invite::from_text(value.as_str().unwrap()).unwrap();
    assert_eq!(
        invite.endpoints().keys().copied().collect::<Vec<_>>(),
        [PeerId(0), PeerId(1)]
    );
    assert_eq!(invite.federation_id(), expected_id);
    assert_eq!(invite.api_secret(), Some("transport-secret"));
    let public = api.dispatch("client_config", &json!(null)).unwrap();
    assert!(
        !String::from_utf8(minimint_ng::json::encode(&public).unwrap())
            .unwrap()
            .contains("transport-secret")
    );
}
#[test]
fn legacy_broadcast_null_and_bigsize_nested_instance_are_explicit() {
    let mut config = server().client_config();
    config.broadcast_public_keys = None;
    let mut module = config.modules.remove(&ModuleId(42)).unwrap();
    module.config.module_id = ModuleId(300);
    config.modules.insert(ModuleId(300), module);
    let native = client_config_value(&config).unwrap();
    assert!(native["broadcast_public_keys"].is_null());
    assert_eq!(native["modules"]["300"]["config"], json!("fd012c0109"));
    config
        .modules
        .get_mut(&ModuleId(300))
        .unwrap()
        .config
        .module_id = ModuleId(42);
    assert_eq!(
        client_config_value(&config),
        Err(ConfigApiError::InvalidConfiguration)
    );
}
#[test]
fn local_membership_support_binding_and_null_params_are_checked() {
    let api = api();
    for method in [
        "client_config",
        "invite_code",
        "federation_id",
        "server_config_consensus_hash",
        "version",
        "fedimintd_version",
    ] {
        assert_eq!(
            api.dispatch(method, &json!([])),
            Err(ConfigApiError::InvalidParams)
        );
    }
    for method in ["chain_id", "api_announcements", "unknown"] {
        assert_eq!(
            api.dispatch(method, &json!(null)),
            Err(ConfigApiError::MethodNotFound)
        );
    }
    let server = server();
    assert!(matches!(
        ConfigApi::new(
            server.clone(),
            PeerId(1),
            None,
            "build".into(),
            support(&server)
        ),
        Err(ConfigApiError::InvalidConfiguration)
    ));
    let mut summary = support(&server);
    summary.modules = BTreeMap::new();
    assert!(matches!(
        ConfigApi::new(server.clone(), PeerId(0), None, "build".into(), summary),
        Err(ConfigApiError::InvalidConfiguration)
    ));
    let mut summary = support(&server);
    summary
        .modules
        .get_mut(&ModuleId(42))
        .unwrap()
        .module_consensus
        .minor += 1;
    assert!(matches!(
        ConfigApi::new(server.clone(), PeerId(0), None, "build".into(), summary),
        Err(ConfigApiError::InvalidConfiguration)
    ));
}

fn captured_client() -> config::RawClientConfig {
    use sonic_rs::JsonContainerTrait;
    let native: Value = sonic_rs::from_slice(include_bytes!(
        "fixtures/interop/mixed-failure-2026-09-10/peer0-client_config.json"
    ))
    .unwrap();
    let mut client = server().client_config();
    client.api_endpoints = native["api_endpoints"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, v)| {
            (
                PeerId(id.parse().unwrap()),
                config::Endpoint {
                    url: config::CanonicalUrl::simple(v["url"].as_str().unwrap()).unwrap(),
                    name: v["name"].as_str().unwrap().into(),
                },
            )
        })
        .collect();
    client.broadcast_public_keys = Some(
        native["broadcast_public_keys"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(id, key)| {
                (
                    PeerId(id.parse().unwrap()),
                    hex_decode(key.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            })
            .collect(),
    );
    client.consensus_version = Version {
        major: native["consensus_version"]["major"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
        minor: native["consensus_version"]["minor"]
            .as_u64()
            .unwrap()
            .try_into()
            .unwrap(),
    };
    client.meta = native["meta"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.into(), value.as_str().unwrap().into()))
        .collect();
    client.modules = native["modules"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, module)| {
            (
                ModuleId(id.parse().unwrap()),
                config::ClientModuleConfig::from_config_hex(
                    module["kind"].as_str().unwrap().into(),
                    Version {
                        major: module["version"]["major"]
                            .as_u64()
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        minor: module["version"]["minor"]
                            .as_u64()
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    },
                    module["config"].as_str().unwrap(),
                )
                .unwrap(),
            )
        })
        .collect();
    assert_eq!(client_config_value(&client).unwrap(), native);
    client
}

#[test]
fn diagnostic_matches_entire_paired_reference_capture() {
    let reference: Value = sonic_rs::from_slice(include_bytes!(
        "fixtures/interop/reference-api-2026-09-10/peer2-client_config_json-None.json"
    ))
    .unwrap();
    assert_eq!(
        minimint_ng::api::config::diagnostic_client_config_value(&captured_client()).unwrap(),
        reference["result"]
    );
}

#[test]
fn diagnostic_preserves_ids_and_u64_and_rejects_only_unsupported_diagnostic() {
    use minimint_ng::{api::config::diagnostic_client_config_value, codec::ConsensusEncode};
    let mut client = captured_client();
    let mut mint = client.modules.remove(&ModuleId(0)).unwrap();
    mint.config.module_id = ModuleId(300);
    let mut payload: config::RawMintConfig = decode_whole(&mint.config.payload).unwrap();
    payload.amount_unit = u64::MAX;
    payload.fee.base = u64::MAX;
    mint.config.payload = payload.consensus_encode();
    client.modules.insert(ModuleId(300), mint);
    let diagnostic = diagnostic_client_config_value(&client).unwrap();
    assert_eq!(
        diagnostic["modules"]["300"]["amount_unit"].as_u64(),
        Some(u64::MAX)
    );
    assert_eq!(
        diagnostic["modules"]["300"]["fee_consensus"]["base"].as_u64(),
        Some(u64::MAX)
    );
    client.modules.get_mut(&ModuleId(300)).unwrap().kind = "unknown".into();
    assert_eq!(
        diagnostic_client_config_value(&client),
        Err(ConfigApiError::InvalidConfiguration)
    );
    assert!(client_config_value(&client).is_ok());
    assert_eq!(
        api().dispatch("client_config_json", &json!(null)),
        Err(ConfigApiError::InvalidConfiguration)
    );
    assert_eq!(
        api().dispatch("client_config_json", &json!([])),
        Err(ConfigApiError::InvalidParams)
    );
    assert!(api().dispatch("client_config", &json!(null)).is_ok());
}
#[test]
fn broadcast_keys_are_compressed_hex_and_iroh_is_excluded_from_legacy_hash() {
    let mut server = server();
    let key = minimint_ng::crypto::secp::SecretKey::from_bytes(&[1; 32])
        .unwrap()
        .public_key();
    server.broadcast_public_keys.insert(PeerId(0), key);
    let legacy = server.legacy_server_consensus_hash();
    server.iroh_endpoints.insert(
        PeerId(0),
        config::IrohEndpoint {
            name: "Guardian 0".into(),
            api_key: [1; 32],
            p2p_key: [2; 32],
        },
    );
    let api = ConfigApi::new(
        server.clone(),
        PeerId(0),
        None,
        "build".into(),
        support(&server),
    )
    .unwrap();
    assert_eq!(
        api.dispatch("server_config_consensus_hash", &json!(null))
            .unwrap(),
        json!(hex_encode(&legacy))
    );
    assert_eq!(
        api.dispatch("client_config", &json!(null)).unwrap()["broadcast_public_keys"]["0"],
        json!(hex_encode(&key))
    );
}
