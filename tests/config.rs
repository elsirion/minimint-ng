use minimint_ng::{
    codec::{
        ConsensusEncode, decode_whole,
        text::{hex_decode, hex_encode},
    },
    config::*,
    protocol::{ModuleId, PeerId, Version},
};
use std::collections::BTreeMap;

#[test]
fn supplied_endpoint_identity_and_invite() {
    let endpoints = BTreeMap::from([(
        PeerId(0),
        Endpoint {
            url: CanonicalUrl::simple("wss://example.com/").unwrap(),
            name: "Guardian 0".into(),
        },
    )]);
    assert_eq!(
        hex_encode(&endpoints.consensus_encode()),
        "0100127773733a2f2f6578616d706c652e636f6d2f0a477561726469616e2030"
    );
    let id = federation_id(&endpoints);
    assert_eq!(
        hex_encode(&id),
        "45dce366c5a92ab6a589b79ad5a7411c4b7df0b61bc08e5d3fdc946c3086d6f7"
    );
    let invite = Invite::compact(&endpoints, id, None).unwrap();
    let expected = "fed11qgqpgynhwden5te0v4uxzmtsd3jjucm0d5hsqqfqghwwxek94y4tdfvfk7ddtf6pr39hmu9kr0qguhflmj2xcvyx6mmsjtre29";
    assert_eq!(invite.to_bech32m(), expected);
    assert_eq!(Invite::from_text(expected).unwrap(), invite);
    assert_eq!(
        Invite::from_text(&invite.to_base32().to_uppercase()).unwrap(),
        invite
    );
}
#[test]
fn module_instance_is_nested_in_client_but_not_server() {
    let value = ClientModuleConfig {
        kind: "mintv2".into(),
        version: Version { major: 1, minor: 0 },
        config: minimint_ng::protocol::DynamicValue {
            module_id: ModuleId(42),
            payload: vec![9],
        },
    };
    assert_eq!(
        hex_encode(&value.consensus_encode()),
        "066d696e74763201002a0109"
    );
    assert_eq!(
        decode_whole::<ClientModuleConfig>(&value.consensus_encode()),
        Ok(value)
    );
    let server = ServerModuleConfig {
        kind: "mintv2".into(),
        version: Version { major: 1, minor: 0 },
        config: vec![9],
    };
    assert_eq!(
        hex_encode(&server.consensus_encode()),
        "066d696e74763201000109"
    );
}

fn setup(name: &str) -> SetupRecord {
    SetupRecord {
        name: name.into(),
        endpoints: SetupEndpoints::Tcp {
            api_url: CanonicalUrl::simple("ws://localhost:8174/").unwrap(),
            p2p_url: CanonicalUrl::simple("fedimint://localhost:8173/").unwrap(),
            certificate: vec![1, 2],
        },
        federation_name: None,
        disable_base_fees: None,
        enabled_modules: None,
        federation_size: None,
        network: BitcoinNetwork::Regtest,
        release: "0.13.0-local+source".into(),
    }
}
#[test]
fn typed_setup_order_release_network_and_roundtrip() {
    assert_eq!(normalize_release("0.13.0-rc1+source"), "0.13.0");
    assert_eq!(normalize_release("0.13.0+source-rc1"), "0.13.0");
    let a = setup("Z");
    let b = setup("AA");
    assert!(a.consensus_encode() < b.consensus_encode());
    let assigned = assign_peer_ids([a.clone(), b]).unwrap();
    assert_eq!(assigned[&PeerId(0)].name, "AA");
    assert_eq!(
        SetupRecord::from_code(&a.to_code().to_uppercase()).unwrap(),
        a
    );
    assert_eq!(
        BitcoinNetwork::Regtest.consensus_encode(),
        hex_decode("fabfb5da").unwrap()
    );
    assert!(BitcoinNetwork::Mainnet < BitcoinNetwork::Testnet3);
    assert!(decode_whole::<BitcoinNetwork>(&[0; 4]).is_err());
    assert!(decode_whole::<SetupEndpoints>(&[1, 0]).is_err());
    let mut invalid = a.clone();
    invalid.federation_name = Some("name".into());
    assert!(invalid.validate_local_parameters().is_err());
    invalid.federation_size = Some(4);
    assert!(invalid.validate_local_parameters().is_ok());
}
#[test]
fn invite_duplicate_precedence_unknown_and_required_fields() {
    let url = CanonicalUrl::simple("ws://localhost/").unwrap();
    let later = CanonicalUrl::simple("ws://localhost:9000/").unwrap();
    let invite = Invite::new(vec![
        InviteRecord::Endpoint {
            url,
            peer: PeerId(7),
        },
        InviteRecord::FederationId([1; 32]),
        InviteRecord::ApiSecret("first".into()),
        InviteRecord::Unknown {
            tag: 99,
            payload: vec![1],
        },
        InviteRecord::Endpoint {
            url: later.clone(),
            peer: PeerId(7),
        },
        InviteRecord::FederationId([2; 32]),
        InviteRecord::ApiSecret("second".into()),
    ])
    .unwrap();
    assert_eq!(invite.federation_id(), [1; 32]);
    assert_eq!(invite.api_secret(), Some("first"));
    assert_eq!(invite.endpoints()[&PeerId(7)], later);
    assert_eq!(
        decode_whole::<Invite>(&invite.consensus_encode()).unwrap(),
        invite
    );
    assert!(!format!("{invite:?}").contains("first"));
    assert!(decode_whole::<Invite>(&[0]).is_err());
    let mut trailing = invite.consensus_encode();
    trailing.push(0);
    assert!(decode_whole::<Invite>(&trailing).is_err());
    let mut corrupt = invite.to_bech32m().into_bytes();
    *corrupt.last_mut().unwrap() = b'!';
    assert!(Invite::from_text(std::str::from_utf8(&corrupt).unwrap()).is_err());
}
#[test]
fn simple_url_scope_is_explicit() {
    for input in [
        "wss://EXAMPLE.com/",
        "wss://example.com:443/",
        "wss://u:p@example.com/",
        "wss://example.com/?q=1",
        "wss://example.com/a/../b",
        "ws://127.1/",
        "ws://example.com/%41",
    ] {
        assert!(CanonicalUrl::simple(input).is_err(), "{input}");
    }
    assert!(CanonicalUrl::simple("ws://127.0.0.1:8174/").is_ok());
}
#[test]
fn module_config_units_and_wallet_sizes() {
    let mint = RawMintConfig {
        aggregate_keys: BTreeMap::new(),
        public_shares: BTreeMap::new(),
        fee: Fee {
            base: 100,
            parts_per_million: 0,
        },
        amount_unit: 0,
    };
    assert_eq!(mint.consensus_encode(), [0, 0, 100, 0, 0]);
    let wallet = RawWalletConfig {
        bitcoin_pks: BTreeMap::new(),
        descriptor: DescriptorKind::Wsh,
        send_tx_vbytes: 228,
        receive_tx_vbytes: 316,
        feerate_base: 250,
        dust_limit: 10000,
        fee_consensus: Fee {
            base: 100000,
            parts_per_million: 0,
        },
        network: BitcoinNetwork::Regtest,
    };
    assert_eq!(
        hex_encode(&wallet.consensus_encode()),
        "000000e4fd013cfafd2710fe000186a000fabfb5da"
    );
    assert_eq!(
        decode_whole::<RawWalletConfig>(&wallet.consensus_encode()).unwrap(),
        wallet
    );
    assert_eq!(wallet_vbytes(4).unwrap(), (228, 316));
    assert_eq!(wallet_vbytes(1).unwrap(), (166, 192));
    assert!(Fee::wallet(0, 10001).is_err());
    assert!(Fee::wallet(0, 10000).is_ok());
    assert!(Fee::mint(0, 1000).is_ok());
    assert!(Fee::mint(0, 1001).is_err());
}
#[test]
fn binary_versions_preserve_order_json_boundary_rejects_it() {
    let api = decode_whole::<ApiVersions>(&[2, 1, 0, 0, 9]).unwrap();
    assert!(api.validate().is_err());
    let peer = CoreSupport {
        core_consensus: Version {
            major: 2,
            minor: 99,
        },
        api: ApiVersions {
            versions: vec![CORE_API],
        },
    };
    assert!(peer.compatible(CORE_CONSENSUS, Version { major: 0, minor: 5 }));
    assert!(!peer.compatible(
        Version { major: 3, minor: 0 },
        Version { major: 0, minor: 5 }
    ));
}

#[test]
fn independent_four_commitment_layouts() {
    // Literal fields independently assembled with Python hashlib; saved fixture
    // explicitly is not a valid module configuration or upstream checksum vector.
    let server = RawServerConfig {
        code_release: "0.13.0".into(),
        consensus_version: CORE_CONSENSUS,
        broadcast_public_keys: BTreeMap::new(),
        rounds_per_session: 3600,
        api_endpoints: BTreeMap::from([(
            PeerId(0),
            Endpoint {
                url: CanonicalUrl::simple("wss://example.com/").unwrap(),
                name: "Guardian 0".into(),
            },
        )]),
        iroh_endpoints: BTreeMap::new(),
        tls_certificates: BTreeMap::new(),
        modules: BTreeMap::from([(
            ModuleId(42),
            ServerModuleConfig {
                kind: "mintv2".into(),
                version: MODULE_CONSENSUS,
                config: vec![9],
            },
        )]),
        meta: BTreeMap::new(),
    };
    assert_eq!(
        hex_encode(&server.consensus_encode()),
        "06302e31332e30020100fd0e100100127773733a2f2f6578616d706c652e636f6d2f0a477561726469616e20300000012a066d696e7476320100010900"
    );
    assert_eq!(
        hex_encode(&server.consensus_hash()),
        "77b434dc04bf3b7c84a45bffc558aa654144c12a29a66d6905586a538b403c75"
    );
    assert_eq!(
        hex_encode(&server.legacy_server_consensus_hash()),
        "d33d34ac8f34acf12a4916e291aa7f3eaf9bf677f6e675897c7781d577eb5b8c"
    );
    let mut changed = server.clone();
    changed.code_release = "0.13.0-local+build".into();
    changed.iroh_endpoints.insert(
        PeerId(0),
        IrohEndpoint {
            name: "unused".into(),
            api_key: [1; 32],
            p2p_key: [2; 32],
        },
    );
    assert_eq!(
        changed.legacy_server_consensus_hash(),
        server.legacy_server_consensus_hash()
    );
    assert_ne!(changed.consensus_hash(), server.consensus_hash());
    let mut client = server.client_config();
    assert_eq!(
        hex_encode(&client.full_hash()),
        "8202d48bf2ba491780ae8f609d1b4c59da6b59d8ef853ae71b225ecc9a8fe089"
    );
    assert_eq!(
        hex_encode(&client.federation_id()),
        "45dce366c5a92ab6a589b79ad5a7411c4b7df0b61bc08e5d3fdc946c3086d6f7"
    );
    assert!(client.check_module_routing().is_ok());
    client
        .modules
        .get_mut(&ModuleId(42))
        .unwrap()
        .config
        .module_id = ModuleId(0);
    assert!(client.check_module_routing().is_err());
    assert_ne!(client.full_hash(), server.client_config().full_hash());
    assert_eq!(
        client.federation_id(),
        server.client_config().federation_id()
    );
}

#[test]
fn legacy_bech32_checksum_and_case_rules() {
    let legacy = "fed11qgqpgynhwden5te0v4uxzmtsd3jjucm0d5hsqqfqghwwxek94y4tdfvfk7ddtf6pr39hmu9kr0qguhflmj2xcvyx6mms8hn408";
    let parsed = Invite::from_text(legacy).unwrap();
    assert_eq!(Invite::from_text(&legacy.to_uppercase()).unwrap(), parsed);
    assert!(Invite::from_text(&legacy.replacen("fed", "Fed", 1)).is_err());
    assert!(Invite::from_text(&legacy.replacen("fed11", "btc11", 1)).is_err());
}
#[test]
fn setup_global_optional_fields_are_unique_even_when_equal() {
    let mut local = setup("Alice");
    local.federation_name = Some("test".into());
    local.federation_size = Some(4);
    let mut peers = assign_peer_ids([local, setup("Bob"), setup("Carol"), setup("Dave")]).unwrap();
    assert!(validate_setup_set(&peers).is_ok());
    peers.get_mut(&PeerId(1)).unwrap().federation_size = Some(4);
    assert!(validate_setup_set(&peers).is_err());
    peers.get_mut(&PeerId(1)).unwrap().federation_size = None;
    peers.get_mut(&PeerId(1)).unwrap().release = "0.14.0".into();
    assert!(validate_setup_set(&peers).is_err());
    assert!(validate_setup_set(&assign_peer_ids([setup("A"), setup("B")]).unwrap()).is_err());
}
#[test]
fn public_config_parsers_do_not_accept_invalid_points() {
    let mut mint = RawMintConfig {
        aggregate_keys: BTreeMap::from([(0, [0; 96])]),
        public_shares: BTreeMap::new(),
        fee: Fee {
            base: 0,
            parts_per_million: 0,
        },
        amount_unit: 0,
    };
    assert!(mint.check_public_points().is_err());
    mint.aggregate_keys
        .insert(0, minimint_ng::crypto::bls::G2::identity().to_bytes());
    assert!(mint.check_public_points().is_ok());
    mint.amount_unit = 1;
    assert!(mint.check_public_points().is_err());
}

#[test]
fn raw_profile_checks_route_by_kind_with_arbitrary_instances() {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    let key = minimint_ng::crypto::secp::SecretKey::from_bytes(&scalar)
        .unwrap()
        .public_key();
    let keys = (0..4)
        .map(|id| (PeerId(id), key))
        .collect::<BTreeMap<_, _>>();
    let mint = RawMintConfig {
        aggregate_keys: BTreeMap::new(),
        public_shares: BTreeMap::new(),
        fee: Fee {
            base: 0,
            parts_per_million: 0,
        },
        amount_unit: 0,
    };
    let wallet = RawWalletConfig {
        bitcoin_pks: keys.clone(),
        descriptor: DescriptorKind::Wsh,
        send_tx_vbytes: 228,
        receive_tx_vbytes: 316,
        feerate_base: 250,
        dust_limit: 10000,
        fee_consensus: Fee {
            base: 100000,
            parts_per_million: 0,
        },
        network: BitcoinNetwork::Regtest,
    };
    let mut server = RawServerConfig {
        code_release: "0.13.0".into(),
        consensus_version: CORE_CONSENSUS,
        broadcast_public_keys: keys,
        rounds_per_session: 3600,
        api_endpoints: (0..4)
            .map(|id| {
                (
                    PeerId(id),
                    Endpoint {
                        url: CanonicalUrl::simple(&format!("ws://localhost:{}/", 9000 + id))
                            .unwrap(),
                        name: format!("peer {id}"),
                    },
                )
            })
            .collect(),
        iroh_endpoints: BTreeMap::new(),
        tls_certificates: (0..4).map(|id| (PeerId(id), "0102".into())).collect(),
        modules: BTreeMap::from([
            (
                ModuleId(42),
                ServerModuleConfig {
                    kind: "mintv2".into(),
                    version: MODULE_CONSENSUS,
                    config: mint.consensus_encode(),
                },
            ),
            (
                ModuleId(99),
                ServerModuleConfig {
                    kind: "walletv2".into(),
                    version: MODULE_CONSENSUS,
                    config: wallet.consensus_encode(),
                },
            ),
        ]),
        meta: BTreeMap::new(),
    };
    // Structural public check is intentionally insufficient for startup: this
    // fixture has no Mint local shares and no valid transport certificates.
    assert!(server.check_two_module_profile().is_ok());
    assert!(server.client_config().check_module_routing().is_ok());
    server.modules.get_mut(&ModuleId(42)).unwrap().kind = "walletv2".into();
    assert!(server.check_two_module_profile().is_err());
    server.modules.get_mut(&ModuleId(42)).unwrap().kind = "mintv2".into();
    server
        .modules
        .get_mut(&ModuleId(99))
        .unwrap()
        .config
        .push(0);
    assert!(server.check_two_module_profile().is_err());
}

#[test]
fn direct_module_json_hex_has_no_rpc_wrapper() {
    let module =
        ClientModuleConfig::from_config_hex("mintv2".into(), MODULE_CONSENSUS, "2a0109").unwrap();
    assert_eq!(module.config.module_id, ModuleId(42));
    assert_eq!(module.config.payload, [9]);
    assert_eq!(module.config_hex(), "2a0109");
    assert!(
        ClientModuleConfig::from_config_hex("mintv2".into(), MODULE_CONSENSUS, "2a010900").is_err()
    );
}
