use minimint_ng::{
    codec::{ConsensusEncode, decode_whole, text::hex_encode},
    config::{
        self, BitcoinNetwork, CanonicalUrl, DescriptorKind, Endpoint, Fee, RawMintConfig,
        RawServerConfig, RawWalletConfig, ServerModuleConfig, SetupEndpoints, SetupRecord,
    },
    crypto::{
        bls::{G2, Scalar},
        secp::SecretKey,
    },
    daemon::config::{RuntimeConfig, RuntimeConfigError},
    net::{envelope::Envelope, tls::Identity},
    protocol::{ModuleId, PeerId},
    setup::{self, GeneratedConfig, GeneratedSecrets, PersistedSetup},
    storage::Store,
};
use std::collections::BTreeMap;
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn key(byte: u8) -> SecretKey {
    SecretKey::from_bytes(&[byte; 32]).unwrap()
}
fn url(text: &str) -> CanonicalUrl {
    CanonicalUrl::simple(text).unwrap()
}
// Typed configuration fixture. Constant Mint share polynomials are valid local
// share correspondence fixtures, not a claim of running fresh random DKG here.
fn persisted(n: u16) -> PersistedSetup {
    let identities: Vec<_> = (0..n)
        .map(|peer| Identity::generate(&format!("Guardian {peer:02}")).unwrap())
        .collect();
    let mut endpoints = BTreeMap::new();
    let mut certificates = BTreeMap::new();
    let mut records = BTreeMap::new();
    for peer in 0..n {
        let id = PeerId(peer);
        let name = format!("Guardian {peer:02}");
        let api_url = url(&format!("ws://127.0.0.1:{}/", 10000 + peer));
        let certificate = identities[peer as usize].certificate_der().unwrap();
        endpoints.insert(
            id,
            Endpoint {
                url: api_url.clone(),
                name: name.clone(),
            },
        );
        certificates.insert(id, hex_encode(&certificate));
        records.insert(
            id,
            SetupRecord {
                name,
                endpoints: SetupEndpoints::Tcp {
                    api_url,
                    p2p_url: url(&format!("fedimint://127.0.0.1:{}/", 9000 + peer)),
                    certificate,
                },
                federation_name: (peer == 0).then(|| "Federation".into()),
                disable_base_fees: None,
                enabled_modules: None,
                federation_size: (peer == 0).then_some(u32::from(n)),
                network: BitcoinNetwork::Regtest,
                release: "0.13.0-test".into(),
            },
        );
    }
    let point = G2::generator().to_bytes();
    let mint = RawMintConfig {
        aggregate_keys: (0..42).map(|d| (d, point)).collect(),
        public_shares: (0..42)
            .map(|d| (d, (0..n).map(|peer| (PeerId(peer), point)).collect()))
            .collect(),
        fee: Fee::mint(100, 0).unwrap(),
        amount_unit: 0,
    };
    let wallet = RawWalletConfig {
        bitcoin_pks: (0..n)
            .map(|peer| (PeerId(peer), key(peer as u8 + 101).public_key()))
            .collect(),
        descriptor: DescriptorKind::Wsh,
        send_tx_vbytes: 228,
        receive_tx_vbytes: 316,
        feerate_base: 250,
        dust_limit: 10000,
        fee_consensus: Fee::wallet(100000, 0).unwrap(),
        network: BitcoinNetwork::Regtest,
    };
    let server = RawServerConfig {
        code_release: "0.13.0".into(),
        consensus_version: config::CORE_CONSENSUS,
        broadcast_public_keys: (0..n)
            .map(|peer| (PeerId(peer), key(peer as u8 + 1).public_key()))
            .collect(),
        rounds_per_session: 3600,
        api_endpoints: endpoints,
        iroh_endpoints: BTreeMap::new(),
        tls_certificates: certificates,
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
                    config: wallet.consensus_encode(),
                },
            ),
        ]),
        meta: BTreeMap::from([("federation_name".into(), "Federation".into())]),
    };
    PersistedSetup {
        generated: GeneratedConfig {
            server,
            setup_records: records,
            peer: PeerId(0),
            secrets: GeneratedSecrets {
                broadcast: key(1),
                wallet: key(101),
                mint: (0..42).map(|d| (d, Scalar::from_u64(1))).collect(),
            },
        },
        identity: identities.into_iter().next().unwrap(),
    }
}
fn reject(value: PersistedSetup, expected: RuntimeConfigError) {
    assert!(matches!(RuntimeConfig::from_persisted(value),Err(error) if error==expected));
}
#[test]
fn four_guardian_profile_constructs_closed_modules_tls_and_protected_session_factory() {
    let value = persisted(4);
    let expected = value.generated.server.clone();
    let runtime = RuntimeConfig::from_persisted(value).unwrap();
    assert_eq!(runtime.peer(), PeerId(0));
    assert_eq!(runtime.server_config(), &expected);
    assert_eq!(runtime.modules().mint().instance(), ModuleId(0));
    assert_eq!(runtime.modules().wallet().module_id(), ModuleId(1));
    let session = runtime.session_config().unwrap();
    assert_eq!(
        session.local_key.public_key(),
        expected.broadcast_public_keys[&PeerId(0)]
    );
    assert_eq!(session.version, config::CORE_CONSENSUS);
    assert_eq!(session.rounds, 3600);
    assert_eq!(
        runtime.session_config().unwrap().local_key.public_key(),
        session.local_key.public_key()
    );
    let _tls = runtime.tls_config();
    let resolved = runtime.resolve_peer_addresses().unwrap();
    assert_eq!(resolved.len(), 3);
    assert!(!resolved.contains_key(&PeerId(0)));
    assert_eq!(resolved[&PeerId(1)], "127.0.0.1:9001".parse().unwrap());
    // An independently chosen listener binding need not equal the advertised URL.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    assert_ne!(listener.local_addr().unwrap().port(), 9000);
}
struct NoTransport;
impl setup::SetupTransport for NoTransport {
    fn wait_for_all(&mut self, _: &[PeerId]) -> Result<(), setup::SetupError> {
        panic!("single guardian transport")
    }
    fn send(&mut self, _: PeerId, _: Envelope) -> Result<(), setup::SetupError> {
        panic!("single guardian transport")
    }
    fn receive_from(&mut self, _: PeerId) -> Result<Envelope, setup::SetupError> {
        panic!("single guardian transport")
    }
}
#[test]
fn actual_single_guardian_generated_and_persisted_configuration_starts_without_dns() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut state = setup::SetupState::new(
        url("ws://localhost:8000/"),
        url("fedimint://unresolved.invalid:9000/"),
        BitcoinNetwork::Regtest,
        "0.13.0-test".into(),
    );
    state
        .set_local_params(setup::LocalParams {
            name: "Solo".into(),
            federation_name: Some("Solo Federation".into()),
            disable_base_fees: None,
            enabled_modules: None,
            federation_size: Some(1),
        })
        .unwrap();
    let inputs = state.generation_inputs().unwrap();
    let generated = setup::generate(
        inputs.peer,
        &inputs.records,
        &setup::SetupDefaults::default(),
        &mut NoTransport,
    )
    .unwrap();
    setup::persist_generated(&store, &generated, state.identity().unwrap()).unwrap();
    let runtime =
        RuntimeConfig::from_persisted(setup::load_generated(&store).unwrap().unwrap()).unwrap();
    assert!(runtime.remote_peer_urls().is_empty());
    assert!(runtime.resolve_peer_addresses().unwrap().is_empty());
    assert_eq!(runtime.session_config().unwrap().broadcast_keys.len(), 1);
}
#[test]
fn arbitrary_module_ids_are_routed_by_kind_without_extra_mint_aggregate_predicates() {
    let mut value = persisted(4);
    let mut mint = value.generated.server.modules.remove(&ModuleId(0)).unwrap();
    let mut raw: RawMintConfig = decode_whole(&mint.config).unwrap();
    // MINT012 checks local private shares; neither aggregate reconstruction nor
    // equality of remote-share maps is an additional configuration predicate.
    raw.aggregate_keys
        .insert(0, G2::generator().mul(&Scalar::from_u64(7)).to_bytes());
    raw.public_shares.get_mut(&0).unwrap().remove(&PeerId(1));
    mint.config = raw.consensus_encode();
    let wallet = value.generated.server.modules.remove(&ModuleId(1)).unwrap();
    value.generated.server.modules.insert(ModuleId(300), mint);
    value.generated.server.modules.insert(ModuleId(7), wallet);
    let runtime = RuntimeConfig::from_persisted(value).unwrap();
    assert_eq!(runtime.modules().mint().instance(), ModuleId(300));
    assert_eq!(runtime.modules().wallet().module_id(), ModuleId(7));
}
#[test]
fn unsupported_peer_counts_versions_kinds_and_round_width_fail_before_construction() {
    for n in [2, 3, 21] {
        reject(persisted(n), RuntimeConfigError::UnsupportedProfile);
    }
    let mut value = persisted(1);
    value.generated.server.consensus_version.minor += 1;
    reject(value, RuntimeConfigError::UnsupportedProfile);
    let mut value = persisted(1);
    value.generated.server.code_release = "0.13.0-test".into();
    reject(value, RuntimeConfigError::UnsupportedProfile);
    let mut value = persisted(1);
    value
        .generated
        .server
        .modules
        .get_mut(&ModuleId(1))
        .unwrap()
        .kind = "mintv2".into();
    reject(value, RuntimeConfigError::UnsupportedProfile);
    let mut value = persisted(1);
    value
        .generated
        .server
        .modules
        .get_mut(&ModuleId(0))
        .unwrap()
        .version
        .major += 1;
    reject(value, RuntimeConfigError::UnsupportedProfile);
    for rounds in [0, 64536] {
        let mut value = persisted(1);
        value.generated.server.rounds_per_session = rounds;
        reject(value, RuntimeConfigError::UnsupportedProfile);
    }
    let mut value = persisted(1);
    value.generated.server.rounds_per_session = 64535;
    RuntimeConfig::from_persisted(value).unwrap();
}
#[test]
fn core_peer_maps_and_private_key_correspondence_are_checked() {
    let mut value = persisted(4);
    value
        .generated
        .server
        .broadcast_public_keys
        .remove(&PeerId(1));
    reject(value, RuntimeConfigError::InvalidPeers);
    let mut value = persisted(4);
    value
        .generated
        .server
        .broadcast_public_keys
        .insert(PeerId(1), [0; 33]);
    reject(value, RuntimeConfigError::InvalidKeys);
    let mut value = persisted(1);
    value.generated.secrets.broadcast = key(5);
    reject(value, RuntimeConfigError::InvalidKeys);
    let mut value = persisted(1);
    value.generated.secrets.wallet = key(5);
    reject(value, RuntimeConfigError::InvalidModule);
    let mut value = persisted(1);
    value.generated.secrets.mint.remove(&0);
    reject(value, RuntimeConfigError::InvalidModule);
    let mut value = persisted(1);
    value.generated.secrets.mint.insert(0, Scalar::from_u64(2));
    reject(value, RuntimeConfigError::InvalidModule);
}
#[test]
fn wallet_membership_network_and_exact_payload_are_checked() {
    for mutation in 0..3 {
        let mut value = persisted(4);
        let module = value
            .generated
            .server
            .modules
            .get_mut(&ModuleId(1))
            .unwrap();
        let mut raw: RawWalletConfig = decode_whole(&module.config).unwrap();
        match mutation {
            0 => {
                raw.bitcoin_pks.remove(&PeerId(3));
            }
            1 => raw.network = BitcoinNetwork::Mainnet,
            _ => {}
        }
        module.config = raw.consensus_encode();
        if mutation == 2 {
            module.config.push(0);
        }
        reject(value, RuntimeConfigError::InvalidModule);
    }
}
#[test]
fn tls_identity_and_retained_public_binding_fail_closed() {
    let mut value = persisted(1);
    value.identity = Identity::generate("other").unwrap();
    reject(value, RuntimeConfigError::InvalidTls);
    let mut value = persisted(4);
    value
        .generated
        .server
        .api_endpoints
        .get_mut(&PeerId(1))
        .unwrap()
        .name = "other".into();
    reject(value, RuntimeConfigError::InvalidPeers);
    let mut value = persisted(4);
    let SetupEndpoints::Tcp { certificate, .. } = &mut value
        .generated
        .setup_records
        .get_mut(&PeerId(1))
        .unwrap()
        .endpoints
    else {
        unreachable!()
    };
    *certificate = vec![0];
    value
        .generated
        .server
        .tls_certificates
        .insert(PeerId(1), "00".into());
    reject(value, RuntimeConfigError::InvalidTls);
    let mut value = persisted(1);
    value
        .generated
        .server
        .meta
        .insert("federation_name".into(), "other".into());
    reject(value, RuntimeConfigError::UnsupportedProfile);
}
#[test]
fn tcp_scheme_root_path_explicit_port_and_dns_separation_are_checked() {
    for endpoint in [
        "ws://127.0.0.1:9000/",
        "tcp://127.0.0.1:9000/",
        "fedimint://127.0.0.1/",
        "fedimint://127.0.0.1:9000/path/",
    ] {
        let mut value = persisted(1);
        let SetupEndpoints::Tcp { p2p_url, .. } = &mut value
            .generated
            .setup_records
            .get_mut(&PeerId(0))
            .unwrap()
            .endpoints
        else {
            unreachable!()
        };
        *p2p_url = url(endpoint);
        reject(value, RuntimeConfigError::InvalidEndpoint);
    }
    let mut value = persisted(4);
    let SetupEndpoints::Tcp { p2p_url, .. } = &mut value
        .generated
        .setup_records
        .get_mut(&PeerId(1))
        .unwrap()
        .endpoints
    else {
        unreachable!()
    };
    *p2p_url = url("fedimint://unresolved.invalid:9001/");
    let runtime = RuntimeConfig::from_persisted(value).unwrap();
    assert_eq!(
        runtime.remote_peer_urls()[&PeerId(1)].as_str(),
        "fedimint://unresolved.invalid:9001/"
    );
    // No DNS call here: the explicit resolution method belongs to the driver.
}
