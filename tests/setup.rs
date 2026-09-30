use minimint_ng::{
    codec::{ConsensusEncode, decode_whole},
    config::{
        self, BitcoinNetwork, CanonicalUrl, RawMintConfig, RawWalletConfig, SetupEndpoints,
        SetupRecord,
    },
    net::envelope::{DkgMessage, Envelope},
    protocol::{ModuleId, PeerId},
    setup::*,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Checksum,
    Exchange,
    Hash,
    Commitments,
    Share,
}
struct MemoryTransport {
    local: PeerId,
    senders: BTreeMap<PeerId, mpsc::Sender<Envelope>>,
    receivers: BTreeMap<PeerId, mpsc::Receiver<Envelope>>,
    trace: Arc<Mutex<Vec<(PeerId, PeerId, Kind)>>>,
}
impl SetupTransport for MemoryTransport {
    fn wait_for_all(&mut self, peers: &[PeerId]) -> Result<(), SetupError> {
        if peers
            .iter()
            .all(|p| self.senders.contains_key(p) && self.receivers.contains_key(p))
        {
            Ok(())
        } else {
            Err(SetupError::Transport)
        }
    }
    fn send(&mut self, peer: PeerId, message: Envelope) -> Result<(), SetupError> {
        let kind = match &message {
            Envelope::Checksum(_) => Kind::Checksum,
            Envelope::SetupExchange(_) => Kind::Exchange,
            Envelope::DkgG2(DkgMessage::Hash(_)) => Kind::Hash,
            Envelope::DkgG2(DkgMessage::Commitments(_)) => Kind::Commitments,
            Envelope::DkgG2(DkgMessage::Share(_)) => Kind::Share,
            _ => return Err(SetupError::UnexpectedEnvelope),
        };
        self.trace.lock().unwrap().push((self.local, peer, kind));
        // Exercise actual legacy envelopes, including private scalar framing.
        let bytes =
            zeroize::Zeroizing::new(message.encode_legacy().map_err(|_| SetupError::Transport)?);
        let message = Envelope::decode(&bytes).map_err(|_| SetupError::Transport)?;
        self.senders
            .get(&peer)
            .ok_or(SetupError::UnknownPeer)?
            .send(message)
            .map_err(|_| SetupError::Transport)
    }
    fn receive_from(&mut self, peer: PeerId) -> Result<Envelope, SetupError> {
        // Harness-only deadline detects deadlocks; not a setup protocol timeout.
        self.receivers
            .get(&peer)
            .ok_or(SetupError::UnknownPeer)?
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| SetupError::Transport)
    }
}
fn transports(
    n: usize,
) -> (
    Vec<MemoryTransport>,
    Arc<Mutex<Vec<(PeerId, PeerId, Kind)>>>,
) {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut peers = (0..n)
        .map(|i| MemoryTransport {
            local: PeerId(i as u16),
            senders: BTreeMap::new(),
            receivers: BTreeMap::new(),
            trace: trace.clone(),
        })
        .collect::<Vec<_>>();
    for sender in 0..n {
        for receiver in 0..n {
            if sender != receiver {
                let (tx, rx) = mpsc::channel();
                peers[sender].senders.insert(PeerId(receiver as u16), tx);
                peers[receiver].receivers.insert(PeerId(sender as u16), rx);
            }
        }
    }
    (peers, trace)
}
fn records(n: u32) -> BTreeMap<PeerId, SetupRecord> {
    config::assign_peer_ids((0..n).map(|i| SetupRecord {
        name: format!("Guardian {i}"),
        endpoints: SetupEndpoints::Tcp {
            api_url: CanonicalUrl::simple(&format!("ws://localhost:{}/", 8000 + i)).unwrap(),
            p2p_url: CanonicalUrl::simple(&format!("fedimint://localhost:{}/", 9000 + i)).unwrap(),
            certificate: vec![i as u8 + 1],
        },
        federation_name: (i == 0).then(|| "test federation".into()),
        disable_base_fees: (i == 1).then_some(true),
        enabled_modules: None,
        federation_size: (i == 0).then_some(n),
        network: BitcoinNetwork::Regtest,
        release: format!("0.13.0-local{i}"),
    }))
    .unwrap()
}
#[test]
fn four_guardians_complete42_serial_dkgs_and_two_checksums() {
    let records = Arc::new(records(4));
    let (peers, trace) = transports(4);
    let results = std::thread::scope(|scope| {
        let joins = peers
            .into_iter()
            .map(|mut transport| {
                let records = records.clone();
                scope.spawn(move || {
                    generate(
                        transport.local,
                        &records,
                        &SetupDefaults::default(),
                        &mut transport,
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    let expected = results[0].server.clone();
    for generated in results {
        assert_eq!(generated.server, expected);
        assert_eq!(generated.server.rounds_per_session, 3600);
        assert_eq!(generated.server.code_release, "0.13.0");
        assert_eq!(
            generated.server.broadcast_public_keys[&generated.peer],
            generated.secrets.broadcast.public_key()
        );
        let mint: RawMintConfig =
            decode_whole(&generated.server.modules[&ModuleId(0)].config).unwrap();
        let wallet: RawWalletConfig =
            decode_whole(&generated.server.modules[&ModuleId(1)].config).unwrap();
        assert_eq!(mint.aggregate_keys.len(), 42);
        assert_eq!(mint.fee.base, 0);
        assert_eq!(wallet.fee_consensus.base, 100000);
        assert_eq!(
            (wallet.send_tx_vbytes, wallet.receive_tx_vbytes),
            (228, 316)
        );
        assert_ne!(
            generated.secrets.broadcast.public_key(),
            generated.secrets.wallet.public_key()
        );
        minimint_ng::modules::mint::Mint::new(
            ModuleId(0),
            generated.peer,
            mint,
            generated.secrets.mint,
        )
        .unwrap();
        minimint_ng::modules::wallet::Wallet::new(
            ModuleId(1),
            generated.peer,
            wallet,
            generated.secrets.wallet,
        )
        .unwrap();
    }
    let trace = trace.lock().unwrap();
    let mut schedule = vec![Kind::Checksum, Kind::Exchange];
    for _ in 0..42 {
        schedule.extend([Kind::Hash, Kind::Commitments, Kind::Share]);
    }
    schedule.extend([Kind::Exchange, Kind::Checksum]);
    for sender in 0..4 {
        for receiver in 0..4 {
            if sender != receiver {
                assert_eq!(
                    trace
                        .iter()
                        .filter(|(s, r, _)| *s == PeerId(sender) && *r == PeerId(receiver))
                        .map(|(_, _, kind)| *kind)
                        .collect::<Vec<_>>(),
                    schedule
                );
            }
        }
    }
    assert_eq!(trace.len(), 4 * 3 * 130);
}
struct NoTransport;
impl SetupTransport for NoTransport {
    fn wait_for_all(&mut self, _: &[PeerId]) -> Result<(), SetupError> {
        panic!("single guardian bypasses transport")
    }
    fn send(&mut self, _: PeerId, _: Envelope) -> Result<(), SetupError> {
        panic!("single guardian bypasses transport")
    }
    fn receive_from(&mut self, _: PeerId) -> Result<Envelope, SetupError> {
        panic!("single guardian bypasses transport")
    }
}
#[test]
fn single_guardian_uses_trusted_generation_without_messages() {
    let generated = generate(
        PeerId(0),
        &records(1),
        &SetupDefaults::default(),
        &mut NoTransport,
    )
    .unwrap();
    let mint: RawMintConfig = decode_whole(&generated.server.modules[&ModuleId(0)].config).unwrap();
    let wallet: RawWalletConfig =
        decode_whole(&generated.server.modules[&ModuleId(1)].config).unwrap();
    assert_eq!(mint.fee.base, 100);
    assert_eq!(
        (wallet.send_tx_vbytes, wallet.receive_tx_vbytes),
        (166, 192)
    );
    assert_eq!(generated.secrets.mint.len(), 42);
}
struct RejectTransport {
    reply: Option<Envelope>,
}
impl SetupTransport for RejectTransport {
    fn wait_for_all(&mut self, _: &[PeerId]) -> Result<(), SetupError> {
        Ok(())
    }
    fn send(&mut self, _: PeerId, _: Envelope) -> Result<(), SetupError> {
        Ok(())
    }
    fn receive_from(&mut self, _: PeerId) -> Result<Envelope, SetupError> {
        self.reply.take().ok_or(SetupError::Transport)
    }
}
#[test]
fn initial_checksum_wrong_envelope_and_shutdown_abort() {
    for (reply, error) in [
        (
            Some(Envelope::Checksum([0; 32])),
            SetupError::ChecksumMismatch,
        ),
        (
            Some(Envelope::SessionIndex(0)),
            SetupError::UnexpectedEnvelope,
        ),
        (None, SetupError::Transport),
    ] {
        let result = generate(
            PeerId(0),
            &records(4),
            &SetupDefaults::default(),
            &mut RejectTransport { reply },
        );
        assert!(matches!(result,Err(e)if e==error));
    }
}

#[test]
fn differing_implicit_fee_defaults_are_caught_by_final_checksum() {
    let mut records = records(4);
    for record in records.values_mut() {
        record.disable_base_fees = None;
    }
    let records = Arc::new(records);
    let (peers, _) = transports(4);
    let errors = std::thread::scope(|scope| {
        let joins = peers
            .into_iter()
            .map(|mut transport| {
                let records = records.clone();
                scope.spawn(move || {
                    let defaults = SetupDefaults {
                        disable_base_fees: transport.local == PeerId(0),
                        ..SetupDefaults::default()
                    };
                    generate(transport.local, &records, &defaults, &mut transport).err()
                })
            })
            .collect::<Vec<_>>();
        joins
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Vec<_>>()
    });
    // Once one guardian detects disagreement it closes its test channels; a
    // slower guardian may observe that shutdown while sending its checksum.
    assert!(errors.contains(&Some(SetupError::ChecksumMismatch)));
    assert!(errors.iter().all(|error| matches!(
        error,
        Some(SetupError::ChecksumMismatch | SetupError::Transport)
    )));
}
#[test]
fn dkg_wrong_envelope_and_invalid_exchanged_key_abort() {
    assert!(matches!(
        run_g2_dkg(
            PeerId(0),
            4,
            &mut RejectTransport {
                reply: Some(Envelope::SessionIndex(0))
            }
        ),
        Err(SetupError::UnexpectedEnvelope)
    ));
    struct Replies(std::collections::VecDeque<Envelope>);
    impl SetupTransport for Replies {
        fn wait_for_all(&mut self, _: &[PeerId]) -> Result<(), SetupError> {
            Ok(())
        }
        fn send(&mut self, _: PeerId, _: Envelope) -> Result<(), SetupError> {
            Ok(())
        }
        fn receive_from(&mut self, _: PeerId) -> Result<Envelope, SetupError> {
            self.0.pop_front().ok_or(SetupError::Transport)
        }
    }
    let records = records(4);
    let hash = config::setup_checksum(&records);
    let mut replies = Replies(
        [
            Envelope::Checksum(hash),
            Envelope::Checksum(hash),
            Envelope::Checksum(hash),
            Envelope::SetupExchange(vec![0; 33]),
        ]
        .into(),
    );
    assert!(matches!(
        generate(PeerId(0), &records, &SetupDefaults::default(), &mut replies),
        Err(SetupError::InvalidPublicKey)
    ));
}

fn admin(name: &str, size: Option<u32>) -> SetupState {
    let mut state = SetupState::new(
        CanonicalUrl::simple("ws://localhost:8174/").unwrap(),
        CanonicalUrl::simple("fedimint://localhost:8173/").unwrap(),
        BitcoinNetwork::Regtest,
        "0.13.0-local".into(),
    );
    state
        .set_local_params(LocalParams {
            name: name.into(),
            federation_name: size.map(|_| "test federation".into()),
            disable_base_fees: None,
            enabled_modules: None,
            federation_size: size,
        })
        .unwrap();
    state
}
#[test]
fn administration_idempotence_uniqueness_reset_and_restore_exclusion() {
    let mut local = admin("Alice", Some(4));
    let code = local.get_setup_code().unwrap();
    let cert = local.identity().unwrap().certificate_der().unwrap();
    assert_eq!(local.status().as_str(), "SharingConnectionCodes");
    let params = LocalParams {
        name: "Alice".into(),
        federation_name: Some("test federation".into()),
        disable_base_fees: None,
        enabled_modules: None,
        federation_size: Some(4),
    };
    assert_eq!(local.set_local_params(params.clone()).unwrap(), code);
    assert_eq!(local.identity().unwrap().certificate_der().unwrap(), cert);
    let mut changed = params;
    changed.name = "Changed".into();
    assert_eq!(
        local.set_local_params(changed).err(),
        Some(AdminError::ParametersAlreadySet)
    );
    assert_eq!(
        local.add_peer_setup_code(&code).err(),
        Some(AdminError::LocalCode)
    );
    let other = admin("Bob", Some(4));
    assert_eq!(
        local
            .add_peer_setup_code(&other.get_setup_code().unwrap())
            .err(),
        Some(AdminError::DuplicateOptionalField)
    );
    let bob = admin("Bob", None);
    let bob_code = bob.get_setup_code().unwrap();
    assert_eq!(local.add_peer_setup_code(&bob_code).unwrap(), "Bob");
    local.set_restore_in_progress(true);
    assert_eq!(local.add_peer_setup_code(&bob_code).unwrap(), "Bob");
    assert_eq!(
        local
            .add_peer_setup_code(&admin("Carol", None).get_setup_code().unwrap())
            .err(),
        Some(AdminError::RestoreInProgress)
    );
    local.set_restore_in_progress(false);
    local
        .add_peer_setup_code(&admin("Carol", None).get_setup_code().unwrap())
        .unwrap();
    local
        .add_peer_setup_code(&admin("Dave", None).get_setup_code().unwrap())
        .unwrap();
    let inputs = local.generation_inputs().unwrap();
    assert_eq!(inputs.peer, PeerId(0));
    assert_eq!(inputs.records.len(), 4);
    local.reset_peer_setup_codes();
    assert_eq!(local.get_setup_code().unwrap(), code);
    assert_eq!(local.identity().unwrap().certificate_der().unwrap(), cert);
    assert!(matches!(
        local.generation_inputs(),
        Err(AdminError::InvalidGeneration)
    ));
}
#[test]
fn administration_rejects_invalid_local_parameters_and_incompatible_codes() {
    let mut state = SetupState::new(
        CanonicalUrl::simple("ws://localhost/").unwrap(),
        CanonicalUrl::simple("fedimint://localhost/").unwrap(),
        BitcoinNetwork::Regtest,
        "0.13.0".into(),
    );
    assert_eq!(state.status().as_str(), "AwaitingLocalParams");
    assert!(state.get_setup_code().is_none());
    let params = LocalParams {
        name: String::new(),
        federation_name: None,
        disable_base_fees: None,
        enabled_modules: None,
        federation_size: None,
    };
    assert_eq!(
        state.set_local_params(params).err(),
        Some(AdminError::InvalidParameters)
    );
    assert!(state.identity().is_none());
    let mut local = admin("Alice", Some(4));
    let mut peer = SetupRecord::from_code(&admin("Bob", None).get_setup_code().unwrap()).unwrap();
    peer.network = BitcoinNetwork::Signet;
    assert_eq!(
        local.add_peer_setup_code(&peer.to_code()).err(),
        Some(AdminError::IncompatiblePeer)
    );
    peer.network = BitcoinNetwork::Regtest;
    peer.release = "0.14.0".into();
    assert_eq!(
        local.add_peer_setup_code(&peer.to_code()).err(),
        Some(AdminError::IncompatiblePeer)
    );
    assert_eq!(
        local.add_peer_setup_code("not-a-code").err(),
        Some(AdminError::InvalidPeerCode)
    );
}
#[path = "fixtures/storage/mod.rs"]
mod storage_fixture;
#[test]
fn generated_private_configuration_is_atomic_validated_and_reopens() {
    use minimint_ng::storage::Store;
    let dir = storage_fixture::TestDir::new();
    let state = admin("Alice", Some(1));
    let inputs = state.generation_inputs().unwrap();
    let generated = generate(
        inputs.peer,
        &inputs.records,
        &SetupDefaults::default(),
        &mut NoTransport,
    )
    .unwrap();
    {
        let store = Store::open(dir.path()).unwrap();
        assert!(load_generated(&store).unwrap().is_none());
        let wrong = minimint_ng::net::tls::Identity::generate("Wrong").unwrap();
        assert!(matches!(
            persist_generated(&store, &generated, &wrong.into()),
            Err(PersistenceError::InvalidConfiguration)
        ));
        assert!(load_generated(&store).unwrap().is_none());
        persist_generated(&store, &generated, state.identity().unwrap()).unwrap();
        assert!(matches!(
            persist_generated(&store, &generated, state.identity().unwrap()),
            Err(PersistenceError::AlreadyStored)
        ));
    }
    let store = Store::open(dir.path()).unwrap();
    let restored = load_generated(&store).unwrap().unwrap();
    assert_eq!(restored.generated.server, generated.server);
    assert_eq!(restored.generated.setup_records, generated.setup_records);
    assert_eq!(restored.generated.peer, generated.peer);
    assert_eq!(
        restored.generated.secrets.broadcast.public_key(),
        generated.secrets.broadcast.public_key()
    );
    assert_eq!(
        restored.generated.secrets.wallet.public_key(),
        generated.secrets.wallet.public_key()
    );
    assert_eq!(
        restored.identity.certificate_der().unwrap(),
        state.identity().unwrap().certificate_der().unwrap()
    );
    assert_eq!(restored.generated.secrets.mint.len(), 42);
    // Local key correspondence was revalidated during load; no private bytes
    // are included in assertions or diagnostic formatting.
}
#[test]
fn persisted_configuration_rejects_truncation_and_trailing_private_bytes() {
    use minimint_ng::storage::{Namespace, Store};
    let dir = storage_fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let state = admin("Alice", Some(1));
    let inputs = state.generation_inputs().unwrap();
    let generated = generate(
        inputs.peer,
        &inputs.records,
        &SetupDefaults::default(),
        &mut NoTransport,
    )
    .unwrap();
    persist_generated(&store, &generated, state.identity().unwrap()).unwrap();
    let mut bytes = zeroize::Zeroizing::new(
        store
            .snapshot()
            .unwrap()
            .get(Namespace::Local, b"setup/generated/v1")
            .unwrap()
            .unwrap(),
    );
    bytes.push(0);
    let mut tx = store.transaction().unwrap();
    tx.put(Namespace::Local, b"setup/generated/v1", &bytes)
        .unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        load_generated(&store),
        Err(PersistenceError::CorruptRecord)
    ));
    let mut tx = store.transaction().unwrap();
    tx.put(Namespace::Local, b"setup/generated/v1", &[1])
        .unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        load_generated(&store),
        Err(PersistenceError::CorruptRecord)
    ));
}

#[test]
fn four_guardians_generate_over_authenticated_tcp_and_shutdown_unblocks_setup() {
    use minimint_ng::net::{
        PeerNetwork,
        tls::{Identity, PeerCertificate, TlsConfig},
    };
    use std::net::TcpListener;
    let mut records = records(4);
    let identities: Vec<_> = records
        .values()
        .map(|record| Identity::generate(&record.name).unwrap())
        .collect();
    let listeners: Vec<_> = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: BTreeMap<_, _> = listeners
        .iter()
        .enumerate()
        .map(|(id, listener)| (PeerId(id as u16), listener.local_addr().unwrap()))
        .collect();
    let certificates: BTreeMap<_, _> = records
        .iter_mut()
        .map(|(peer, record)| {
            let certificate_der = identities[usize::from(peer.0)].certificate_der().unwrap();
            let SetupEndpoints::Tcp {
                certificate,
                p2p_url,
                ..
            } = &mut record.endpoints
            else {
                unreachable!()
            };
            *certificate = certificate_der.clone();
            *p2p_url = CanonicalUrl::simple(&format!("tcp://{}/", addresses[peer])).unwrap();
            (
                *peer,
                PeerCertificate {
                    name: record.name.clone(),
                    certificate_der,
                },
            )
        })
        .collect();
    let networks: Vec<_> = listeners
        .into_iter()
        .enumerate()
        .map(|(id, listener)| {
            let local = PeerId(id as u16);
            PeerNetwork::start(
                local,
                TlsConfig::new(&identities[id], certificates.clone()).unwrap(),
                addresses
                    .iter()
                    .filter(|(peer, _)| **peer != local)
                    .map(|(peer, address)| (*peer, *address))
                    .collect(),
                listener,
                32,
            )
            .unwrap()
        })
        .collect();
    let (tx, rx) = mpsc::channel();
    let generated = std::thread::scope(|scope| {
        for (id, network) in networks.iter().enumerate() {
            let tx = tx.clone();
            let records = &records;
            scope.spawn(move || {
                let local = PeerId(id as u16);
                let mut transport = PeerSetupTransport::new(
                    network,
                    records.keys().copied().filter(|peer| *peer != local),
                );
                let result = generate(local, records, &SetupDefaults::default(), &mut transport);
                tx.send(result).unwrap();
            });
        }
        drop(tx);
        let mut generated = Vec::new();
        // Harness-only deadline releases every worker on test failure.
        for _ in 0..4 {
            match rx.recv_timeout(Duration::from_secs(30)) {
                Ok(Ok(config)) => generated.push(config),
                _ => {
                    for network in &networks {
                        network.request_shutdown();
                    }
                    break;
                }
            }
        }
        generated
    });
    assert_eq!(generated.len(), 4);
    assert!(
        generated
            .iter()
            .all(|config| config.server == generated[0].server)
    );
    for config in &generated {
        let directory = storage_fixture::TestDir::new();
        let store = minimint_ng::storage::Store::open(directory.path()).unwrap();
        let source = &identities[usize::from(config.peer.0)];
        let identity = Identity::from_der(
            &source.certificate_der().unwrap(),
            &source.private_key_der().unwrap(),
        )
        .unwrap();
        persist_generated(&store, config, &identity.into()).unwrap();
        let restored = load_generated(&store).unwrap().unwrap();
        assert_eq!(restored.generated.server, config.server);
        assert_eq!(restored.generated.setup_records, config.setup_records);
        // Corrupt one remote public point in the persisted public config while
        // leaving the local signing key and every private record untouched.
        // Loaded configuration must reject it before agreement starts.
        let remote_key = config
            .server
            .broadcast_public_keys
            .iter()
            .find(|(peer, _)| **peer != config.peer)
            .unwrap()
            .1;
        let public_bytes = config.server.consensus_encode();
        let offset = public_bytes
            .windows(33)
            .position(|bytes| bytes == remote_key)
            .unwrap()
            + 1;
        let namespace = minimint_ng::storage::Namespace::Local;
        let mut bytes = zeroize::Zeroizing::new(
            store
                .snapshot()
                .unwrap()
                .get(namespace, b"setup/generated/v1")
                .unwrap()
                .unwrap(),
        );
        bytes[offset..offset + 33].fill(0);
        let mut writer = store.transaction().unwrap();
        writer
            .put(namespace, b"setup/generated/v1", &bytes)
            .unwrap();
        writer.commit().unwrap();
        assert!(matches!(
            load_generated(&store),
            Err(PersistenceError::InvalidConfiguration)
        ));
    }
    let mut transport = PeerSetupTransport::new(&networks[0], [PeerId(1), PeerId(2), PeerId(3)]);
    assert_eq!(
        transport.receive_from(PeerId(4)).err(),
        Some(SetupError::UnknownPeer)
    );
    networks[0].request_shutdown();
    assert_eq!(
        transport.wait_for_all(&[PeerId(1)]).err(),
        Some(SetupError::Transport)
    );
    assert_eq!(
        transport.receive_from(PeerId(1)).err(),
        Some(SetupError::Transport)
    );
    for network in networks {
        network.shutdown().unwrap();
    }
}
