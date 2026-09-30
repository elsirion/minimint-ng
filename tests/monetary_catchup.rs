//! Local monetary suffix recovery through the real authenticated catchup client.
//! Certificates are constructed with explicit test keys; Bitcoin blocks are
//! deterministic fixtures. No external client, DKG, Core or mixed-money claim.
use minimint_ng::{
    agreement::{Data, FinalizedUnit, ProposalQueue},
    api::{
        announcements::{ApiAnnouncement, SignedAnnouncement},
        websocket::{Limits, Message, WebSocket},
    },
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::{ConsensusEncode, rpc, text::hex_decode},
    core::{
        history::HistoryVerifier,
        session::{self, Session},
        transaction::{ExecutionError, accepted_output_modules, check_submission, transaction_id},
    },
    crypto::{
        bls::{self, G1, G2, Scalar},
        secp::SecretKey,
    },
    daemon::{
        catchup::{Catchup, CatchupEndpoint, CatchupError, CatchupOptions},
        config::RuntimeConfig,
        consensus::{Runtime, RuntimeBackend, RuntimeHandle, RuntimeOptions},
    },
    modules::{mint, wallet},
    net::PeerNetwork,
    protocol::{
        ConsensusItem, DynamicValue, ModuleId, PeerId, SessionOutcome, SignedSessionOutcome,
        Transaction, TransactionSignatures,
    },
    storage::{KeyValueRows, Namespace, Store},
};
use sonic_rs::{JsonValueTrait, json};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod directory;
#[path = "fixtures/monetary/mod.rs"]
mod fixture;

fn scalar_key(value: u64) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretKey::from_bytes(&bytes).unwrap()
}
fn dynamic(id: u16, value: impl ConsensusEncode) -> DynamicValue {
    DynamicValue {
        module_id: ModuleId(id),
        payload: value.consensus_encode(),
    }
}
fn sign(mut tx: Transaction, key: &SecretKey) -> Transaction {
    tx.signatures =
        TransactionSignatures::Schnorr(vec![key.schnorr_sign(&transaction_id(&tx)).unwrap()]);
    tx
}
fn output(denomination: u8, message: G1, tweak: u8) -> mint::Output {
    mint::Output::V0(mint::OutputV0 {
        denomination,
        blinded_message: mint::G1Bytes::from_bytes(message.to_bytes()).unwrap(),
        tweak: [tweak; 16],
    })
}
fn claim(index: u64, nonce: u8, output: mint::Output) -> Transaction {
    sign(
        Transaction {
            inputs: vec![dynamic(
                1,
                wallet::Input::V0 {
                    output_index: index,
                    claimant: scalar_key(53843).public_key(),
                    mining_fee_sat: 316,
                },
            )],
            outputs: vec![dynamic(0, output)],
            nonce: [nonce; 8],
            signatures: TransactionSignatures::Schnorr(vec![]),
        },
        &scalar_key(53843),
    )
}
struct Backend {
    block: bitcoin::Block,
    stopped: AtomicBool,
    last_broadcast: Mutex<Option<Vec<u8>>>,
}
impl Backend {
    fn new(config: &RuntimeConfig) -> Self {
        let script =
            hex_decode("00206760a3fc7b8c1d4f7266aa80773672cd98bc5f3e4e9d6eb2edf300156bef0a06")
                .unwrap();
        assert_eq!(
            config
                .modules()
                .wallet()
                .deposit_script(&scalar_key(53843).public_key())
                .unwrap(),
            script
        );
        assert!(config.modules().wallet().matches_filter(&script));
        Self {
            stopped: AtomicBool::new(false),
            last_broadcast: Mutex::new(None),
            block: bitcoin::Block {
                header: [0; 80],
                transactions: vec![bitcoin::Transaction {
                    version: 2,
                    lock_time: 0,
                    inputs: vec![bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint {
                            txid: bitcoin::Txid([7; 32]),
                            vout: 0,
                        },
                        script_sig: vec![],
                        sequence: u32::MAX,
                        witness: vec![],
                    }],
                    outputs: (0..2)
                        .map(|_| bitcoin::TxOut {
                            value_sat: 100000,
                            script_pubkey: script.clone(),
                        })
                        .collect(),
                }],
            },
        }
    }
}
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        Err(BackendError)
    }
    fn wait_for_count(&self, count: u64) -> Result<(), BackendError> {
        if count <= 7 && !self.stopped.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(BackendError)
        }
    }
    fn block_hash(&self, height: u64) -> Result<[u8; 32], BackendError> {
        if height == 0 {
            Ok(self.block.hash())
        } else {
            Err(BackendError)
        }
    }
    fn block(&self, hash: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        if hash == self.block.hash() {
            Ok(self.block.clone())
        } else {
            Err(BackendError)
        }
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Err(BackendError)
    }
    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), BackendError> {
        *self.last_broadcast.lock().unwrap() = Some(tx.encode());
        Err(BackendError)
    }
}
impl RuntimeBackend for Backend {
    fn request_shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
    }
}
fn ordered(s: &mut Session, config: &RuntimeConfig, b: &Backend, peer: u16, item: ConsensusItem) {
    let before = s.status().pending.items.len();
    s.enqueue(FinalizedUnit {
        creator: PeerId(peer),
        round: 0,
        data: Some(Data::Batch(vec![item].consensus_encode())),
    });
    let q = ProposalQueue::new(64).unwrap().0;
    s.drive(config.modules(), b, &q).unwrap();
    assert_eq!(s.status().pending.items.len(), before + 1);
}
fn certificate(config: &RuntimeConfig, outcome: SessionOutcome) -> SignedSessionOutcome {
    let verifier =
        HistoryVerifier::new(config.server_config().broadcast_public_keys.clone()).unwrap();
    let signatures = (0..3)
        .map(|p| {
            (
                PeerId(p),
                verifier
                    .sign(0, &outcome, PeerId(p), &fixture::key(p as u8 + 1))
                    .unwrap(),
            )
        })
        .collect();
    SignedSessionOutcome {
        outcome,
        signatures,
    }
}
fn module_state(store: &Store) -> BTreeMap<u8, KeyValueRows> {
    [
        Namespace::Replicated,
        Namespace::Local,
        Namespace::Outbox,
        Namespace::ClientBackup,
    ]
    .into_iter()
    .map(|namespace| {
        let rows = store
            .snapshot()
            .unwrap()
            .scan_prefix(namespace, b"")
            .unwrap()
            .into_iter()
            .filter(|(key, _)| !key.starts_with(b"core/session/v1/"))
            .collect();
        (namespace as u8, rows)
    })
    .collect()
}
fn wait(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(Instant::now() < end, "bounded monetary catchup wait");
        thread::sleep(Duration::from_millis(5));
    }
}
struct Running {
    runtime: Option<Runtime>,
    handle: Option<RuntimeHandle>,
}
impl Running {
    fn start(
        store: &Store,
        config: Arc<RuntimeConfig>,
        network: Arc<PeerNetwork>,
        backend: Arc<Backend>,
    ) -> Self {
        let (runtime, handle) = Runtime::start(
            store.clone(),
            config,
            network,
            backend,
            RuntimeOptions {
                wallet_poll_interval: Duration::from_millis(20),
                ..RuntimeOptions::default()
            },
        )
        .unwrap();
        wait(|| handle.current_session().is_some());
        Self {
            runtime: Some(runtime),
            handle: Some(handle),
        }
    }
    fn stop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown().unwrap();
        }
        self.handle.take();
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}
struct Network(Option<Arc<PeerNetwork>>);
impl Drop for Network {
    fn drop(&mut self) {
        if let Some(network) = self.0.take() {
            network.request_shutdown();
            if let Ok(network) = Arc::try_unwrap(network) {
                let _ = network.shutdown();
            }
        }
    }
}
struct Server {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<u64>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn server(signed: SignedSessionOutcome) -> (Server, CatchupEndpoint) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let announcement = ApiAnnouncement {
        api_url: fixture::url(&format!("ws://{address}/")),
        nonce: 1,
    };
    let signature = fixture::key(2)
        .schnorr_sign(&announcement.digest())
        .unwrap();
    let endpoint = CatchupEndpoint::announced(
        PeerId(1),
        SignedAnnouncement {
            api_announcement: announcement,
            signature,
        },
        vec![address],
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let worker = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(10);
        let mut first_index = None;
        // Keep serving until the test acknowledges its observation: closing
        // after one reply could replace InvalidHistory with a transport error.
        while !stopping.load(Ordering::Acquire) {
            assert!(Instant::now() < end, "bounded API fixture accept");
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            let mut ws = match WebSocket::accept(
                stream,
                Some("local-catchup-secret"),
                Limits {
                    handshake_timeout: Duration::from_secs(2),
                    operation_timeout: Duration::from_secs(2),
                    ..Limits::default()
                },
            ) {
                Ok(ws) => ws,
                Err(_) if stopping.load(Ordering::Acquire) => break,
                Err(e) => panic!("{e:?}"),
            };
            let request = match ws.receive() {
                Ok(Message::Text(request)) => request,
                Err(_) if stopping.load(Ordering::Acquire) => break,
                _ => panic!("text RPC required"),
            };
            let value = minimint_ng::json::parse(request.as_bytes(), 1024 * 1024, 32).unwrap();
            assert_eq!(
                value["method"].as_str(),
                Some("await_signed_session_outcome")
            );
            assert!(value["params"][0]["auth"].is_null());
            let index = value["params"][0]["params"].as_u64().unwrap();
            if let Err(error) = ws.send_text(
                &json!({"jsonrpc":"2.0","id":value["id"],"result":rpc::hex(&signed)}).to_string(),
            ) {
                assert!(
                    stopping.load(Ordering::Acquire),
                    "API response failed: {error:?}"
                );
                break;
            }
            first_index.get_or_insert(index);
        }
        first_index.expect("authenticated history request served")
    });
    (
        Server {
            stop,
            worker: Some(worker),
        },
        endpoint,
    )
}

#[test]
fn monetary_catchup_child() {
    if std::env::var_os("MINIMINT_MONETARY_CATCHUP_CHILD").as_deref()
        != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }
    // Reserved remote P2P ports prevent reconnect dials reaching the API fixture.
    let mut listeners: Vec<_> = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let configs = fixture::configs(4, 3600, &listeners);
    let config = configs[0].clone();
    let backend = Backend::new(&config);
    let control_dir = directory::TestDir::new();
    let control = Store::open(control_dir.path()).unwrap();
    let mut source = Session::open(control.clone(), config.session_config().unwrap()).unwrap();
    for value in [
        wallet::ConsensusItem::BlockCount(1),
        wallet::ConsensusItem::FeeRate(Some(1000)),
    ] {
        for peer in 0..3 {
            ordered(
                &mut source,
                &config,
                &backend,
                peer,
                ConsensusItem::Module(dynamic(1, value.clone())),
            );
        }
    }
    let nonce = scalar_key(9);
    let message = bls::message_sha256(&nonce.public_key()).unwrap();
    let blind = Scalar::from_u64(7);
    let first = claim(0, 1, output(19, message.mul(&blind), 1));
    ordered(
        &mut source,
        &config,
        &backend,
        0,
        ConsensusItem::Transaction(first.clone()),
    );
    let prefix = source.status().pending.clone();
    let mut shares = vec![];
    for peer in 0..3 {
        let replica_dir = directory::TestDir::new();
        let replica = Store::open(replica_dir.path()).unwrap();
        let c = &configs[peer as usize];
        let mut s = Session::open(replica.clone(), c.session_config().unwrap()).unwrap();
        for accepted in &prefix.items {
            ordered(&mut s, c, &backend, accepted.peer.0, accepted.item.clone());
        }
        let bytes = c
            .modules()
            .mint()
            .signature_shares(&replica.snapshot().unwrap(), transaction_id(&first), 0..1)
            .unwrap();
        let share = G1::from_bytes(&bytes[0].to_bytes()).unwrap();
        let coefficients = [
            Scalar::from_u64(5),
            Scalar::from_u64(7),
            Scalar::from_u64(11),
        ];
        bls::verify_share(
            &message.mul(&blind),
            &G2::generator().mul(&bls::evaluate_polynomial(&coefficients, peer).unwrap()),
            &share,
        )
        .unwrap();
        shares.push((peer, share));
    }
    assert_ne!(shares[0].1.to_bytes(), shares[1].1.to_bytes());
    let note = mint::Note {
        denomination: 19,
        nonce: mint::Nonce::from_bytes(nonce.public_key()).unwrap(),
        signature: mint::G1Bytes::from_bytes(
            bls::interpolate_g1(&shares, 3)
                .unwrap()
                .mul(&blind.inverse().unwrap())
                .to_bytes(),
        )
        .unwrap(),
    };
    let second = claim(
        1,
        2,
        output(19, G1::generator().mul(&Scalar::from_u64(11)), 2),
    );
    ordered(
        &mut source,
        &config,
        &backend,
        1,
        ConsensusItem::Transaction(second.clone()),
    );
    let reissue = sign(
        Transaction {
            inputs: vec![dynamic(0, mint::Input::V0(note))],
            outputs: vec![dynamic(
                0,
                output(18, G1::generator().mul(&Scalar::from_u64(13)), 3),
            )],
            nonce: [3; 8],
            signatures: TransactionSignatures::Schnorr(vec![]),
        },
        &nonce,
    );
    ordered(
        &mut source,
        &config,
        &backend,
        2,
        ConsensusItem::Transaction(reissue.clone()),
    );
    for peer in 0..3 {
        let signatures = configs[peer as usize]
            .modules()
            .wallet()
            .local_signatures(&control.snapshot().unwrap())
            .unwrap();
        assert_eq!(signatures.len(), 1);
        ordered(
            &mut source,
            &config,
            &backend,
            peer,
            ConsensusItem::Module(dynamic(1, signatures[0].clone())),
        );
    }
    let signed = certificate(&config, source.status().pending.clone());
    let expected = module_state(&control);
    let outbox = control
        .snapshot()
        .unwrap()
        .scan_prefix(Namespace::Outbox, b"")
        .unwrap();
    assert_eq!(outbox.len(), 1);
    let transaction = bitcoin::Transaction::decode(&outbox[0].1).unwrap();
    assert_eq!(transaction.inputs.len(), 2);
    assert!(
        transaction
            .inputs
            .iter()
            .all(|input| input.witness.len() == 5)
    );
    let expected_recovery = config
        .modules()
        .mint()
        .recovery_slice(&control.snapshot().unwrap(), 0..u64::MAX)
        .unwrap();
    assert_eq!(expected_recovery.len(), 4);
    let destination_dir = directory::TestDir::new();
    let mut destination = Store::open(destination_dir.path()).unwrap();
    {
        let mut s = Session::open(destination.clone(), config.session_config().unwrap()).unwrap();
        for accepted in &prefix.items {
            ordered(
                &mut s,
                &config,
                &backend,
                accepted.peer.0,
                accepted.item.clone(),
            );
        }
    }
    assert_eq!(
        config
            .modules()
            .mint()
            .recovery_count(&destination.snapshot().unwrap())
            .unwrap(),
        1
    );
    assert!(
        destination
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Outbox, b"")
            .unwrap()
            .is_empty()
    );
    let network = Network(Some(Arc::new(
        PeerNetwork::start(
            PeerId(0),
            config.tls_config(),
            config.resolve_peer_addresses().unwrap(),
            listeners.remove(0),
            64,
        )
        .unwrap(),
    )));
    for restart in 0..2 {
        let b = Arc::new(Backend::new(&config));
        let mut running = Running::start(
            &destination,
            config.clone(),
            network.0.as_ref().unwrap().clone(),
            b.clone(),
        );
        let (mut api, endpoint) = server(signed.clone());
        let catchup = Catchup::start(
            running.handle.as_ref().unwrap().clone(),
            vec![endpoint],
            Some(zeroize::Zeroizing::new("local-catchup-secret".into())),
            CatchupOptions {
                request_timeout: Duration::from_secs(2),
                retry_interval: Duration::from_millis(20),
                max_response_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        if restart == 0 {
            wait(|| session::session_count(&destination.snapshot().unwrap()).unwrap() == 1);
        } else {
            wait(|| catchup.last_error() == Some(CatchupError::InvalidHistory));
        }
        api.stop.store(true, Ordering::Release);
        catchup.shutdown().unwrap();
        assert_eq!(api.worker.take().unwrap().join().unwrap(), restart);
        assert_eq!(module_state(&destination), expected);
        let snapshot = destination.snapshot().unwrap();
        let modules = config.modules();
        assert_eq!(
            session::completed(&snapshot, 0).unwrap(),
            Some(signed.clone())
        );
        assert!(session::persisted_status(&snapshot, 1).unwrap().is_none());
        assert!(destination.read_agreement(0).unwrap().is_empty());
        assert_eq!(modules.mint().recovery_count(&snapshot).unwrap(), 4);
        assert_eq!(
            modules
                .mint()
                .recovery_slice(&snapshot, 0..u64::MAX)
                .unwrap(),
            expected_recovery
        );
        for tx in [&first, &second, &reissue] {
            assert_eq!(
                accepted_output_modules(&snapshot, &transaction_id(tx)).unwrap(),
                Some(vec![ModuleId(0)])
            );
            assert_eq!(
                modules
                    .mint()
                    .signature_shares(&snapshot, transaction_id(tx), 0..1)
                    .unwrap()
                    .len(),
                1
            );
        }
        let view = modules.wallet().snapshot(&snapshot).unwrap();
        assert_eq!((view.chain.len(), view.pending_chain.len()), (1, 1));
        assert_eq!(view.wallet.as_ref().unwrap().value_sat, 199684);
        let discoveries = view.output_info_slice(0, 2);
        assert_eq!(discoveries.len(), 2);
        assert!(discoveries.iter().all(|item| item.spent));
        assert_eq!(
            modules.audit(&destination.transaction().unwrap()).unwrap(),
            199684000 - (1_i64 << 19) - (1_i64 << 18)
        );
        assert_eq!(
            check_submission(
                &destination,
                &reissue,
                modules,
                config.server_config().consensus_version
            )
            .unwrap(),
            transaction_id(&reissue)
        );
        let mut replay = reissue.clone();
        replay.nonce = [9; 8];
        let replay = sign(replay, &nonce);
        let Err(ExecutionError::Rejected(minimint_ng::protocol::TransactionError::Input(error))) =
            check_submission(
                &destination,
                &replay,
                modules,
                config.server_config().consensus_version,
            )
        else {
            panic!("spent-note replay with a new transaction ID must fail");
        };
        assert_eq!(error.module_id, ModuleId(0));
        assert_eq!(
            error.payload,
            mint::InputError::SpentCoin.consensus_encode()
        );
        assert_eq!(module_state(&destination), expected);
        wait(|| b.last_broadcast.lock().unwrap().is_some());
        assert_eq!(
            b.last_broadcast.lock().unwrap().as_ref(),
            Some(&outbox[0].1)
        );
        drop(snapshot);
        running.stop();
        drop(running);
        drop(destination);
        destination = Store::open(destination_dir.path()).unwrap();
        assert_eq!(module_state(&destination), expected);
    }
}

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn monetary_suffix_api_catchup_and_restart_preserve_recovery_and_signed_outbox() {
    // Predicate deadlines alone do not bound native shutdown. The parent owns
    // the entire scenario process and kills/reaps it if any worker/join stalls.
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "monetary_catchup_child", "--nocapture"])
            .env("MINIMINT_MONETARY_CATCHUP_CHILD", "1")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "monetary catchup scenario failed");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "monetary catchup process deadline; guard kills and reaps"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
