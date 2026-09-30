//! Real RPC -> durable announcement -> process poller -> history transport.
//! Deterministic private keys are confined to this non-monetary test fixture.
#![cfg(unix)]
use minimint_ng::{
    api::{
        announcements::{AnnouncementApi, ApiAnnouncement, SignedAnnouncement},
        websocket::{Limits, Message, WebSocket},
    },
    codec::{
        ConsensusEncode, rpc,
        text::{hex_decode, hex_encode},
    },
    config::{BitcoinNetwork, SetupEndpoints, SetupRecord},
    core::{history::HistoryVerifier, session::session_count},
    crypto::bls::Scalar,
    modules::wallet,
    net::tls::Identity,
    protocol::{
        AcceptedItem, ConsensusItem, DynamicValue, ModuleId, PeerId, SessionOutcome,
        SignedSessionOutcome,
    },
    setup::{self, GeneratedConfig, GeneratedSecrets},
    storage::Store,
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
#[path = "fixtures/runtime/mod.rs"]
mod runtime_fixture;
use runtime_fixture::{configs, key, url};
const ADMIN: &str = "endpoint-refresh-test-admin";
fn private(path: &Path, text: &str) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(text.as_bytes()).unwrap();
}
fn bound() -> TcpListener {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    l
}
fn accept(listener: &TcpListener) -> TcpStream {
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        match listener.accept() {
            Ok((socket, _)) => return socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept: {error}"),
        };
        assert!(Instant::now() < end, "history endpoint was not contacted");
        thread::sleep(Duration::from_millis(10));
    }
}
struct Daemon {
    child: Child,
    log: PathBuf,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
impl Daemon {
    fn launch(root: &Path, api: SocketAddr, p2p: SocketAddr, bitcoin: SocketAddr, run: u8) -> Self {
        let log = root.join(format!("stderr-{run}"));
        let output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&log)
            .unwrap();
        let executable = root.join(format!("daemon-image-{run}"));
        fs::copy(env!("CARGO_BIN_EXE_fedimintd"), &executable).unwrap();
        let child = Command::new(&executable)
            .arg("--data-dir")
            .arg(root.join("guardian"))
            .args([
                "--api-bind",
                &api.to_string(),
                "--p2p-bind",
                &p2p.to_string(),
                "--api-url",
                &format!("ws://{api}/"),
                "--p2p-url",
                &format!("fedimint://{p2p}/"),
                "--bitcoin-rpc",
                &bitcoin.to_string(),
            ])
            .arg("--bitcoin-rpc-credentials-file")
            .arg(root.join("bitcoin"))
            .arg("--admin-secret-file")
            .arg(root.join("admin"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        Self { child, log }
    }
    fn check(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "daemon stopped: {}",
            fs::read_to_string(&self.log)
                .unwrap()
                .replace(ADMIN, "[redacted]")
                .replace("test-password", "[redacted]")
        );
    }
    fn stop(&mut self) {
        self.check();
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "daemon shutdown failed");
                break;
            }
            assert!(Instant::now() < end, "daemon shutdown timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
struct Rpc {
    ws: WebSocket,
    id: u64,
}
impl Rpc {
    fn connect(api: SocketAddr, daemon: &mut Daemon) -> Self {
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            daemon.check();
            if let Ok(socket) = TcpStream::connect_timeout(&api, Duration::from_millis(100)) {
                if let Ok(ws) = WebSocket::connect(
                    socket,
                    &api.to_string(),
                    "/",
                    None,
                    Limits {
                        handshake_timeout: Duration::from_secs(1),
                        operation_timeout: Duration::from_secs(3),
                        ..Limits::default()
                    },
                ) {
                    return Self { ws, id: 0 };
                }
            }
            assert!(Instant::now() < end, "API startup");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn call(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        self.ws.send_text(&json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":[{"auth":null,"params":params}]}).to_string()).unwrap();
        let Message::Text(text) = self.ws.receive().unwrap() else {
            panic!("nontext API result")
        };
        let response: Value = sonic_rs::from_str(&text).unwrap();
        assert_eq!(response["id"].as_u64(), Some(self.id));
        assert!(response["error"].is_null(), "RPC {method} failed");
        response["result"].clone()
    }
    fn wait_count(&mut self, count: u64, daemon: &mut Daemon) {
        let end = Instant::now() + Duration::from_secs(15);
        while self.call("session_count", json!(null)).as_u64() != Some(count) {
            daemon.check();
            assert!(Instant::now() < end, "history adoption deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
fn response(listener: &TcpListener, index: u64, verifier: &HistoryVerifier) {
    let socket = accept(listener);
    let mut ws = WebSocket::accept(socket, None, Limits::default()).unwrap();
    let Message::Text(request) = ws.receive().unwrap() else {
        panic!("history request")
    };
    let request: Value = sonic_rs::from_str(&request).unwrap();
    assert_eq!(
        request["method"].as_str(),
        Some("await_signed_session_outcome")
    );
    assert_eq!(request["params"][0]["params"].as_u64(), Some(index));
    let outcome = SessionOutcome {
        items: vec![AcceptedItem {
            peer: PeerId(0),
            item: ConsensusItem::Module(DynamicValue {
                module_id: ModuleId(1),
                payload: wallet::ConsensusItem::FeeRate(Some(1000 + index)).consensus_encode(),
            }),
        }],
    };
    let signatures = (0..3)
        .map(|p| {
            (
                PeerId(p),
                verifier
                    .sign(index, &outcome, PeerId(p), &key(p as u8 + 1))
                    .unwrap(),
            )
        })
        .collect();
    let signed = SignedSessionOutcome {
        outcome,
        signatures,
    };
    ws.send_text(&json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&signed)}).to_string())
        .unwrap();
}
#[test]
fn rpc_endpoint_move_is_durable_and_restored_process_uses_new_destination() {
    let dir = fixture::TestDir::new();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    private(&dir.path().join("admin"), ADMIN);
    private(&dir.path().join("bitcoin"), "test-user:test-password");
    let mut peer_listeners: Vec<_> = (0..4).map(|_| bound()).collect();
    let mut api_listeners: Vec<_> = (0..4).map(|_| bound()).collect();
    let config = configs(4, 3600, &peer_listeners).remove(0);
    let mut server = config.server_config().clone();
    let local_identity = Identity::generate("Guardian 00").unwrap();
    server.tls_certificates.insert(
        PeerId(0),
        hex_encode(&local_identity.certificate_der().unwrap()),
    );
    let records: BTreeMap<_, _> = (0..4)
        .map(|p| {
            let peer = PeerId(p);
            let endpoint = server.api_endpoints.get_mut(&peer).unwrap();
            endpoint.url = url(&format!(
                "ws://{}/",
                api_listeners[p as usize].local_addr().unwrap()
            ));
            (
                peer,
                SetupRecord {
                    name: endpoint.name.clone(),
                    endpoints: SetupEndpoints::Tcp {
                        api_url: endpoint.url.clone(),
                        p2p_url: url(&format!(
                            "fedimint://{}/",
                            peer_listeners[p as usize].local_addr().unwrap()
                        )),
                        certificate: hex_decode(&server.tls_certificates[&peer]).unwrap(),
                    },
                    federation_name: (p == 0).then(|| "Federation".into()),
                    disable_base_fees: None,
                    enabled_modules: None,
                    federation_size: (p == 0).then_some(4),
                    network: BitcoinNetwork::Regtest,
                    release: "0.13.0-test".into(),
                },
            )
        })
        .collect();
    let verifier = HistoryVerifier::new(server.broadcast_public_keys.clone()).unwrap();
    let public = server.clone();
    let generated = GeneratedConfig {
        server,
        setup_records: records,
        peer: PeerId(0),
        secrets: GeneratedSecrets {
            broadcast: key(1),
            wallet: key(101),
            mint: (0..42).map(|d| (d, Scalar::from_u64(1))).collect(),
        },
    };
    let store = Store::open(dir.path().join("guardian")).unwrap();
    setup::persist_generated(&store, &generated, &local_identity).unwrap();
    drop(store);
    drop(generated);
    drop(config);
    let api = api_listeners[0].local_addr().unwrap();
    let p2p = peer_listeners[0].local_addr().unwrap();
    drop(api_listeners.remove(0));
    drop(peer_listeners.remove(0));
    let old = api_listeners.remove(0);
    drop(api_listeners);
    let bitcoin = bound();
    let new = bound();
    let mut daemon = Daemon::launch(dir.path(), api, p2p, bitcoin.local_addr().unwrap(), 0);
    let mut client = Rpc::connect(api, &mut daemon);
    // Operational resolution must still execute this running image after a
    // build replaces or removes its original pathname.
    fs::remove_file(dir.path().join("daemon-image-0")).unwrap();
    let identity = client.call("federation_id", json!(null));
    let mut obsolete = WebSocket::accept(
        accept(&old),
        None,
        Limits {
            operation_timeout: Duration::from_secs(5),
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(obsolete.receive().unwrap(), Message::Text(_)));
    let api_announcement = ApiAnnouncement {
        api_url: url(&format!("ws://{}/", new.local_addr().unwrap())),
        nonce: 0,
    };
    let signature = key(2).schnorr_sign(&api_announcement.digest()).unwrap();
    let signed = SignedAnnouncement {
        api_announcement,
        signature,
    };
    assert!(client.call("submit_api_announcement",json!({"peer_id":1,"api_announcement":signed.api_announcement.json(),"signature":hex_encode(&signed.signature)})).is_null());
    assert_eq!(
        client.call("api_announcements", json!(null))["1"],
        signed.json()
    );
    assert!(obsolete.receive().is_err());
    response(&new, 0, &verifier);
    client.wait_count(1, &mut daemon);
    assert_eq!(client.call("federation_id", json!(null)), identity);
    daemon.stop();
    drop(client);
    drop(daemon);
    let store = Store::open(dir.path().join("guardian")).unwrap();
    let loaded = setup::load_generated(&store).unwrap().unwrap();
    assert_eq!(loaded.generated.server, public);
    let updates = AnnouncementApi::new(
        store.clone(),
        public.broadcast_public_keys.clone(),
        PeerId(0),
        key(1),
    )
    .unwrap();
    assert!(
        updates
            .announcements(&store.snapshot().unwrap())
            .unwrap()
            .get(&PeerId(1))
            == Some(&signed)
    );
    assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 1);
    drop(updates);
    drop(loaded);
    drop(store);
    // Discard an already accepted-but-unserved index1 TCP attempt from the first
    // process before using this same announced address after restart.
    while let Ok((socket, _)) = new.accept() {
        drop(socket);
    }
    let mut daemon = Daemon::launch(dir.path(), api, p2p, bitcoin.local_addr().unwrap(), 1);
    let mut client = Rpc::connect(api, &mut daemon);
    assert_eq!(
        client.call("api_announcements", json!(null))["1"],
        signed.json()
    );
    response(&new, 1, &verifier);
    client.wait_count(2, &mut daemon);
    assert_eq!(
        old.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(client.call("federation_id", json!(null)), identity);
    daemon.stop();
}
