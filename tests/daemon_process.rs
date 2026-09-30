//! Subprocess coverage of the actual guardian executable; this WS harness is test-only.
#![cfg(unix)]
use minimint_ng::{
    api::websocket::{Limits, Message, WebSocket},
    codec::{rpc, text::hex_encode},
    config::{BitcoinNetwork, CanonicalUrl},
    core::{
        session::{persisted_status, session_count},
        transaction::{accepted_output_modules, transaction_id},
    },
    protocol::{Transaction, TransactionError, TransactionSignatures},
    setup::{self, LocalParams, SetupState},
    storage::Store,
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
const ADMIN: &str = "subprocess-test-admin";
fn url(value: &str) -> CanonicalUrl {
    CanonicalUrl::simple(value).unwrap()
}
fn private_file(path: &std::path::Path, content: &str) {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(content.as_bytes()).unwrap();
}
/// Deterministically unavailable Bitcoin endpoint: accept then close without a
/// response. No RPC schema or Bitcoin behavior is supplied by this fixture.
struct OfflineBitcoin {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl OfflineBitcoin {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => drop(stream),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("offline endpoint failed: {e}"),
                }
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for OfflineBitcoin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
struct Harness {
    dir: fixture::TestDir,
    api: SocketAddr,
    p2p: SocketAddr,
    offline: OfflineBitcoin,
    launches: usize,
}
impl Harness {
    fn new() -> Self {
        let dir = fixture::TestDir::new();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private_file(&dir.path().join("admin"), &format!("{ADMIN}\n"));
        private_file(&dir.path().join("bitcoin"), "test-user:test-password\n");
        let api = TcpListener::bind("127.0.0.1:0").unwrap();
        let p2p = TcpListener::bind("127.0.0.1:0").unwrap();
        let offline = OfflineBitcoin::new();
        Self {
            dir,
            api: api.local_addr().unwrap(),
            p2p: p2p.local_addr().unwrap(),
            offline,
            launches: 0,
        }
    }
    fn data(&self) -> PathBuf {
        self.dir.path().join("guardian")
    }
    fn spawn(&mut self) -> Daemon {
        let log = self.dir.path().join(format!("stderr-{}", self.launches));
        self.launches += 1;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log)
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_fedimintd"))
            .arg("--data-dir")
            .arg(self.data())
            .arg("--api-bind")
            .arg(self.api.to_string())
            .arg("--p2p-bind")
            .arg(self.p2p.to_string())
            .arg("--api-url")
            .arg(format!("ws://{}/", self.api))
            .arg("--p2p-url")
            .arg(format!("fedimint://{}/", self.p2p))
            .arg("--bitcoin-rpc")
            .arg(self.offline.address.to_string())
            .arg("--bitcoin-rpc-credentials-file")
            .arg(self.dir.path().join("bitcoin"))
            .arg("--admin-secret-file")
            .arg(self.dir.path().join("admin"))
            .arg("--round-delay-ms")
            .arg("20")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        Daemon {
            child,
            log,
            api: self.api,
        }
    }
}
struct Daemon {
    child: Child,
    log: PathBuf,
    api: SocketAddr,
}
impl Daemon {
    fn connect(&mut self) -> Rpc {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "daemon exited before API startup ({status}): {}",
                    fs::read_to_string(&self.log).unwrap()
                );
            }
            if let Ok(stream) = TcpStream::connect_timeout(&self.api, Duration::from_millis(100)) {
                let limits = Limits {
                    handshake_timeout: Duration::from_secs(2),
                    operation_timeout: Duration::from_secs(3),
                    ..Limits::default()
                };
                if let Ok(ws) = WebSocket::connect(stream, &self.api.to_string(), "/", None, limits)
                {
                    return Rpc { ws, next: 0 };
                }
            }
            assert!(Instant::now() < deadline, "daemon API startup deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn terminate(&mut self, signal: &str) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "daemon stopped before signal"
        );
        assert!(
            Command::new("kill")
                .arg(signal)
                .arg(self.child.id().to_string())
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let log = fs::read_to_string(&self.log).unwrap();
                assert!(
                    status.success(),
                    "daemon failed clean shutdown ({status}): {log}"
                );
                assert!(!log.contains(ADMIN));
                assert!(!log.contains("test-password"));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "daemon failed to join within test deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
struct Rpc {
    ws: WebSocket,
    next: u64,
}
impl Rpc {
    fn call(&mut self, method: &str, params: Value, admin: bool) -> Value {
        self.next += 1;
        let request = json!({"jsonrpc":"2.0","id":self.next,"method":method,"params":[{"auth":if admin{Some(ADMIN)}else{None},"params":params}]});
        self.ws
            .send_text(std::str::from_utf8(&minimint_ng::json::encode(&request).unwrap()).unwrap())
            .unwrap();
        let Message::Text(text) = self.ws.receive().unwrap() else {
            panic!("non-text RPC response")
        };
        let reply = minimint_ng::json::parse(text.as_bytes(), 65536, 64).unwrap();
        assert_eq!(reply["id"].as_u64(), Some(self.next));
        assert!(reply.get("error").is_none(), "RPC failed: {reply:?}");
        reply["result"].clone()
    }
    fn status(&mut self) -> String {
        self.call("setup_status", json!(null), false)
            .as_str()
            .unwrap()
            .to_owned()
    }
    fn wait_running(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.status() != "ConsensusIsRunning" {
            assert!(Instant::now() < deadline, "setup completion deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
#[test]
fn fresh_binary_setup_transaction_sigterm_and_reopen_duplicate_are_durable() {
    let mut h = Harness::new();
    let mut daemon = h.spawn();
    let mut rpc = daemon.connect();
    assert_eq!(rpc.status(), "AwaitingLocalParams");
    assert!(
        rpc.call(
            "set_local_params",
            json!({"name":"Solo","federation_name":"Subprocess federation","federation_size":1}),
            true
        )
        .is_str()
    );
    rpc.call("start_dkg", json!(null), true);
    rpc.wait_running();
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [61; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    let id = transaction_id(&tx);
    let accepted = rpc.call("submit_transaction", json!(rpc::hex(&tx)), false);
    assert_eq!(accepted, json!(rpc::hex(&Ok::<_, TransactionError>(id))));
    daemon.terminate("-TERM");
    drop(rpc);
    drop(daemon);
    let store = Store::open(h.data()).unwrap();
    assert!(setup::load_generated(&store).unwrap().is_some());
    assert_eq!(
        accepted_output_modules(&store.snapshot().unwrap(), &id).unwrap(),
        Some(vec![])
    );
    assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 0);
    let pending = persisted_status(&store.snapshot().unwrap(), 0).unwrap();
    drop(store);
    let mut daemon = h.spawn();
    let mut rpc = daemon.connect();
    assert_eq!(rpc.status(), "ConsensusIsRunning");
    assert_eq!(
        rpc.call("await_transaction", json!(hex_encode(&id)), false)
            .as_str(),
        Some(hex_encode(&id).as_str())
    );
    let mut duplicate = tx;
    duplicate.signatures = TransactionSignatures::Schnorr(vec![[255; 64]]);
    assert_eq!(
        rpc.call("submit_transaction", json!(rpc::hex(&duplicate)), false),
        accepted
    );
    daemon.terminate("-TERM");
    drop(rpc);
    drop(daemon);
    let store = Store::open(h.data()).unwrap();
    assert_eq!(
        persisted_status(&store.snapshot().unwrap(), 0).unwrap(),
        pending
    );
}
#[test]
fn sigint_while_awaiting_parameters_releases_ports_and_reopens_fresh() {
    let mut h = Harness::new();
    let mut daemon = h.spawn();
    let mut rpc = daemon.connect();
    assert_eq!(rpc.status(), "AwaitingLocalParams");
    daemon.terminate("-INT");
    drop(rpc);
    drop(daemon);
    let store = Store::open(h.data()).unwrap();
    assert!(setup::load_generated(&store).unwrap().is_none());
    drop(store);
    let mut daemon = h.spawn();
    let mut rpc = daemon.connect();
    assert_eq!(rpc.status(), "AwaitingLocalParams");
    daemon.terminate("-INT");
}
#[test]
fn sigint_during_missing_peer_generation_joins_without_persisting_partial_setup() {
    let mut h = Harness::new();
    let mut daemon = h.spawn();
    let mut rpc = daemon.connect();
    rpc.call(
        "set_local_params",
        json!({"name":"Guardian 00","federation_name":"Missing peers","federation_size":4}),
        true,
    );
    // Keep these ports reserved with no TLS peers. Generation must remain in its
    // authenticated membership wait until the process receives cancellation.
    let peers: Vec<_> = (1..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    for (index, listener) in peers.iter().enumerate() {
        let mut setup = SetupState::new(
            url(&format!("ws://127.0.0.1:{}/", 20000 + index)),
            url(&format!("fedimint://{}/", listener.local_addr().unwrap())),
            BitcoinNetwork::Regtest,
            "0.13.0".into(),
        );
        let code = setup
            .set_local_params(LocalParams {
                name: format!("Guardian {:02}", index + 1),
                federation_name: None,
                disable_base_fees: None,
                enabled_modules: None,
                federation_size: None,
            })
            .unwrap();
        rpc.call("add_peer_setup_code", json!(code), true);
    }
    rpc.call("start_dkg", json!(null), true);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(rpc.status(), "SharingConnectionCodes");
    daemon.terminate("-INT");
    drop(rpc);
    drop(daemon);
    let store = Store::open(h.data()).unwrap();
    assert!(setup::load_generated(&store).unwrap().is_none());
    drop(store);
    let mut daemon = h.spawn();
    let mut rpc = daemon.connect();
    assert_eq!(rpc.status(), "AwaitingLocalParams");
    daemon.terminate("-INT");
}
