#![allow(dead_code)]
//! Test-only subprocess helpers. No timing override: daemon defaults remain active.
use minimint_ng::api::websocket::{Limits, Message, WebSocket};
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
#[path = "../storage/mod.rs"]
mod fixture;
pub const ADMIN: &str = "subprocess-test-admin";
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
    pub fn new() -> Self {
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
pub struct Harness {
    dir: fixture::TestDir,
    api: SocketAddr,
    p2p: SocketAddr,
    offline: OfflineBitcoin,
    launches: usize,
}
impl Harness {
    pub fn new() -> Self {
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
    pub fn data(&self) -> PathBuf {
        self.dir.path().join("guardian")
    }
    pub fn spawn(&mut self) -> Daemon {
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
pub struct Daemon {
    child: Child,
    log: PathBuf,
    api: SocketAddr,
}
impl Daemon {
    pub fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            panic!(
                "daemon stopped unexpectedly ({status}): {}",
                fs::read_to_string(&self.log).unwrap()
            );
        }
    }

    pub fn connect(&mut self) -> Rpc {
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
    pub fn terminate(&mut self, signal: &str) {
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
pub struct Rpc {
    ws: WebSocket,
    next: u64,
}
impl Rpc {
    pub fn call(&mut self, method: &str, params: Value, admin: bool) -> Value {
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
    pub fn status(&mut self) -> String {
        self.call("setup_status", json!(null), false)
            .as_str()
            .unwrap()
            .to_owned()
    }
    pub fn wait_running(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.status() != "ConsensusIsRunning" {
            assert!(Instant::now() < deadline, "setup completion deadline");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
