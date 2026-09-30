//! Black-box two-independent/two-reference guardian evidence; no monetary claim.
//! MINIMINT_REFERENCE_DAEMON must name the verified exact-baseline artifact.
//! MINIMINT_MIXED_SETUP_ONLY=1 bounds execution to setup/configuration evidence.
//! MINIMINT_MIXED_FAILURES=1 adds joined outages and a bounded quorum barrier.
//! MINIMINT_MIXED_OUTAGE_PEER=0|1|2|3 selects the first outage (default 1).
//! MINIMINT_MIXED_ONE_OUTAGE_ONLY=1 skips the subsequent fixed pair barrier.
//! MINIMINT_MIXED_NEW_PEERS=0,1 assigns exactly two independent guardians;
//! canonical ascending pairs only. Use 2,3 for the inverse implementation layout.
//! MINIMINT_MIXED_RECOVERY_CHECKS=1 checks opaque backups and empty Mint recovery,
//! including joined restarts. With SETUP_ONLY=1 it makes no session-history claim.
//! MINIMINT_MIXED_DRIVER=/absolute/executable runs a separate external workflow
//! with --handoff DIRECTORY after setup, instead of submitting empty transactions.
//! MINIMINT_MIXED_MONETARY_SURVIVORS=1 enables eight fixed joined stop/restart
//! controls from that driver, one guardian at a time, within its original deadline.
//! Its result remains an external claim; only history verification is independent.
//! Full runs require MINIMINT_BITCOIN_RPC and MINIMINT_BITCOIN_CREDENTIALS_FILE
//! for an operator-owned regtest Core node outside IBD; this test never mines.
#![cfg(unix)]
use minimint_ng::{
    api::websocket::{Limits, Message, WebSocket},
    codec::{rpc, text::hex_encode},
    config::{self, SetupRecord},
    core::{
        history::{HistoryVerifier, SignaturePolicy},
        transaction::transaction_id,
    },
    protocol::{
        PeerId, SignedSessionOutcome, Transaction, TransactionError, TransactionSignatures,
    },
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
const ADMIN: &str = "mixed-process-test-admin";
const PASSWORD: &str = "mixed-process-bitcoin-password";
const REFERENCE_HASH: &str = "d51bc18b275ac699c2d20e3ca905bc38f20afdf6b704c14b0524f9eaa20ae8b8";
struct Daemon {
    child: Child,
    command: Command,
    log: PathBuf,
    api: SocketAddr,
    password: String,
    reference: bool,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if thread::panicking() {
            let log = self.log();
            eprintln!(
                "mixed child {} sanitized stderr: {}",
                self.api,
                log.chars()
                    .rev()
                    .take(12000)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>()
            );
        }
    }
}
impl Daemon {
    fn restart(&mut self) -> Rpc {
        self.restart_until(Instant::now() + Duration::from_secs(30))
    }
    fn restart_until(&mut self, deadline: Instant) -> Rpc {
        assert!(Instant::now() < deadline, "restart deadline");
        assert!(
            self.child.try_wait().unwrap().is_some(),
            "restart requires joined outage"
        );
        self.command.stderr(Stdio::from(
            OpenOptions::new().append(true).open(&self.log).unwrap(),
        ));
        self.child = self.command.spawn().unwrap();
        self.connect_until(deadline)
    }
    fn check(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            panic!("mixed child exited {status}: {}", self.log());
        }
    }
    fn log(&self) -> String {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .replace(ADMIN, "[admin redacted]")
            .replace(PASSWORD, "[Bitcoin password redacted]")
            .replace(&self.password, "[Bitcoin password redacted]")
    }
    fn connect(&mut self) -> Rpc {
        self.connect_until(Instant::now() + Duration::from_secs(30))
    }
    fn connect_until(&mut self, deadline: Instant) -> Rpc {
        let end = deadline.min(Instant::now() + Duration::from_secs(30));
        loop {
            assert!(Instant::now() < end, "API connection deadline");
            self.check();
            if let Ok(stream) = TcpStream::connect_timeout(&self.api, Duration::from_millis(100)) {
                let limits = Limits {
                    handshake_timeout: Duration::from_secs(1)
                        .min(end.saturating_duration_since(Instant::now())),
                    operation_timeout: Duration::from_secs(5)
                        .min(end.saturating_duration_since(Instant::now())),
                    ..Limits::default()
                };
                if let Ok(ws) = WebSocket::connect(stream, &self.api.to_string(), "/", None, limits)
                {
                    return Rpc { ws, id: 0 };
                }
            }
            assert!(Instant::now() < end, "API startup deadline: {}", self.log());
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn stop(&mut self) -> i32 {
        self.stop_until(Instant::now() + Duration::from_secs(35))
    }
    fn stop_until(&mut self, deadline: Instant) -> i32 {
        assert!(Instant::now() < deadline, "stop deadline");
        self.check();
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let end = deadline.min(Instant::now() + Duration::from_secs(35));
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                // This exact reference artifact observably returns 255 after
                // SIGTERM, both before and after consensus. Record it; no
                // reference clean-exit convention is specified by the handoff.
                assert!(
                    status.success() || (self.reference && status.code() == Some(255)),
                    "unclean mixed shutdown {status}: {}",
                    self.log()
                );
                return status.code().unwrap();
            }
            assert!(
                Instant::now() < end,
                "mixed shutdown deadline: {}",
                self.log()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}
struct Rpc {
    ws: WebSocket,
    id: u64,
}
impl Rpc {
    fn call(&mut self, method: &str, params: Value, admin: bool) -> Value {
        self.try_call(method, params, admin)
            .unwrap_or_else(|error| panic!("{method}: {error}"))
    }
    fn try_call(&mut self, method: &str, params: Value, admin: bool) -> Result<Value, String> {
        self.send(method, params, admin)?;
        self.reply(method)
    }
    fn send(&mut self, method: &str, params: Value, admin: bool) -> Result<(), String> {
        self.id += 1;
        let req = json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":[{"auth":if admin{Some(ADMIN)}else{None},"params":params}]});
        self.ws
            .send_text(&req.to_string())
            .map_err(|error| format!("send {error:?}"))
    }
    fn reply(&mut self, method: &str) -> Result<Value, String> {
        let reply = self.raw_reply()?;
        assert!(
            reply.get("error").is_none(),
            "{method} error: {}",
            reply.to_string().replace(ADMIN, "[redacted]")
        );
        Ok(reply["result"].clone())
    }
    fn raw_reply(&mut self) -> Result<Value, String> {
        let Message::Text(reply) = self
            .ws
            .receive()
            .map_err(|error| format!("receive {error:?}"))?
        else {
            return Err("nontext response".into());
        };
        let reply = minimint_ng::json::parse(reply.as_bytes(), 16 * 1024 * 1024, 64).unwrap();
        assert_eq!(reply["id"].as_u64(), Some(self.id));
        assert_eq!(reply["jsonrpc"].as_str(), Some("2.0"));
        Ok(reply)
    }
}
fn bound() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").unwrap()
}
fn private(path: &std::path::Path, text: &str) {
    use std::io::Write;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(text.as_bytes()).unwrap();
}
fn launch(
    root: &std::path::Path,
    index: usize,
    is_reference: bool,
    reference: &std::path::Path,
    bitcoin: SocketAddr,
    credentials: &str,
) -> Daemon {
    let (username, password) = credentials
        .split_once(':')
        .expect("Bitcoin credentials username:password");
    assert!(!password.is_empty());
    let dir = root.join(format!("guardian-{index}"));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let api = bound();
    let p2p = bound();
    let ui = bound();
    let metrics = bound();
    let api_addr = api.local_addr().unwrap();
    let p2p_addr = p2p.local_addr().unwrap();
    let log = dir.join("stderr");
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log)
        .unwrap();
    let mut cmd = Command::new(if !is_reference {
        std::path::Path::new(env!("CARGO_BIN_EXE_fedimintd"))
    } else {
        reference
    });
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("FM_") || name == "NEXTEST" {
            cmd.env_remove(name);
        }
    }
    cmd.arg("--data-dir").arg(dir.join("data"));
    if !is_reference {
        private(&dir.join("admin"), ADMIN);
        private(&dir.join("bitcoin"), credentials);
        cmd.args([
            "--api-bind",
            &api_addr.to_string(),
            "--p2p-bind",
            &p2p_addr.to_string(),
            "--bitcoin-rpc",
            &bitcoin.to_string(),
        ])
        .arg("--bitcoin-rpc-credentials-file")
        .arg(dir.join("bitcoin"))
        .arg("--admin-secret-file")
        .arg(dir.join("admin"));
    } else {
        cmd.args([
            "--bitcoin-network",
            "regtest",
            "--enable-iroh",
            "false",
            "--bind-api",
            &api_addr.to_string(),
            "--bind-p2p",
            &p2p_addr.to_string(),
            "--bind-ui",
            &ui.local_addr().unwrap().to_string(),
            "--bind-metrics",
            &metrics.local_addr().unwrap().to_string(),
            "--bitcoind-url",
            &format!("http://{bitcoin}"),
            "--password-api",
            ADMIN,
        ]);
        cmd.env("FM_BITCOIND_USERNAME", username)
            .env("FM_BITCOIND_PASSWORD", password);
    }
    cmd.args([
        "--api-url",
        &format!("ws://{api_addr}/"),
        "--p2p-url",
        &format!("fedimint://{p2p_addr}/"),
    ]);
    drop((api, p2p, ui, metrics));
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    Daemon {
        child,
        command: cmd,
        log,
        api: api_addr,
        password: password.to_owned(),
        reference: is_reference,
    }
}
fn compare(values: &[Value], label: &str) {
    for (index, value) in values.iter().enumerate().skip(1) {
        assert_eq!(
            value, &values[0],
            "mixed {label} mismatch guardian0 vs guardian{index}"
        );
    }
}

fn new_peers(value: Option<&std::ffi::OsStr>) -> Result<[usize; 2], &'static str> {
    match value.map(std::ffi::OsStr::to_str) {
        None | Some(Some("0,1")) => Ok([0, 1]),
        Some(Some("0,2")) => Ok([0, 2]),
        Some(Some("0,3")) => Ok([0, 3]),
        Some(Some("1,2")) => Ok([1, 2]),
        Some(Some("1,3")) => Ok([1, 3]),
        Some(Some("2,3")) => Ok([2, 3]),
        _ => Err("MINIMINT_MIXED_NEW_PEERS must be two distinct ascending IDs from 0..3"),
    }
}

#[test]
fn implementation_assignment_accepts_only_canonical_two_by_two_layouts() {
    use std::ffi::OsStr;
    assert_eq!(new_peers(None), Ok([0, 1]));
    for first in 0..4 {
        for second in first + 1..4 {
            let text = format!("{first},{second}");
            assert_eq!(new_peers(Some(OsStr::new(&text))), Ok([first, second]));
            let references: Vec<_> = (0..4)
                .filter(|peer| ![first, second].contains(peer))
                .collect();
            assert_eq!(references.len(), 2);
            assert_ne!(first, references[0]);
            assert_ne!(second, references[1]);
        }
    }
    for value in [
        "", "0", "0,0", "1,0", "0,4", "-1,2", "0,1,2", "0, 1", "00,1",
    ] {
        assert!(new_peers(Some(OsStr::new(value))).is_err());
    }
}

fn outage_options(
    failures: bool,
    peer: Option<&std::ffi::OsStr>,
    only: Option<&std::ffi::OsStr>,
) -> Result<(usize, bool), &'static str> {
    if !failures && (peer.is_some() || only.is_some()) {
        return Err("outage options require MINIMINT_MIXED_FAILURES=1");
    }
    let peer = match peer.map(std::ffi::OsStr::to_str) {
        None | Some(Some("1")) => 1,
        Some(Some("0")) => 0,
        Some(Some("2")) => 2,
        Some(Some("3")) => 3,
        _ => return Err("MINIMINT_MIXED_OUTAGE_PEER must be 0, 1, 2 or 3"),
    };
    let only = match only.map(std::ffi::OsStr::to_str) {
        None | Some(Some("0")) => false,
        Some(Some("1")) => true,
        _ => return Err("MINIMINT_MIXED_ONE_OUTAGE_ONLY must be 0 or 1"),
    };
    Ok((peer, only))
}

#[test]
fn outage_options_validate_all_survivor_sets_before_launch() {
    use std::ffi::OsStr;
    assert_eq!(outage_options(true, None, None), Ok((1, false)));
    for peer in 0..4 {
        assert_eq!(
            outage_options(
                true,
                Some(OsStr::new(&peer.to_string())),
                Some(OsStr::new("1"))
            ),
            Ok((peer, true))
        );
        let survivors: Vec<_> = (0..4).filter(|value| *value != peer).collect();
        assert_eq!(survivors.len(), 3);
        assert!(!survivors.contains(&peer));
    }
    for peer in ["4", "-1", "", "01", "other"] {
        assert!(outage_options(true, Some(OsStr::new(peer)), None).is_err());
    }
    assert!(outage_options(false, Some(OsStr::new("1")), None).is_err());
    assert!(outage_options(false, None, Some(OsStr::new("1"))).is_err());
    assert!(outage_options(true, None, Some(OsStr::new("yes"))).is_err());
}

fn wait_count(
    daemons: &mut [Daemon],
    rpcs: &mut [Rpc],
    peers: &[usize],
    count: u64,
    deadline: Instant,
    started: Instant,
) {
    let mut report = Instant::now();
    loop {
        let mut ready = true;
        for &peer in peers {
            daemons[peer].check();
            ready &= rpcs[peer]
                .call("session_count", json!(null), false)
                .as_u64()
                .unwrap()
                >= count;
        }
        if ready {
            return;
        }
        assert!(Instant::now() < deadline, "mixed session{count} deadline");
        if report.elapsed() >= Duration::from_secs(15) {
            eprintln!(
                "mixed waiting completed count={count} peers={peers:?} elapsed={:?}",
                started.elapsed()
            );
            report = Instant::now();
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn signed_history(rpc: &mut Rpc, index: u64) -> SignedSessionOutcome {
    let value = rpc.call("await_signed_session_outcome", json!(index), false);
    let strings: Vec<_> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    rpc::decode_hex(&strings).unwrap()
}

fn signed_backup(
    key: &minimint_ng::crypto::secp::SecretKey,
    nanos: u32,
    payload: Vec<u8>,
) -> Value {
    use minimint_ng::api::backup::{BackupTimestamp, SignedBackup};
    let mut request = SignedBackup {
        id: key.public_key(),
        payload,
        timestamp: BackupTimestamp {
            secs_since_epoch: 42,
            nanos_since_epoch: nanos,
        },
        signature: [0; 64],
    };
    request.signature = key.schnorr_sign(&request.digest()).unwrap();
    request.verify().unwrap();
    json!({"id":hex_encode(&request.id),"payload":hex_encode(&request.payload),"timestamp":request.timestamp.json(),"signature":hex_encode(&request.signature)})
}

fn empty_mint_recovery(rpc: &mut Rpc, evidence: &std::path::Path, peer: usize, phase: &str) {
    let cases = [
        ("recovery_count", json!(null), json!(0)),
        ("recovery_slice", json!([0, 1]), json!([])),
        (
            "recovery_slice_hash",
            json!([0, 1]),
            json!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
        ),
        ("recovery_signature_shares", json!([]), json!([])),
        (
            "signature_shares",
            json!({"txid":"00".repeat(32),"idx_range":{"start":0,"end":1}}),
            json!([]),
        ),
    ];
    for (method, params, expected) in cases {
        let method = format!("module_0_{method}");
        let response = rpc.call(&method, params.clone(), false);
        private(
            &evidence.join(format!("recovery-{phase}-peer{peer}-{method}.json")),
            &json!({"params":params,"response":response}).to_string(),
        );
        assert_eq!(
            response, expected,
            "empty Mint recovery {method} peer{peer}"
        );
    }
}

fn recovery_checks(
    daemons: &mut [Daemon],
    rpcs: &mut [Rpc],
    evidence: &std::path::Path,
    started: Instant,
) {
    // This client backup identity is ephemeral and never exported. Only its
    // public key, signatures, normalized timestamps and synthetic bytes persist.
    let key = minimint_ng::crypto::secp::SecretKey::random().unwrap();
    let initial = signed_backup(&key, 123456789, vec![0, 255, 42, 0, 128]);
    let replacement = signed_backup(&key, 123456790, vec![128, 0, 255, 43, 1, 0]);
    let id = json!(hex_encode(&key.public_key()));
    drop(key);
    private(
        &evidence.join("synthetic-backup-requests.json"),
        &json!({"initial":initial,"replacement":replacement}).to_string(),
    );
    let expected =
        |request: &Value| json!({"timestamp":request["timestamp"],"data":request["payload"]});
    for (peer, rpc) in rpcs.iter_mut().enumerate() {
        assert_eq!(rpc.call("recover", id.clone(), false), json!(null));
        assert_eq!(rpc.call("backup", initial.clone(), false), json!(null));
        assert_eq!(rpc.call("recover", id.clone(), false), expected(&initial));
        rpc.send("backup", initial.clone(), false).unwrap();
        let repeated = rpc.raw_reply().unwrap();
        private(
            &evidence.join(format!("backup-peer{peer}-repeated-error.json")),
            &repeated.to_string(),
        );
        assert!(
            repeated.get("error").is_some_and(|value| {
                value["code"].as_u64() == Some(400) && value["message"].as_str().is_some()
            }) && repeated.get("result").is_none(),
            "repeated timestamp must be rejected"
        );
        assert_eq!(rpc.call("recover", id.clone(), false), expected(&initial));
        assert_eq!(rpc.call("backup", replacement.clone(), false), json!(null));
        assert_eq!(
            rpc.call("recover", id.clone(), false),
            expected(&replacement)
        );
        rpc.send("backup", initial.clone(), false).unwrap();
        let older = rpc.raw_reply().unwrap();
        private(
            &evidence.join(format!("backup-peer{peer}-older-error.json")),
            &older.to_string(),
        );
        assert!(
            older.get("error").is_some_and(|value| {
                value["code"].as_u64() == Some(400) && value["message"].as_str().is_some()
            }) && older.get("result").is_none(),
            "older timestamp must be rejected"
        );
        let recovered = rpc.call("recover", id.clone(), false);
        private(
            &evidence.join(format!("backup-peer{peer}-before-restart.json")),
            &recovered.to_string(),
        );
        assert_eq!(recovered, expected(&replacement));
        empty_mint_recovery(rpc, evidence, peer, "before-restart");
    }
    let exits: Vec<_> = daemons.iter_mut().map(Daemon::stop).collect();
    private(
        &evidence.join("recovery-restart-exits.json"),
        &json!(exits).to_string(),
    );
    for (peer, daemon) in daemons.iter_mut().enumerate() {
        rpcs[peer] = daemon.restart();
    }
    for (peer, rpc) in rpcs.iter_mut().enumerate() {
        let recovered = rpc.call("recover", id.clone(), false);
        private(
            &evidence.join(format!("backup-peer{peer}-after-restart.json")),
            &recovered.to_string(),
        );
        assert_eq!(recovered, expected(&replacement));
        empty_mint_recovery(rpc, evidence, peer, "after-restart");
    }
    private(&evidence.join("recovery-checks.json"), &json!({"opaque_backup_exact_recovery":true,"strict_timestamp_replacement":true,"all_four_joined_restart":true,"empty_mint_queries":true,"nonempty_mint_recovery":false,"monetary_workflow":false,"session_history_verified_by_these_checks":false}).to_string());
    eprintln!(
        "mixed opaque backup and empty Mint recovery matched across all four joined restarts at {:?}; no monetary or signed-session claim",
        started.elapsed()
    );
}

/// The external driver and its CLI children share an owned process group. The
/// driver contract forbids daemonizing or moving descendants to another group.
struct Driver {
    child: Child,
    group: u32,
}
impl Drop for Driver {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", self.group)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
    }
}

#[test]
fn external_driver_drop_kills_and_reaps_owned_process() {
    let child = Command::new("sleep")
        .arg("30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    drop(Driver { child, group: pid });
    assert!(
        !Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}

fn driver_file(path: &std::path::Path) -> fs::File {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
}

fn monetary_survivors_option(
    value: Option<&std::ffi::OsStr>,
    driver: bool,
) -> Result<bool, &'static str> {
    match value.and_then(std::ffi::OsStr::to_str) {
        None if value.is_none() => Ok(false),
        Some("0") => Ok(false),
        Some("1") if driver => Ok(true),
        _ => Err("monetary survivor controls require external driver and value 0 or 1"),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuardianControl {
    id: u8,
    peer: usize,
    restart: bool,
}
fn guardian_control(value: &Value, next: u8) -> Result<GuardianControl, &'static str> {
    let object = value.as_object().ok_or("control object")?;
    if object.len() != 4
        || !["schema", "id", "action", "peer"]
            .iter()
            .all(|key| object.contains_key(key))
    {
        return Err("control fields");
    }
    let uint =
        |name: &str| minimint_ng::json::unsigned(&value[name]).map_err(|_| "control integer");
    if uint("schema")? != 1
        || next >= 8
        || uint("id")? != u64::from(next)
        || uint("peer")? != u64::from(next / 2)
    {
        return Err("control sequence");
    }
    let restart = next % 2 == 1;
    if value["action"].as_str() != Some(if restart { "restart" } else { "stop" }) {
        return Err("control action");
    }
    Ok(GuardianControl {
        id: next,
        peer: usize::from(next / 2),
        restart,
    })
}
#[test]
fn guardian_controls_validate_exact_bounded_sequence_and_opt_in() {
    use std::ffi::OsStr;
    assert_eq!(monetary_survivors_option(None, false), Ok(false));
    assert_eq!(
        monetary_survivors_option(Some(OsStr::new("1")), true),
        Ok(true)
    );
    assert!(monetary_survivors_option(Some(OsStr::new("1")), false).is_err());
    assert!(monetary_survivors_option(Some(OsStr::new("yes")), true).is_err());
    for id in 0..8 {
        let valid =
            json!({"schema":1,"id":id,"action":if id%2==0{"stop"}else{"restart"},"peer":id/2});
        assert_eq!(
            guardian_control(&valid, id).unwrap(),
            GuardianControl {
                id,
                peer: usize::from(id / 2),
                restart: id % 2 == 1
            }
        );
        assert!(guardian_control(&valid, (id + 1) % 8).is_err());
    }
    for invalid in [
        json!(null),
        json!({"schema":1,"id":0,"action":"stop","peer":0,"pid":1}),
        json!({"schema":1,"id":0,"action":"kill","peer":0}),
        json!({"schema":1,"id":0,"action":"stop","peer":4}),
        json!({"schema":1,"id":0.0,"action":"stop","peer":0}),
        json!({"schema":1,"id":0,"action":"stop","peer":"0"}),
        json!({"schema":2,"id":0,"action":"stop","peer":0}),
    ] {
        assert!(guardian_control(&invalid, 0).is_err());
    }
    assert!(guardian_control(&json!({"schema":1,"id":8,"action":"stop","peer":4}), 8).is_err());
}

#[test]
fn guardian_owned_fixture_child() {
    let Some(ready) = std::env::var_os("MINIMINT_GUARDIAN_OWNED_CHILD") else {
        return;
    };
    let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone()).unwrap();
    fs::write(ready, b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
        assert!(Instant::now() < deadline, "owned child fixture deadline");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn guardian_stop_joins_before_ack_and_restart_replaces_only_owned_child() {
    // The owned child exercises lifecycle/TERM/reaping only. A separate owned
    // local WebSocket listener supplies connect handshakes, not guardian state.
    struct ApiFixture {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        join: Option<thread::JoinHandle<()>>,
    }
    impl Drop for ApiFixture {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            self.join.take().unwrap().join().unwrap();
        }
    }
    let listener = bound();
    let api = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let _api = ApiFixture {
        stop,
        join: Some(thread::spawn(move || {
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = WebSocket::accept(
                            stream,
                            None,
                            Limits {
                                handshake_timeout: Duration::from_secs(1),
                                operation_timeout: Duration::from_secs(1),
                                ..Limits::default()
                            },
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        })),
    };
    let directory = fixture::TestDir::new();
    let ready = directory.path().join("ready");
    let log = directory.path().join("child.log");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "guardian_owned_fixture_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MINIMINT_GUARDIAN_OWNED_CHILD", &ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(driver_file(&log)));
    let child = command.spawn().unwrap();
    let mut daemon = Daemon {
        child,
        command,
        log,
        api,
        password: "unused-owned-fixture".into(),
        reference: false,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let wait_ready = |daemon: &mut Daemon| {
        while !ready.exists() {
            daemon.check();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
    };
    wait_ready(&mut daemon);
    let original = daemon.child.id();
    let exit = daemon.stop_until(deadline);
    assert_eq!(exit, 0);
    assert!(daemon.child.try_wait().unwrap().is_some());
    guardian_ack(
        directory.path(),
        GuardianControl {
            id: 0,
            peer: 0,
            restart: false,
        },
        Some(exit),
        7,
    );
    let ack = minimint_ng::json::parse(
        &fs::read(directory.path().join("guardian-ack-0.json")).unwrap(),
        1024,
        8,
    )
    .unwrap();
    assert_eq!(ack["exit"].as_i64(), Some(0));
    assert_eq!(ack["completed_count"].as_u64(), Some(7));
    fs::remove_file(&ready).unwrap();
    let _rpc = daemon.restart_until(deadline);
    wait_ready(&mut daemon);
    assert_ne!(daemon.child.id(), original);
    assert!(daemon.child.try_wait().unwrap().is_none());
    assert_eq!(daemon.stop_until(deadline), 0);
}
fn driver_deadline(deadline: Instant) {
    assert!(
        Instant::now() < deadline,
        "original external driver deadline"
    );
}
fn reconnect_live(daemons: &mut [Daemon], rpcs: &mut [Rpc], peers: &[usize], deadline: Instant) {
    for &peer in peers {
        driver_deadline(deadline);
        rpcs[peer] = daemons[peer].connect_until(deadline);
    }
}
fn control_count(
    daemons: &mut [Daemon],
    rpcs: &mut [Rpc],
    peers: &[usize],
    deadline: Instant,
    started: Instant,
) -> u64 {
    reconnect_live(daemons, rpcs, peers, deadline);
    let count = peers
        .iter()
        .map(|&peer| {
            driver_deadline(deadline);
            rpcs[peer]
                .call("session_count", json!(null), false)
                .as_u64()
                .unwrap()
        })
        .max()
        .unwrap();
    assert!(count <= 1024, "bounded monetary survivor history");
    wait_count(daemons, rpcs, peers, count, deadline, started);
    driver_deadline(deadline);
    count
}
fn control_verifier(config: &Value) -> HistoryVerifier {
    HistoryVerifier::new(
        config["broadcast_public_keys"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(p, k)| {
                (
                    PeerId(p.parse().unwrap()),
                    minimint_ng::codec::text::hex_decode(k.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            })
            .collect(),
    )
    .unwrap()
}
fn control_histories(
    daemons: &mut [Daemon],
    rpcs: &mut [Rpc],
    peers: &[usize],
    config: &Value,
    evidence: &std::path::Path,
    label: &str,
    count: u64,
    deadline: Instant,
) {
    reconnect_live(daemons, rpcs, peers, deadline);
    let verifier = control_verifier(config);
    for index in 0..count {
        let mut outcomes = Vec::new();
        for &peer in peers {
            driver_deadline(deadline);
            let history = signed_history(&mut rpcs[peer], index);
            verifier
                .verify(index, &history, SignaturePolicy::GuardianAdoption)
                .unwrap();
            private(
                &evidence.join(format!("{label}-peer{peer}-signed-session{index}.json")),
                &json!(rpc::hex(&history)).to_string(),
            );
            outcomes.push(history.outcome);
        }
        assert!(outcomes.iter().all(|v| v == &outcomes[0]));
    }
    driver_deadline(deadline);
}

/// A later session count alone is not monetary evidence. Resolve the driver's
/// fresh destination to exactly one accepted Wallet output, then bind that
/// Fedimint output location to the observed Bitcoin child on every live peer.
fn control_monetary_target(
    rpcs: &mut [Rpc],
    peers: &[usize],
    evidence: &std::path::Path,
    label: &str,
    count: u64,
    stopped_count: u64,
    marker: &Value,
    deadline: Instant,
) -> Transaction {
    use minimint_ng::modules::wallet::Output;
    let script = minimint_ng::codec::text::hex_decode(
        marker["destination_script"]
            .as_str()
            .expect("public destination script"),
    )
    .unwrap();
    assert!(
        script.len() == 22 && script.starts_with(&[0, 20]),
        "survivor destination must be fresh P2WPKH"
    );
    assert_eq!(
        minimint_ng::json::unsigned(&marker["amount_sat"]).unwrap(),
        10_000
    );
    let fee = minimint_ng::json::unsigned(&marker["fee_sat"]).unwrap();
    assert!(fee > 0);
    let bitcoin_id = marker["bitcoin_txid"]
        .as_str()
        .expect("public Bitcoin txid");
    assert_eq!(
        minimint_ng::codec::text::hex_decode(bitcoin_id)
            .unwrap()
            .len(),
        32
    );
    let post = minimint_ng::json::unsigned(&marker["post_broadcast_completed_count"]).unwrap();
    let final_count = minimint_ng::json::unsigned(&marker["final_count"]).unwrap();
    assert!(post >= stopped_count && final_count > post && count >= final_count);
    let survivor_keys: Vec<_> = peers.iter().map(|&p| PeerId(p as u16)).collect();
    let mut common = None;
    let mut common_transaction = None;
    for &peer in peers {
        let mut found = Vec::new();
        for index in 0..count {
            let bytes =
                fs::read(evidence.join(format!("{label}-peer{peer}-signed-session{index}.json")))
                    .unwrap();
            let value = minimint_ng::json::parse(&bytes, 16 * 1024 * 1024, 64).unwrap();
            let strings: Vec<_> = value
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            let history: SignedSessionOutcome = rpc::decode_hex(&strings).unwrap();
            for item in &history.outcome.items {
                if let minimint_ng::protocol::ConsensusItem::Transaction(transaction) = &item.item {
                    for (out_idx, output) in transaction.outputs.iter().enumerate() {
                        if output.module_id.0 != 1 {
                            continue;
                        }
                        let decoded: Output =
                            minimint_ng::codec::decode_whole(&output.payload).unwrap();
                        if let Output::V0 {
                            destination,
                            value_sat,
                            mining_fee_sat,
                        } = decoded
                        {
                            if value_sat == 10_000
                                && mining_fee_sat == fee
                                && destination.script_pubkey().as_ref() == Some(&script)
                            {
                                assert!(
                                    index >= stopped_count,
                                    "target destination was already accepted before outage"
                                );
                                if peers.len() == 3 {
                                    assert_eq!(
                                        history.signatures.keys().copied().collect::<Vec<_>>(),
                                        survivor_keys,
                                        "target transaction certificate includes offline guardian"
                                    );
                                }
                                found.push((transaction_id(transaction), out_idx as u64, index));
                                if let Some(old) = &common_transaction {
                                    assert_eq!(old, transaction);
                                } else {
                                    common_transaction = Some(transaction.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(
            found.len(),
            1,
            "fresh monetary Wallet output must occur exactly once"
        );
        let (txid, out_idx, index) = found[0];
        if let Some(expected) = common {
            assert_eq!(expected, (txid, out_idx, index));
        } else {
            common = Some((txid, out_idx, index));
        }
        driver_deadline(deadline);
        let mapped = rpcs[peer].call(
            "module_1_transaction_id",
            json!({"txid":hex_encode(&txid),"out_idx":out_idx}),
            false,
        );
        assert_eq!(mapped.as_str(), Some(bitcoin_id));
        private(&evidence.join(format!("{label}-peer{peer}-target.json")),&json!({"transaction_id":hex_encode(&txid),"out_idx":out_idx,"session":index,"bitcoin_txid":mapped}).to_string());
    }
    driver_deadline(deadline);
    common_transaction.unwrap()
}

type ReissueMarkers = BTreeMap<(u8, [u8; 32]), usize>;
fn reissue_markers(value: &Value) -> Result<ReissueMarkers, &'static str> {
    let values = value.as_array().ok_or("reissue notes array")?;
    if values.is_empty() || values.len() > 256 {
        return Err("reissue marker bound");
    }
    let mut result = BTreeMap::new();
    for value in values {
        let object = value.as_object().ok_or("note marker object")?;
        if object.len() != 2
            || !object.contains_key(&"denomination")
            || !object.contains_key(&"signature_sha256")
        {
            return Err("note marker fields");
        }
        let denomination =
            minimint_ng::json::unsigned(&value["denomination"]).map_err(|_| "note denomination")?;
        if denomination > 41 {
            return Err("note denomination");
        }
        let text = value["signature_sha256"]
            .as_str()
            .ok_or("note signature hash")?;
        let hash: [u8; 32] = minimint_ng::codec::text::hex_decode(text)
            .map_err(|_| "note signature hash")?
            .try_into()
            .map_err(|_| "note signature hash")?;
        if hex_encode(&hash) != text {
            return Err("canonical note signature hash");
        }
        if result.insert((denomination as u8, hash), 1).is_some() {
            return Err("duplicate note marker");
        }
    }
    Ok(result)
}
fn transaction_note_markers(transaction: &Transaction) -> Option<ReissueMarkers> {
    use minimint_ng::modules::mint::Input;
    if transaction.inputs.is_empty() || transaction.inputs.len() > 256 {
        return None;
    }
    let mut result = BTreeMap::new();
    for input in &transaction.inputs {
        if input.module_id.0 != 0 {
            return None;
        }
        let Input::V0(note) = minimint_ng::codec::decode_whole::<Input>(&input.payload).ok()?
        else {
            return None;
        };
        *result
            .entry((
                note.denomination,
                minimint_ng::crypto::sha256(&note.signature.to_bytes()),
            ))
            .or_insert(0) += 1;
    }
    Some(result)
}
// A client may consolidate existing notes while reissuing the exported notes.
// Require every exported marker exactly once, and reject duplicate consumption
// of any note; additional bounded Mint inputs are legitimate.
fn consumes_reissue_markers(transaction: &Transaction, expected: &ReissueMarkers) -> bool {
    transaction_note_markers(transaction).is_some_and(|actual| {
        !expected.is_empty()
            && actual.values().all(|count| *count == 1)
            && expected
                .iter()
                .all(|(marker, count)| *count == 1 && actual.get(marker) == Some(&1))
    })
}
#[test]
fn reissue_markers_identify_complete_captured_note_set_not_just_denominations() {
    let bytes = include_bytes!(
        "fixtures/interop/mixed-monetary-2026-09-11/monetary_observed/peer2-signed-session-2.json"
    );
    let value = minimint_ng::json::parse(bytes, 1024 * 1024, 64).unwrap();
    let strings: Vec<_> = value["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let history: SignedSessionOutcome = rpc::decode_hex(&strings).unwrap();
    let transaction = history
        .outcome
        .items
        .iter()
        .find_map(|accepted| match &accepted.item {
            minimint_ng::protocol::ConsensusItem::Transaction(t)
                if transaction_note_markers(t).is_some() =>
            {
                Some(t)
            }
            _ => None,
        })
        .unwrap();
    let expected = transaction_note_markers(transaction).unwrap();
    assert!(expected.len() > 1);
    let markers: Vec<_> = expected
        .keys()
        .map(|(d, h)| json!({"denomination":d,"signature_sha256":hex_encode(h)}))
        .collect();
    assert_eq!(reissue_markers(&json!(markers)).unwrap(), expected);
    let mut omitted = markers.clone();
    omitted.pop();
    assert_ne!(reissue_markers(&json!(omitted)).unwrap(), expected);
    let mut changed = markers.clone();
    changed[0] =
        json!({"denomination":markers[0]["denomination"],"signature_sha256":"00".repeat(32)});
    assert_ne!(reissue_markers(&json!(changed)).unwrap(), expected);
    let mut duplicate = markers.clone();
    duplicate.push(markers[0].clone());
    assert!(reissue_markers(&json!(duplicate)).is_err());
    for invalid in [
        json!([]),
        json!([{"denomination":42,"signature_sha256":"00".repeat(32)}]),
        json!([{"denomination":1.0,"signature_sha256":"00".repeat(32)}]),
        json!([{"denomination":1,"signature_sha256":"AA".repeat(32)}]),
        json!([{"denomination":1,"signature_sha256":"00"}]),
    ] {
        assert!(reissue_markers(&invalid).is_err());
    }
}
fn saved_control_history(
    evidence: &std::path::Path,
    label: &str,
    peer: usize,
    index: u64,
) -> SignedSessionOutcome {
    let bytes =
        fs::read(evidence.join(format!("{label}-peer{peer}-signed-session{index}.json"))).unwrap();
    let value = minimint_ng::json::parse(&bytes, 16 * 1024 * 1024, 64).unwrap();
    let strings: Vec<_> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    rpc::decode_hex(&strings).unwrap()
}
#[test]
fn reissue_target_accepts_captured_existing_note_consolidation() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop/mixed-monetary-survivor-partial-case3-2026-09-11");
    let read = |name: &str| {
        minimint_ng::json::parse(&fs::read(fixture.join(name)).unwrap(), 16 * 1024 * 1024, 64)
            .unwrap()
    };
    let manifest = read("manifest.json");
    let listed: BTreeSet<_> = manifest["sha256"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, digest)| {
            let path = fixture.join(name);
            assert!(path.is_file() && !path.is_symlink());
            assert_eq!(
                hex_encode(&minimint_ng::crypto::sha256(&fs::read(path).unwrap())),
                digest.as_str().unwrap()
            );
            name.to_owned()
        })
        .collect();
    let actual: BTreeSet<_> = fs::read_dir(&fixture)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
        .filter(|name| name != "manifest.json")
        .collect();
    assert_eq!(actual, listed);
    let marker = read("survivor-case-3-public.json");
    let expected = reissue_markers(&marker["reissue_notes"]).unwrap();
    assert_eq!(expected.len(), 6);
    let verifier = control_verifier(&read("peer0-client_config.json"));
    let label = "guardian-control7-before-restart";
    let temporary = std::env::temp_dir().join(format!(
        "minimint-reissue-marker-regression-{}",
        std::process::id()
    ));
    fs::create_dir(&temporary).unwrap();
    for index in 0..9 {
        let reference = saved_control_history(&fixture, label, 0, index);
        for peer in 0..3 {
            let history = saved_control_history(&fixture, label, peer, index);
            verifier
                .verify(index, &history, SignaturePolicy::GuardianAdoption)
                .unwrap();
            assert_eq!(history.outcome, reference.outcome);
            let name = format!("{label}-peer{peer}-signed-session{index}.json");
            fs::copy(fixture.join(&name), temporary.join(name)).unwrap();
        }
    }
    let target = control_reissue_target(
        &[0, 1, 2],
        &temporary,
        label,
        9,
        read("guardian-ack-6.json")["completed_count"]
            .as_u64()
            .unwrap(),
        &marker,
        Instant::now() + Duration::from_secs(30),
    );
    assert_eq!(
        hex_encode(&transaction_id(&target)),
        "248ee4f3321b867d07eef52bad61152ae6a61f869d240b708773aba0f0c8179d"
    );
    assert_eq!((target.inputs.len(), target.outputs.len()), (14, 7));
    let mut missing = target.clone();
    let position = missing
        .inputs
        .iter()
        .position(|input| {
            let mut single = target.clone();
            single.inputs = vec![input.clone()];
            transaction_note_markers(&single)
                .unwrap()
                .keys()
                .any(|key| expected.contains_key(key))
        })
        .unwrap();
    missing.inputs.remove(position);
    assert!(!consumes_reissue_markers(&missing, &expected));
    let mut duplicate = target.clone();
    duplicate.inputs.push(target.inputs[position].clone());
    assert!(!consumes_reissue_markers(&duplicate, &expected));
    let mut non_mint = target.clone();
    non_mint.inputs[0].module_id.0 = 1;
    assert!(!consumes_reissue_markers(&non_mint, &expected));
    let mut oversized = target.clone();
    oversized.inputs = vec![target.inputs[0].clone(); 257];
    assert!(!consumes_reissue_markers(&oversized, &expected));
    fs::remove_dir_all(temporary).unwrap();
}
fn control_reissue_target(
    peers: &[usize],
    evidence: &std::path::Path,
    label: &str,
    count: u64,
    stopped_count: u64,
    marker: &Value,
    deadline: Instant,
) -> Transaction {
    let expected = reissue_markers(&marker["reissue_notes"]).expect("public reissue markers");
    let survivor_keys: Vec<_> = peers.iter().map(|&p| PeerId(p as u16)).collect();
    let mut common = None;
    for &peer in peers {
        let mut found = Vec::new();
        let mut marker_uses = BTreeMap::new();
        for index in 0..count {
            driver_deadline(deadline);
            let history = saved_control_history(evidence, label, peer, index);
            for accepted in history.outcome.items {
                if let minimint_ng::protocol::ConsensusItem::Transaction(transaction) =
                    accepted.item
                {
                    for input in transaction
                        .inputs
                        .iter()
                        .filter(|input| input.module_id.0 == 0)
                    {
                        let minimint_ng::modules::mint::Input::V0(note) =
                            minimint_ng::codec::decode_whole::<minimint_ng::modules::mint::Input>(
                                &input.payload,
                            )
                            .expect("accepted Mint input")
                        else {
                            panic!("accepted Mint input version")
                        };
                        let marker = (
                            note.denomination,
                            minimint_ng::crypto::sha256(&note.signature.to_bytes()),
                        );
                        if expected.contains_key(&marker) {
                            *marker_uses.entry(marker).or_insert(0) += 1;
                        }
                    }
                    if consumes_reissue_markers(&transaction, &expected) {
                        assert!(index >= stopped_count, "reissue target predates outage");
                        assert!(
                            !transaction.outputs.is_empty()
                                && transaction.outputs.len() <= 256
                                && transaction.outputs.iter().all(|o| o.module_id.0 == 0),
                            "target must be bounded Mint reissuance"
                        );
                        if peers.len() == 3 {
                            assert_eq!(
                                history.signatures.keys().copied().collect::<Vec<_>>(),
                                survivor_keys,
                                "reissue target certificate includes offline guardian"
                            );
                        }
                        found.push((index, transaction));
                    }
                }
            }
        }
        assert_eq!(
            marker_uses, expected,
            "each exported marker consumed exactly once in completed history"
        );
        assert_eq!(
            found.len(),
            1,
            "exactly one fresh reissue must consume all exported notes"
        );
        let (index, transaction) = found.pop().unwrap();
        if let Some(old) = &common {
            assert_eq!(old, &transaction);
        } else {
            common = Some(transaction.clone());
        }
        private(&evidence.join(format!("{label}-peer{peer}-reissue-target.json")),&json!({"transaction_id":hex_encode(&transaction_id(&transaction)),"session":index,"input_count":transaction.inputs.len(),"output_count":transaction.outputs.len()}).to_string());
    }
    common.unwrap()
}
fn restored_mint_shares(
    rpc: &mut Rpc,
    peer: usize,
    config: &Value,
    targets: &[(&str, &Transaction)],
    evidence: &std::path::Path,
    label: &str,
    deadline: Instant,
) {
    use minimint_ng::{
        config::RawMintConfig,
        crypto::bls::{self, G1, G2},
        modules::mint::Output,
        protocol::DynamicValue,
    };
    let dynamic: DynamicValue = minimint_ng::codec::decode_whole(
        &minimint_ng::codec::text::hex_decode(config["modules"]["0"]["config"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dynamic.module_id.0, 0);
    let mint: RawMintConfig = minimint_ng::codec::decode_whole(&dynamic.payload).unwrap();
    for &(name, transaction) in targets {
        assert!(transaction.outputs.len() <= 256);
        let txid = transaction_id(transaction);
        let mut replies = Vec::new();
        for (index, output) in transaction.outputs.iter().enumerate() {
            if output.module_id.0 != 0 {
                continue;
            }
            let Output::V0(output) =
                minimint_ng::codec::decode_whole::<Output>(&output.payload).unwrap()
            else {
                panic!("Mint output version")
            };
            let request =
                json!({"txid":hex_encode(&txid),"idx_range":{"start":index,"end":index+1}});
            driver_deadline(deadline);
            let reply = rpc.call("module_0_signature_shares", request.clone(), false);
            let values = reply.as_array().unwrap();
            assert_eq!(values.len(), 1, "restored peer missing output share");
            let encoded: [u8; 48] =
                minimint_ng::codec::text::hex_decode(values[0].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
            bls::verify_share(
                &G1::from_bytes(&output.blinded_message.to_bytes()).unwrap(),
                &G2::from_bytes(&mint.public_shares[&output.denomination][&PeerId(peer as u16)])
                    .unwrap(),
                &G1::from_bytes(&encoded).unwrap(),
            )
            .expect("restored guardian's public signing share");
            replies.push(json!({"request":request,"response":reply,"output_index":index,"denomination":output.denomination}));
        }
        assert!(!replies.is_empty(), "target must issue Mint outputs");
        private(
            &evidence.join(format!("{label}-peer{peer}-{name}-signature-shares.json")),
            &json!(replies).to_string(),
        );
    }
    driver_deadline(deadline);
}
fn current_money(rpc: &mut Rpc, deadline: Instant) -> Value {
    let mut values = BTreeMap::new();
    for method in [
        "federation_wallet",
        "transaction_chain",
        "pending_transaction_chain",
        "consensus_block_count",
        "consensus_feerate",
        "receive_fee",
        "send_fee",
    ] {
        driver_deadline(deadline);
        values.insert(
            format!("module_1_{method}"),
            rpc.call(&format!("module_1_{method}"), json!(null), false),
        );
    }
    driver_deadline(deadline);
    values.insert(
        "module_1_output_info_slice".into(),
        rpc.call("module_1_output_info_slice", json!([0, u64::MAX]), false),
    );
    driver_deadline(deadline);
    let count = rpc
        .call("module_0_recovery_count", json!(null), false)
        .as_u64()
        .unwrap();
    assert!(count <= 100_000, "bounded recovery capture");
    values.insert("module_0_recovery_count".into(), json!(count));
    for method in ["recovery_slice", "recovery_slice_hash"] {
        driver_deadline(deadline);
        values.insert(
            format!("module_0_{method}"),
            rpc.call(&format!("module_0_{method}"), json!([0, count]), false),
        );
    }
    driver_deadline(deadline);
    json!(values)
}
fn equal_money(
    daemons: &mut [Daemon],
    rpcs: &mut [Rpc],
    peers: &[usize],
    evidence: &std::path::Path,
    label: &str,
    deadline: Instant,
) -> Value {
    loop {
        reconnect_live(daemons, rpcs, peers, deadline);
        let values: Vec<_> = peers
            .iter()
            .map(|&peer| current_money(&mut rpcs[peer], deadline))
            .collect();
        if values.iter().all(|v| v == &values[0]) {
            for (&peer, value) in peers.iter().zip(&values) {
                private(
                    &evidence.join(format!("{label}-peer{peer}-money.json")),
                    &value.to_string(),
                );
            }
            return values[0].clone();
        }
        driver_deadline(deadline);
        thread::sleep(Duration::from_millis(100));
    }
}
fn guardian_ack(
    evidence: &std::path::Path,
    control: GuardianControl,
    exit: Option<i32>,
    count: u64,
) {
    use std::io::Write;
    let temporary = evidence.join(format!("guardian-ack-{}.tmp", control.id));
    let mut file = driver_file(&temporary);
    file.write_all(json!({"schema":1,"id":control.id,"action":if control.restart{"restart"}else{"stop"},"peer":control.peer,"exit":exit,"completed_count":count}).to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let target = evidence.join(format!("guardian-ack-{}.json", control.id));
    assert!(!target.exists());
    fs::rename(temporary, target).unwrap();
}
#[derive(Default)]
struct GuardianControls {
    next: u8,
    offline: Option<usize>,
    stopped_count: u64,
}
impl GuardianControls {
    fn poll(
        &mut self,
        daemons: &mut [Daemon],
        rpcs: &mut [Rpc],
        config: &Value,
        evidence: &std::path::Path,
        deadline: Instant,
        started: Instant,
    ) {
        let path = evidence.join("guardian-control.json");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => panic!("control metadata: {e}"),
        };
        assert!(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 1024,
            "control must be a small regular file"
        );
        let value = minimint_ng::json::parse(&fs::read(&path).unwrap(), 1024, 8).unwrap();
        let control = guardian_control(&value, self.next).expect("guardian control rejected");
        fs::rename(
            path,
            evidence.join(format!("guardian-control-consumed-{}.json", control.id)),
        )
        .unwrap();
        driver_deadline(deadline);
        let label = format!("guardian-control{}", control.id);
        let count;
        let exit;
        if !control.restart {
            assert!(self.offline.is_none());
            let peers = [0, 1, 2, 3];
            count = control_count(daemons, rpcs, &peers, deadline, started);
            control_histories(
                daemons,
                rpcs,
                &peers,
                config,
                evidence,
                &format!("{label}-before-stop"),
                count,
                deadline,
            );
            equal_money(
                daemons,
                rpcs,
                &peers,
                evidence,
                &format!("{label}-before-stop"),
                deadline,
            );
            exit = Some(daemons[control.peer].stop_until(deadline));
            self.offline = Some(control.peer);
            self.stopped_count = count;
        } else {
            assert_eq!(self.offline, Some(control.peer));
            let marker_path = evidence.join(format!("survivor-case-{}-public.json", control.peer));
            let metadata = fs::symlink_metadata(&marker_path)
                .expect("public survivor case marker required before restart");
            assert!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 65536
            );
            let marker =
                minimint_ng::json::parse(&fs::read(marker_path).unwrap(), 65536, 8).unwrap();
            assert_eq!(marker["schema"].as_u64(), Some(1));
            assert_eq!(marker["peer"].as_u64(), Some(control.peer as u64));
            let survivors: Vec<_> = (0..4).filter(|p| *p != control.peer).collect();
            count = control_count(daemons, rpcs, &survivors, deadline, started);
            assert!(
                count > self.stopped_count,
                "restart requires fresh completed survivor history"
            );
            control_histories(
                daemons,
                rpcs,
                &survivors,
                config,
                evidence,
                &format!("{label}-before-restart"),
                count,
                deadline,
            );
            let withdrawal_before = control_monetary_target(
                rpcs,
                &survivors,
                evidence,
                &format!("{label}-before-restart"),
                count,
                self.stopped_count,
                &marker,
                deadline,
            );
            let reissue_before = control_reissue_target(
                &survivors,
                evidence,
                &format!("{label}-before-restart"),
                count,
                self.stopped_count,
                &marker,
                deadline,
            );
            let before = equal_money(
                daemons,
                rpcs,
                &survivors,
                evidence,
                &format!("{label}-before-restart"),
                deadline,
            );
            rpcs[control.peer] = daemons[control.peer].restart_until(deadline);
            self.offline = None;
            reconnect_live(daemons, rpcs, &[0, 1, 2, 3], deadline);
            wait_count(daemons, rpcs, &[0, 1, 2, 3], count, deadline, started);
            control_histories(
                daemons,
                rpcs,
                &[0, 1, 2, 3],
                config,
                evidence,
                &format!("{label}-after-restart"),
                count,
                deadline,
            );
            let withdrawal_after = control_monetary_target(
                rpcs,
                &[0, 1, 2, 3],
                evidence,
                &format!("{label}-after-restart"),
                count,
                self.stopped_count,
                &marker,
                deadline,
            );
            let reissue_after = control_reissue_target(
                &[0, 1, 2, 3],
                evidence,
                &format!("{label}-after-restart"),
                count,
                self.stopped_count,
                &marker,
                deadline,
            );
            assert_eq!(withdrawal_before, withdrawal_after);
            assert_eq!(reissue_before, reissue_after);
            for index in 0..count {
                let before = saved_control_history(
                    evidence,
                    &format!("{label}-before-restart"),
                    survivors[0],
                    index,
                );
                for peer in 0..4 {
                    let after = saved_control_history(
                        evidence,
                        &format!("{label}-after-restart"),
                        peer,
                        index,
                    );
                    assert_eq!(
                        before.outcome, after.outcome,
                        "restart changed completed history"
                    );
                }
            }
            rpcs[control.peer] = daemons[control.peer].connect_until(deadline);
            restored_mint_shares(
                &mut rpcs[control.peer],
                control.peer,
                config,
                &[
                    ("reissue", &reissue_after),
                    ("withdrawal", &withdrawal_after),
                ],
                evidence,
                &label,
                deadline,
            );
            let after = equal_money(
                daemons,
                rpcs,
                &[0, 1, 2, 3],
                evidence,
                &format!("{label}-after-restart"),
                deadline,
            );
            assert_eq!(
                before, after,
                "restart duplicated or changed monetary state"
            );
            exit = None;
        }
        driver_deadline(deadline);
        guardian_ack(evidence, control, exit, count);
        self.next += 1;
    }
}

fn external_driver(
    daemons: &mut [Daemon],
    rpcs: &mut [Rpc],
    configs: &[Value],
    evidence: &std::path::Path,
    executable: &std::path::Path,
    started: Instant,
) {
    assert!(
        executable.is_absolute(),
        "driver executable must have an absolute path"
    );
    let timeout = std::env::var("MINIMINT_MIXED_DRIVER_TIMEOUT_SECS")
        .map(|value| value.parse::<u64>().expect("driver timeout seconds"))
        .unwrap_or(1200);
    assert!(
        (1..=3600).contains(&timeout),
        "driver timeout must be 1..=3600 seconds"
    );
    let monetary_survivors = monetary_survivors_option(
        std::env::var_os("MINIMINT_MIXED_MONETARY_SURVIVORS").as_deref(),
        true,
    )
    .unwrap();
    let mut controls = GuardianControls::default();
    let deadline = Instant::now() + Duration::from_secs(timeout);
    // Setup publishes the API before initial Wallet votes necessarily agree.
    // The monetary driver needs real, matching quotes; no fallback is supplied.
    let quote_deadline = Instant::now() + Duration::from_secs(60);
    let check_deadline = || {
        assert!(
            Instant::now() < quote_deadline && Instant::now() < deadline,
            "monetary driver requires genuine matching Wallet quotes before deadline"
        );
    };
    loop {
        check_deadline();
        let quotes: Vec<_> = rpcs
            .iter_mut()
            .map(|rpc| {
                check_deadline();
                let receive = rpc.call("module_1_receive_fee", json!(null), false);
                check_deadline();
                let send = rpc.call("module_1_send_fee", json!(null), false);
                check_deadline();
                (receive, send)
            })
            .collect();
        if quotes.iter().all(|(receive, send)| {
            receive.as_u64().is_some_and(|fee| fee > 0) && send.as_u64().is_some_and(|fee| fee > 0)
        }) && quotes.windows(2).all(|pair| pair[0] == pair[1])
        {
            private(
                &evidence.join("wallet-quote-readiness.json"),
                &json!({"receive_fee_sat":quotes[0].0,"send_fee_sat":quotes[0].1,"all_four_equal":true,"synthetic_fee":false}).to_string(),
            );
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }
    let invites: Vec<_> = rpcs
        .iter_mut()
        .map(|rpc| rpc.call("invite_code", json!(null), false))
        .collect();
    let endpoints: Vec<_> = daemons
        .iter()
        .map(|daemon| format!("ws://{}/", daemon.api))
        .collect();
    let federation_id = rpcs[0].call("federation_id", json!(null), false);
    private(
        &evidence.join("handoff.json"),
        &json!({
            "schema":1,
            "api_urls":endpoints,
            "invite_codes":invites,
            "client_config":configs[0],
            "federation_id":federation_id,
            "result_path":evidence.join("driver-result.json").to_str().unwrap(),
            "progress_path":evidence.join("driver-progress.json").to_str().unwrap(),
            "monetary_survivors":monetary_survivors
        })
        .to_string(),
    );
    assert!(
        Instant::now() < deadline,
        "monetary driver deadline elapsed before spawn"
    );
    let child = Command::new(executable)
        .arg("--handoff")
        .arg(evidence)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(driver_file(
            &evidence.join("driver-stdout.private.log"),
        )))
        .stderr(Stdio::from(driver_file(
            &evidence.join("driver-stderr.private.log"),
        )))
        .spawn()
        .expect("external driver spawn");
    let mut driver = Driver {
        group: child.id(),
        child,
    };
    let mut report = Instant::now();
    loop {
        driver_deadline(deadline);
        if monetary_survivors {
            controls.poll(daemons, rpcs, &configs[0], evidence, deadline, started);
        }
        for (peer, daemon) in daemons.iter_mut().enumerate() {
            if controls.offline != Some(peer) {
                daemon.check();
            }
        }
        if let Some(status) = driver.child.try_wait().unwrap() {
            // Never include driver output: CLI diagnostics may contain secrets.
            assert!(
                status.success(),
                "external driver failed with {status}; private logs retained"
            );
            assert!(
                controls.offline.is_none(),
                "driver exited during joined outage"
            );
            assert!(
                !monetary_survivors || controls.next == 8,
                "driver did not complete all four monetary survivor cases"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "external driver deadline; private logs retained"
        );
        if report.elapsed() >= Duration::from_secs(15) {
            eprintln!(
                "mixed external driver active; guardians healthy elapsed={:?}",
                started.elapsed()
            );
            report = Instant::now();
        }
        thread::sleep(Duration::from_millis(100));
    }
    drop(driver);
    let result_path = evidence.join("driver-result.json");
    assert!(
        fs::metadata(&result_path).unwrap().len() <= 1024 * 1024,
        "external result size limit"
    );
    let result_bytes = fs::read(&result_path).unwrap();
    let result = minimint_ng::json::parse(&result_bytes, 1024 * 1024, 32).unwrap();
    assert!(
        result["schema"].as_u64() == Some(1),
        "external result schema"
    );
    assert!(
        result["status"].as_str() == Some("passed"),
        "external result status"
    );
    assert!(result["monetary_workflow"].as_bool().is_some());
    let checks = result["checks"].as_array().expect("external named checks");
    assert!(
        !checks.is_empty()
            && checks
                .iter()
                .all(|check| check.as_str().is_some_and(|name| !name.trim().is_empty()))
    );
    // Observe independent public evidence, without interpreting opaque driver
    // assertions or labeling a diagnostic callback as monetary verification.
    // Driver checkpoints can outlive the server's idle WebSocket timeout.
    reconnect_live(daemons, rpcs, &[0, 1, 2, 3], deadline);
    let counts: Vec<_> = rpcs
        .iter_mut()
        .map(|rpc| {
            rpc.call("session_count", json!(null), false)
                .as_u64()
                .unwrap()
        })
        .collect();
    let count = *counts.iter().max().unwrap();
    assert!(count <= 1024, "bounded history capture");
    wait_count(daemons, rpcs, &[0, 1, 2, 3], count, deadline, started);
    let keys = configs[0]["broadcast_public_keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(peer, value)| {
            (
                PeerId(peer.parse().unwrap()),
                minimint_ng::codec::text::hex_decode(value.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    let verifier = HistoryVerifier::new(keys).unwrap();
    for index in 0..count {
        let mut outcomes = Vec::new();
        for (peer, rpc) in rpcs.iter_mut().enumerate() {
            driver_deadline(deadline);
            let history = signed_history(rpc, index);
            verifier
                .verify(index, &history, SignaturePolicy::GuardianAdoption)
                .unwrap();
            private(
                &evidence.join(format!("driver-peer{peer}-signed-session{index}.json")),
                &json!(rpc::hex(&history)).to_string(),
            );
            outcomes.push(history.outcome);
        }
        assert!(outcomes.iter().all(|outcome| outcome == &outcomes[0]));
    }
    for (peer, rpc) in rpcs.iter_mut().enumerate() {
        for method in [
            "consensus_block_count",
            "consensus_feerate",
            "federation_wallet",
            "transaction_chain",
            "pending_transaction_chain",
        ] {
            driver_deadline(deadline);
            let value = rpc.call(&format!("module_1_{method}"), json!(null), false);
            private(
                &evidence.join(format!("driver-peer{peer}-wallet-{method}.json")),
                &value.to_string(),
            );
        }
    }
    private(&evidence.join("driver-harness-evidence.json"), &json!({"schema":1,"verified_equal_signed_sessions":count,"driver_result_is_external_claim":true,"harness_independently_verified_monetary_workflow":false}).to_string());
    eprintln!(
        "mixed external driver exited successfully; independently verified {count} matching signed sessions; external claims retained privately"
    );
}

fn failure_barrier(
    daemons: &mut [Daemon],
    rpcs: &mut [Rpc],
    verifier: &HistoryVerifier,
    root: &std::path::Path,
    evidence: &std::path::Path,
    deadline: Instant,
    started: Instant,
) {
    let independent: Vec<_> = daemons
        .iter()
        .enumerate()
        .filter_map(|(peer, daemon)| (!daemon.reference).then_some(peer))
        .collect();
    let reference: Vec<_> = daemons
        .iter()
        .enumerate()
        .filter_map(|(peer, daemon)| daemon.reference.then_some(peer))
        .collect();
    assert_eq!(independent.len(), 2);
    assert_eq!(reference.len(), 2);
    let [active_new, offline_new] = independent[..] else {
        unreachable!()
    };
    let [active_reference, offline_reference] = reference[..] else {
        unreachable!()
    };
    let expected_block_count = rpcs[offline_new]
        .call("module_1_consensus_block_count", json!(null), false)
        .as_u64()
        .unwrap();
    let first_exit = daemons[offline_new].stop();
    // Inspect only our joined daemon's database, never reference private files.
    // This is persisted module execution evidence, not just a matching certificate.
    {
        assert!(!daemons[offline_new].reference);
        let store =
            minimint_ng::storage::Store::open(root.join(format!("guardian-{offline_new}/data")))
                .unwrap();
        let persisted = minimint_ng::setup::load_generated(&store).unwrap().unwrap();
        let config = minimint_ng::daemon::config::RuntimeConfig::from_persisted(persisted).unwrap();
        assert_eq!(
            config
                .modules()
                .wallet()
                .snapshot(&store.snapshot().unwrap())
                .unwrap()
                .block_count,
            expected_block_count
        );
        assert_eq!(
            minimint_ng::core::session::session_count(&store.snapshot().unwrap()).unwrap(),
            1
        );
    }
    let reference_exit = daemons[offline_reference].stop();
    // Both process handles have been reaped before generating this new nonce.
    let nonce: [u8; 8] = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()[..8]
        .try_into()
        .unwrap();
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce,
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    let id = transaction_id(&tx);
    let mut submission = daemons[active_new].connect();
    submission
        .send("submit_transaction", json!(rpc::hex(&tx)), false)
        .unwrap();
    let barrier_start = Instant::now();
    for peer in [active_new, active_reference] {
        daemons[peer].check();
        assert_eq!(
            rpcs[peer]
                .call("session_count", json!(null), false)
                .as_u64(),
            Some(1)
        );
        let old = signed_history(&mut rpcs[peer], 0);
        verifier
            .verify(0, &old, SignaturePolicy::GuardianAdoption)
            .unwrap();
        assert!(!old.outcome.items.iter().any(|item| matches!(&item.item, minimint_ng::protocol::ConsensusItem::Transaction(value) if transaction_id(value) == id)));
        // Dedicated connections avoid leaving a timed-out response on an RPC stream.
        // Only an actual receive timeout counts as bounded noncompletion evidence.
        for (method, params) in [
            ("await_transaction", json!(hex_encode(&id))),
            ("await_signed_session_outcome", json!(1)),
        ] {
            let mut probe = daemons[peer].connect();
            probe.send(method, params, false).unwrap();
            assert!(
                matches!(
                    probe.ws.receive(),
                    Err(minimint_ng::api::websocket::WsError::Timeout)
                ),
                "{method} unexpectedly completed or failed while only two processes were alive"
            );
        }
        assert_eq!(
            rpcs[peer]
                .call("session_count", json!(null), false)
                .as_u64(),
            Some(1)
        );
    }
    private(&evidence.join("two-peer-barrier.json"), &json!({"offline_peers":[offline_new,offline_reference],"survivors":[active_new,active_reference],"inspected_independent_peer":offline_new,"joined_exits":[first_exit,reference_exit],"fresh_transaction_id":hex_encode(&id),"observed_noncompletion_ms":barrier_start.elapsed().as_millis() as u64,"persisted_wallet_block_count":expected_block_count,"general_quorum_proof":false}).to_string());
    eprintln!(
        "mixed bounded two-peer noncompletion observed for {:?}; restoring quorum",
        barrier_start.elapsed()
    );
    rpcs[offline_new] = daemons[offline_new].restart();
    // Proposal acknowledgement is not the evidence: require all active peers' accepted-ID reads.
    for peer in [active_new, offline_new, active_reference] {
        let end = (Instant::now() + Duration::from_secs(45)).min(deadline);
        loop {
            let mut probe = daemons[peer].connect();
            if let Ok(value) = probe.try_call("await_transaction", json!(hex_encode(&id)), false) {
                assert_eq!(value, json!(hex_encode(&id)));
                break;
            }
            assert!(
                Instant::now() < end,
                "fresh transaction did not resume after quorum restoration"
            );
        }
    }
    // This outstanding request is now safe to consume; it was never used to infer quorum.
    assert_eq!(
        submission.reply("submit_transaction").unwrap(),
        json!(rpc::hex(&Ok::<_, TransactionError>(id)))
    );
    rpcs[offline_reference] = daemons[offline_reference].restart();
    wait_count(daemons, rpcs, &[0, 1, 2, 3], 2, deadline, started);
    let mut outcomes = Vec::new();
    for (peer, rpc) in rpcs.iter_mut().enumerate() {
        let history = signed_history(rpc, 1);
        verifier
            .verify(1, &history, SignaturePolicy::GuardianAdoption)
            .unwrap();
        assert!(history.outcome.items.iter().any(|item| matches!(&item.item, minimint_ng::protocol::ConsensusItem::Transaction(value) if transaction_id(value) == id)));
        private(
            &evidence.join(format!("peer{peer}-signed-session1.json")),
            &json!(rpc::hex(&history)).to_string(),
        );
        outcomes.push(history.outcome);
    }
    assert!(outcomes.iter().all(|outcome| outcome == &outcomes[0]));
    eprintln!(
        "mixed resumed session1 common header SHA256={} elapsed={:?}",
        hex_encode(&minimint_ng::crypto::sha256(
            &minimint_ng::core::history::header(1, &outcomes[0])
        )),
        started.elapsed()
    );
}
#[test]
#[ignore = "requires exact reference artifact; real mixed DKG and ordinary session can take600seconds"]
fn two_independent_two_reference_fresh_setup_and_empty_history() {
    let independent_peers = new_peers(std::env::var_os("MINIMINT_MIXED_NEW_PEERS").as_deref())
        .expect("implementation assignment");
    monetary_survivors_option(
        std::env::var_os("MINIMINT_MIXED_MONETARY_SURVIVORS").as_deref(),
        std::env::var_os("MINIMINT_MIXED_DRIVER").is_some(),
    )
    .unwrap();
    let implementations: Vec<_> = (0..4)
        .map(|peer| {
            if independent_peers.contains(&peer) {
                "independent"
            } else {
                "reference"
            }
        })
        .collect();
    let failures =
        std::env::var_os("MINIMINT_MIXED_FAILURES").as_deref() == Some(std::ffi::OsStr::new("1"));
    let (outage_peer, one_outage_only) = outage_options(
        failures,
        std::env::var_os("MINIMINT_MIXED_OUTAGE_PEER").as_deref(),
        std::env::var_os("MINIMINT_MIXED_ONE_OUTAGE_ONLY").as_deref(),
    )
    .expect("outage options");
    let survivors: Vec<_> = (0..4).filter(|peer| *peer != outage_peer).collect();
    if failures {
        assert!(
            std::env::var_os("MINIMINT_MIXED_DRIVER").is_none()
                && std::env::var_os("MINIMINT_MIXED_SETUP_ONLY").is_none(),
            "failure mode requires full consensus without external driver"
        );
    }
    if std::env::var_os("MINIMINT_MIXED_SETUP_ONLY").as_deref() != Some(std::ffi::OsStr::new("1")) {
        assert!(
            std::env::var_os("MINIMINT_BITCOIN_RPC").is_some()
                && std::env::var_os("MINIMINT_BITCOIN_CREDENTIALS_FILE").is_some(),
            "full mixed consensus requires a live external regtest node and protected credential file"
        );
    }
    let reference = PathBuf::from(
        std::env::var_os("MINIMINT_REFERENCE_DAEMON")
            .expect("set MINIMINT_REFERENCE_DAEMON to verified artifact"),
    );
    let digest = Command::new("sha256sum").arg(&reference).output().unwrap();
    assert!(digest.status.success());
    assert_eq!(
        String::from_utf8(digest.stdout)
            .unwrap()
            .split_whitespace()
            .next(),
        Some(REFERENCE_HASH)
    );
    let started = Instant::now();
    let deadline = started + Duration::from_secs(600);
    let evidence = PathBuf::from("/tmp").join(format!(
        "minimint-mixed-evidence-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&evidence).unwrap();
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("mixed public evidence {}", evidence.display());
    let local_digest = Command::new("sha256sum")
        .arg(env!("CARGO_BIN_EXE_fedimintd"))
        .output()
        .unwrap();
    assert!(local_digest.status.success());
    let local_digest = String::from_utf8(local_digest.stdout).unwrap();
    private(&evidence.join("artifacts.json"), &json!({"reference_revision":"0c316439d60b5a08eea26fab216780eb893c45bf","reference_sha256":REFERENCE_HASH,"independent_sha256":local_digest.split_whitespace().next().unwrap(),"rounds_per_session":3600,"round_delay_ms":50,"guardian_implementations":implementations,"monetary_workflow":false}).to_string());
    let root = fixture::TestDir::new();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    // A bound, unserved endpoint supplies no invented Bitcoin observations.
    let bitcoin = bound();
    let bitcoin_address = std::env::var("MINIMINT_BITCOIN_RPC")
        .ok()
        .map(|value| value.parse().expect("Bitcoin socket"))
        .unwrap_or(bitcoin.local_addr().unwrap());
    let credentials = std::env::var_os("MINIMINT_BITCOIN_CREDENTIALS_FILE")
        .map(|path| fs::read_to_string(path).expect("Bitcoin credential file"))
        .unwrap_or_else(|| format!("test-user:{PASSWORD}"));
    let credentials = credentials.trim_end();
    let mut daemons: Vec<_> = (0..4)
        .map(|i| {
            launch(
                root.path(),
                i,
                !independent_peers.contains(&i),
                &reference,
                bitcoin_address,
                credentials,
            )
        })
        .collect();
    let endpoints: Vec<_> = daemons
        .iter()
        .map(|daemon| format!("ws://{}/", daemon.api))
        .collect();
    private(
        &evidence.join("api-endpoints.json"),
        &json!(endpoints).to_string(),
    );
    eprintln!("mixed API endpoints={endpoints:?}");
    let mut rpcs: Vec<_> = daemons.iter_mut().map(Daemon::connect).collect();
    let names = ["Alice", "Bob", "Carol", "Dave"];
    let mut records = BTreeMap::new();
    let mut codes = vec![];
    for (i, rpc) in rpcs.iter_mut().enumerate() {
        let params = if i == 0 {
            json!({"name":names[i],"federation_name":"mixed guardian process","federation_size":4,"disable_base_fees":false,"enabled_modules":["mintv2","walletv2"]})
        } else {
            json!({"name":names[i]})
        };
        let code = rpc.call("set_local_params", params, true);
        let record = SetupRecord::from_code(code.as_str().expect("SET001 string"))
            .expect("SET001 record decode");
        assert_eq!(record.name, names[i]);
        assert_eq!(config::normalize_release(&record.release), "0.13.0");
        assert_eq!(record.to_code(), code.as_str().unwrap());
        records.insert(PeerId(i as u16), record);
        assert_eq!(rpc.call("get_setup_code", json!(null), true), code);
        codes.push(code);
    }
    private(
        &evidence.join("setup-codes.json"),
        &json!(codes).to_string(),
    );
    config::validate_setup_set(&records).unwrap();
    eprintln!(
        "mixed SET005 initial checksum {}",
        hex_encode(&config::setup_checksum(&records))
    );
    for (i, rpc) in rpcs.iter_mut().enumerate() {
        for (j, code) in codes.iter().enumerate() {
            if i != j {
                assert_eq!(
                    rpc.call("add_peer_setup_code", code.clone(), true),
                    json!(names[j])
                );
            }
        }
    }
    for rpc in &mut rpcs {
        rpc.call("start_dkg", json!(null), true);
    }
    let setup_deadline = Instant::now() + Duration::from_secs(90);
    loop {
        for daemon in &mut daemons {
            daemon.check();
        }
        let states: Vec<_> = daemons
            .iter_mut()
            .map(|daemon| {
                daemon
                    .connect()
                    .try_call("setup_status", json!(null), false)
                    .unwrap_or(json!("TransportRestart"))
            })
            .collect();
        if states
            .iter()
            .all(|s| s.as_str() == Some("ConsensusIsRunning"))
        {
            break;
        }
        assert!(
            Instant::now() < setup_deadline,
            "mixed SET006 DKG deadline states={states:?}; logs={:?}",
            daemons.iter().map(Daemon::log).collect::<Vec<_>>()
        );
        thread::sleep(Duration::from_millis(100));
    }
    rpcs = daemons.iter_mut().map(Daemon::connect).collect();
    let configs: Vec<_> = rpcs
        .iter_mut()
        .map(|r| r.call("client_config", json!(null), false))
        .collect();
    for (peer, config) in configs.iter().enumerate() {
        private(
            &evidence.join(format!("peer{peer}-client_config.json")),
            &config.to_string(),
        );
    }
    compare(&configs, "CFG002 full client_config");
    for method in ["federation_id", "server_config_consensus_hash"] {
        let values: Vec<_> = rpcs
            .iter_mut()
            .map(|r| r.call(method, json!(null), false))
            .collect();
        compare(&values, method);
        private(
            &evidence.join(format!("{method}.json")),
            &json!(values).to_string(),
        );
        eprintln!("mixed {method}={}", values[0]);
    }
    eprintln!(
        "mixed setup/public configuration matched in {:?}",
        started.elapsed()
    );
    if std::env::var_os("MINIMINT_MIXED_RECOVERY_CHECKS").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        recovery_checks(&mut daemons, &mut rpcs, &evidence, started);
    }
    if let Some(executable) = std::env::var_os("MINIMINT_MIXED_DRIVER") {
        assert!(
            std::env::var_os("MINIMINT_MIXED_SETUP_ONLY").is_none()
                && std::env::var_os("MINIMINT_MIXED_FAILURES").is_none(),
            "external driver mode is exclusive"
        );
        external_driver(
            &mut daemons,
            &mut rpcs,
            &configs,
            &evidence,
            std::path::Path::new(&executable),
            started,
        );
        let exits: Vec<_> = daemons.iter_mut().map(Daemon::stop).collect();
        for (peer, daemon) in daemons.iter().enumerate() {
            private(
                &evidence.join(format!("peer{peer}-stderr.redacted.log")),
                &daemon.log(),
            );
        }
        private(
            &evidence.join("sigterm-exits.json"),
            &json!(exits).to_string(),
        );
        eprintln!(
            "mixed external-driver guardians joined; exit codes={exits:?}; reference255 is observed only"
        );
        return;
    }
    if std::env::var_os("MINIMINT_MIXED_SETUP_ONLY").as_deref() == Some(std::ffi::OsStr::new("1")) {
        let exits: Vec<_> = daemons.iter_mut().map(Daemon::stop).collect();
        for (peer, daemon) in daemons.iter().enumerate() {
            private(
                &evidence.join(format!("peer{peer}-stderr.redacted.log")),
                &daemon.log(),
            );
        }
        private(
            &evidence.join("sigterm-exits.json"),
            &json!(exits).to_string(),
        );
        eprintln!(
            "mixed joined SIGTERM exit codes={exits:?}; reference255 is observed, not a clean-exit claim"
        );
        return;
    }
    let mut ids = vec![];
    for (i, r) in rpcs.iter_mut().enumerate() {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            nonce: [180 + i as u8; 8],
            signatures: TransactionSignatures::Schnorr(vec![]),
        };
        let id = transaction_id(&tx);
        assert_eq!(
            r.call("submit_transaction", json!(rpc::hex(&tx)), false),
            json!(rpc::hex(&Ok::<_, TransactionError>(id)))
        );
        ids.push(id);
    }
    for r in &mut rpcs {
        for id in &ids {
            assert_eq!(
                r.call("await_transaction", json!(hex_encode(id)), false),
                json!(hex_encode(id))
            );
        }
    }
    eprintln!(
        "mixed all four empty transactions accepted at {:?}",
        started.elapsed()
    );
    if failures {
        assert_eq!(
            rpcs[outage_peer]
                .call("session_count", json!(null), false)
                .as_u64(),
            Some(0)
        );
        let exit = daemons[outage_peer].stop();
        private(
            &evidence.join("first-outage.json"),
            &json!({"peer":outage_peer,"survivors":survivors,"reference":daemons[outage_peer].reference,"one_outage_only":one_outage_only,"joined_exit":exit,"elapsed_ms":started.elapsed().as_millis() as u64})
                .to_string(),
        );
        eprintln!(
            "mixed guardian{outage_peer} joined before session0 boundary; survivors={survivors:?} at {:?}",
            started.elapsed()
        );
    }
    let mut report = Instant::now();
    loop {
        for (peer, d) in daemons.iter_mut().enumerate() {
            if !failures || survivors.contains(&peer) {
                d.check();
            }
        }
        let counts: Vec<_> = rpcs
            .iter_mut()
            .enumerate()
            .filter(|(peer, _)| !failures || survivors.contains(peer))
            .map(|(_, r)| {
                r.call("session_count", json!(null), false)
                    .as_u64()
                    .unwrap()
            })
            .collect();
        if counts.iter().all(|n| *n >= 1) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "mixed ordinary session deadline counts={counts:?}"
        );
        if report.elapsed() >= Duration::from_secs(15) {
            eprintln!(
                "mixed ordinary session progress elapsed={:?} counts={counts:?}",
                started.elapsed()
            );
            for (peer, rpc) in rpcs.iter_mut().enumerate() {
                if failures && peer == outage_peer {
                    continue;
                }
                let status = rpc.call("session_status", json!(0), false);
                fs::write(
                    evidence.join(format!("peer{peer}-session_status-0.json")),
                    status.to_string(),
                )
                .unwrap();
            }
            report = Instant::now();
        }
        thread::sleep(Duration::from_secs(1));
    }
    if failures {
        rpcs[outage_peer] = daemons[outage_peer].restart();
        wait_count(
            &mut daemons,
            &mut rpcs,
            &[outage_peer],
            1,
            deadline,
            started,
        );
        let expected =
            rpcs[survivors[0]].call("module_1_consensus_block_count", json!(null), false);
        assert!(
            expected.as_u64().unwrap() > 0,
            "requires actual Wallet observations"
        );
        assert_eq!(
            rpcs[outage_peer].call("module_1_consensus_block_count", json!(null), false),
            expected
        );
        private(
            &evidence.join("rejoined-wallet-block-count.json"),
            &json!({"peer":outage_peer,"compared_survivor":survivors[0],"block_count":expected})
                .to_string(),
        );
        eprintln!(
            "mixed guardian{outage_peer} caught up signed history and Wallet block count at {:?}",
            started.elapsed()
        );
    }
    let mut histories = vec![];
    for (peer, r) in rpcs.iter_mut().enumerate() {
        let value = r.call("await_signed_session_outcome", json!(0), false);
        private(
            &evidence.join(format!("peer{peer}-signed-session0.json")),
            &value.to_string(),
        );
        let strings: Vec<_> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        histories.push(rpc::decode_hex::<SignedSessionOutcome>(&strings).unwrap());
    }
    for history in &histories {
        assert_eq!(history.outcome, histories[0].outcome);
        if failures {
            assert_eq!(
                history
                    .signatures
                    .keys()
                    .map(|peer| usize::from(peer.0))
                    .collect::<Vec<_>>(),
                survivors,
                "session0 certificate must come from the active survivor set"
            );
            assert!(
                history.outcome.items.iter().any(|item| matches!(
                    item.item,
                    minimint_ng::protocol::ConsensusItem::Module(_)
                )),
                "outage evidence requires module-bearing history"
            );
        }
        let mut accepted = vec![];
        for item in &history.outcome.items {
            match &item.item {
                minimint_ng::protocol::ConsensusItem::Transaction(tx) => {
                    accepted.push(transaction_id(tx))
                }
                minimint_ng::protocol::ConsensusItem::Module(value) => {
                    assert_eq!(value.module_id, minimint_ng::protocol::ModuleId(1));
                    minimint_ng::codec::decode_whole::<minimint_ng::modules::wallet::ConsensusItem>(&value.payload).expect("known Wallet observation");
                }
                minimint_ng::protocol::ConsensusItem::Unknown { .. } => {
                    panic!("unknown consensus item in signed history")
                }
            }
        }
        accepted.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(accepted, expected);
    }
    // Broadcast identities come from public client config, never reference files.
    let keys = configs[0]["broadcast_public_keys"]
        .as_object()
        .expect("CFG002 keys")
        .iter()
        .map(|(p, v)| {
            let peer = PeerId(p.parse().unwrap());
            let key = minimint_ng::codec::text::hex_decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            (peer, key)
        })
        .collect();
    let verifier = HistoryVerifier::new(keys).unwrap();
    for history in &histories {
        verifier
            .verify(0, history, SignaturePolicy::GuardianAdoption)
            .unwrap();
    }
    eprintln!(
        "mixed session0 common header SHA256={} items={} elapsed={:?}",
        hex_encode(&minimint_ng::crypto::sha256(
            &minimint_ng::core::history::header(0, &histories[0].outcome)
        )),
        histories[0].outcome.items.len(),
        started.elapsed()
    );
    if failures && !one_outage_only {
        failure_barrier(
            &mut daemons,
            &mut rpcs,
            &verifier,
            root.path(),
            &evidence,
            deadline,
            started,
        );
    }
    let exits: Vec<_> = daemons.iter_mut().map(Daemon::stop).collect();
    for (peer, daemon) in daemons.iter().enumerate() {
        private(
            &evidence.join(format!("peer{peer}-stderr.redacted.log")),
            &daemon.log(),
        );
    }
    private(
        &evidence.join("sigterm-exits.json"),
        &json!(exits).to_string(),
    );
    eprintln!(
        "mixed joined SIGTERM exit codes={exits:?}; reference255 is observed, not a clean-exit claim"
    );
    eprintln!(
        "mixed empty-transaction history evidence complete {:?}; no monetary workflow",
        started.elapsed()
    );
}
