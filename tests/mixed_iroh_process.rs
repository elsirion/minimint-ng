//! Black-box mixed Iroh federation: minimint-ng with pinned reference guardians
//! (and optionally an aontas guardian) completes setup/DKG over Iroh, advances
//! signed sessions, and serves the reference client over the Iroh API.
//! No monetary claim.
//!
//! Required: MINIMINT_REFERENCE_DAEMON (fedimintd whose `version-hash` is the
//! pinned revision), MINIMINT_BITCOIN_RPC and MINIMINT_BITCOIN_CREDENTIALS_FILE
//! (`user:password`) for an operator-owned regtest Core node outside IBD.
//! Optional: MINIMINT_REFERENCE_CLI (pinned fedimint-cli) joins through an
//! invite naming only the minimint-ng guardian and queries it over Iroh;
//! MINIMINT_AONTAS_GUARDIAN replaces one reference guardian with aontas;
//! MINIMINT_IROH_SESSIONS (default 1) sets the signed sessions to await;
//! MINIMINT_IROH_CATCHUP=1 stops minimint-ng, lets the others complete a
//! session, and requires Iroh API catch-up after restart.
//!
//! Discovery and relays are disabled everywhere; every endpoint key has an
//! explicit loopback address override. Guardian roles by setup order: Alice
//! (reference), Bob (minimint-ng), Carol (aontas or reference), Dave
//! (reference). Bob therefore both accepts (from 0) and dials (2, 3).
#![cfg(unix)]
use minimint_ng::{
    api::{
        iroh::IrohApiClient,
        websocket::{Limits, Message, WebSocket},
    },
    codec::{rpc, text::hex_encode},
    config::{self, CanonicalUrl, Invite, InviteRecord, SetupEndpoints, SetupRecord},
    core::history::{HistoryVerifier, SignaturePolicy},
    net::iroh::{IrohIdentity, IrohOptions},
    protocol::{PeerId, SignedSessionOutcome},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
const ADMIN: &str = "mixed-iroh-test-admin";
const REVISION: &str = "0c316439d60b5a08eea26fab216780eb893c45bf";
const NAMES: [&str; 4] = ["Alice", "Bob", "Carol", "Dave"];
const INDEPENDENT: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Reference,
    Independent,
    Aontas,
}
struct Daemon {
    child: Child,
    command: Command,
    log: PathBuf,
    api: SocketAddr,
    kind: Kind,
    secrets: Vec<String>,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if thread::panicking() {
            let log = self.log();
            let tail: String = log.chars().rev().take(8000).collect();
            eprintln!(
                "{:?} guardian {} stderr tail: {}",
                self.kind,
                self.api,
                tail.chars().rev().collect::<String>()
            );
        }
    }
}
impl Daemon {
    fn log(&self) -> String {
        let mut log = fs::read_to_string(&self.log).unwrap_or_default();
        for secret in self.secrets.iter().chain([&ADMIN.to_owned()]) {
            log = log.replace(secret.as_str(), "[redacted]");
        }
        log
    }
    fn check(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            panic!("{:?} guardian exited {status}: {}", self.kind, self.log());
        }
    }
    fn connect(&mut self) -> Rpc {
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            self.check();
            if let Ok(stream) = TcpStream::connect_timeout(&self.api, Duration::from_millis(100)) {
                let limits = Limits {
                    handshake_timeout: Duration::from_secs(2),
                    operation_timeout: Duration::from_secs(90),
                    ..Limits::default()
                };
                if let Ok(ws) = WebSocket::connect(stream, &self.api.to_string(), "/", None, limits)
                {
                    return Rpc { ws, id: 0 };
                }
            }
            assert!(Instant::now() < end, "API startup deadline: {}", self.log());
            thread::sleep(Duration::from_millis(50));
        }
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
        let end = Instant::now() + Duration::from_secs(35);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < end, "stop deadline");
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn restart(&mut self) {
        self.command.stderr(Stdio::from(
            OpenOptions::new().append(true).open(&self.log).unwrap(),
        ));
        self.child = self.command.spawn().unwrap();
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
        self.id += 1;
        let auth = if admin { Some(ADMIN) } else { None };
        let request = json!({"jsonrpc":"2.0","id":self.id,"method":method,
            "params":[{"auth":auth,"params":params}]});
        self.ws
            .send_text(&request.to_string())
            .map_err(|error| format!("send {error:?}"))?;
        let Message::Text(reply) = self
            .ws
            .receive()
            .map_err(|error| format!("receive {error:?}"))?
        else {
            return Err("nontext response".into());
        };
        let reply = minimint_ng::json::parse(reply.as_bytes(), 16 * 1024 * 1024, 64).unwrap();
        assert_eq!(reply["id"].as_u64(), Some(self.id));
        if let Some(error) = reply.get("error") {
            return Err(error.to_string().replace(ADMIN, "[redacted]"));
        }
        Ok(reply["result"].clone())
    }
}
fn tcp_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
/// A loopback port free for both TCP (WebSocket) and UDP (Iroh).
fn dual_port() -> SocketAddr {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        if UdpSocket::bind(address).is_ok() {
            return address;
        }
    }
}
fn private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
struct Guardian {
    kind: Kind,
    api: SocketAddr,
    p2p: SocketAddr,
    identity: IrohIdentity,
}
fn overrides_plain(guardians: &[Guardian]) -> String {
    guardians
        .iter()
        .flat_map(|g| {
            [
                (g.identity.api_public(), g.api),
                (g.identity.p2p_public(), g.p2p),
            ]
        })
        .map(|(key, address)| format!("{}={address}", hex_encode(&key)))
        .collect::<Vec<_>>()
        .join(",")
}
/// Reference client/daemon settings equivalent to discovery and relays off.
fn reference_environment(command: &mut Command, guardians: &[Guardian]) {
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("FM_") {
            command.env_remove(name);
        }
    }
    command
        .env(
            "FM_IROH_CONNECT_OVERRIDES_PLAIN",
            overrides_plain(guardians),
        )
        .env("FM_IROH_RELAYS_ENABLE", "0")
        .env("FM_IROH_ENABLE_DHT", "false")
        .env("FM_IROH_DHT_ENABLE", "0")
        .env("FM_IROH_N0_DISCOVERY_ENABLE", "0")
        .env("FM_IROH_PKARR_PUBLISHER_ENABLE", "0")
        .env("FM_IROH_PKARR_RESOLVER_ENABLE", "0");
}
struct Paths {
    reference: PathBuf,
    aontas: Option<PathBuf>,
    bitcoin: SocketAddr,
    credentials: String,
}
fn launch(root: &Path, index: usize, guardians: &[Guardian], paths: &Paths) -> Daemon {
    let guardian = &guardians[index];
    let dir = root.join(format!("guardian-{index}"));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let addresses = dir.join("iroh-addresses.json");
    let map: BTreeMap<String, String> = guardians
        .iter()
        .flat_map(|g| {
            [
                (hex_encode(&g.identity.api_public()), g.api.to_string()),
                (hex_encode(&g.identity.p2p_public()), g.p2p.to_string()),
            ]
        })
        .collect();
    fs::write(&addresses, json!(map).to_string()).unwrap();
    let (username, password) = paths.credentials.split_once(':').unwrap();
    let secret_hex = hex_encode(guardian.identity.secret_bytes().as_slice());
    let log = dir.join("stderr");
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log)
        .unwrap();
    let mut command = match guardian.kind {
        Kind::Independent => {
            private(&dir.join("admin"), ADMIN.as_bytes());
            private(&dir.join("bitcoin"), paths.credentials.as_bytes());
            private(&dir.join("iroh-secret"), secret_hex.as_bytes());
            let mut command = Command::new(env!("CARGO_BIN_EXE_fedimintd"));
            command
                .arg("--data-dir")
                .arg(dir.join("data"))
                .args(["--transport", "iroh", "--iroh-discovery", "false"])
                .arg("--iroh-address-file")
                .arg(&addresses)
                .arg("--iroh-secret-file")
                .arg(dir.join("iroh-secret"))
                .args(["--api-bind", &guardian.api.to_string()])
                .args(["--p2p-bind", &guardian.p2p.to_string()])
                .args(["--bitcoin-rpc", &paths.bitcoin.to_string()])
                .arg("--bitcoin-rpc-credentials-file")
                .arg(dir.join("bitcoin"))
                .arg("--admin-secret-file")
                .arg(dir.join("admin"));
            command
        }
        Kind::Aontas => {
            private(&dir.join("admin"), ADMIN.as_bytes());
            private(&dir.join("bitcoin"), password.as_bytes());
            private(
                &dir.join("transport-seeds"),
                guardian.identity.secret_bytes().as_slice(),
            );
            let mut command = Command::new(paths.aontas.as_ref().unwrap());
            command
                .arg("--data-dir")
                .arg(dir.join("data"))
                .args(["--api-url", &format!("ws://{}/", guardian.api)])
                .args(["--transport", "iroh", "--iroh-discovery", "false"])
                .arg("--admin-password-file")
                .arg(dir.join("admin"))
                .arg("--bitcoin-rpc-password-file")
                .arg(dir.join("bitcoin"))
                .args(["--bitcoin-rpc-user", username])
                .args(["--bitcoin-rpc-url", &format!("http://{}", paths.bitcoin)])
                .args(["--api-bind", &guardian.api.to_string()])
                .args(["--peer-bind", &guardian.p2p.to_string()])
                .arg("--iroh-key-file")
                .arg(dir.join("transport-seeds"))
                .arg("--iroh-address-file")
                .arg(&addresses);
            command
        }
        Kind::Reference => {
            let mut command = Command::new(&paths.reference);
            reference_environment(&mut command, guardians);
            let secrets = guardian.identity.secret_bytes();
            command
                .env(
                    "FM_IROH_API_SECRET_KEY_OVERRIDE",
                    hex_encode(&secrets[..32]),
                )
                .env(
                    "FM_IROH_P2P_SECRET_KEY_OVERRIDE",
                    hex_encode(&secrets[32..]),
                )
                .env("FM_BITCOIND_USERNAME", username)
                .env("FM_BITCOIND_PASSWORD", password)
                .arg("--data-dir")
                .arg(dir.join("data"))
                .args([
                    "--bitcoin-network",
                    "regtest",
                    "--enable-iroh",
                    "true",
                    "--enable-iroh-next",
                    "false",
                    "--bind-api",
                    &guardian.api.to_string(),
                    "--bind-p2p",
                    &guardian.p2p.to_string(),
                    "--bind-ui",
                    &tcp_port().to_string(),
                    "--bind-metrics",
                    &tcp_port().to_string(),
                    "--api-url",
                    &format!("ws://{}/", guardian.api),
                    "--p2p-url",
                    &format!("fedimint://{}/", guardian.p2p),
                    "--bitcoind-url",
                    &format!("http://{}", paths.bitcoin),
                    "--password-api",
                    ADMIN,
                ]);
            command
        }
    };
    command.stdin(Stdio::null()).stdout(Stdio::null());
    command.stderr(Stdio::from(stderr));
    let child = command.spawn().unwrap();
    Daemon {
        child,
        command,
        log,
        api: guardian.api,
        kind: guardian.kind,
        secrets: vec![password.to_owned(), secret_hex],
    }
}
fn wait_sessions(daemons: &mut [Daemon], peers: &[usize], count: u64, deadline: Instant) {
    loop {
        let counts: Vec<_> = peers
            .iter()
            .map(|peer| {
                daemons[*peer]
                    .connect()
                    .try_call("session_count", json!(null), false)
                    .ok()
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            })
            .collect();
        if counts.iter().all(|c| *c >= count) {
            eprintln!("mixed iroh session counts {counts:?}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "session deadline counts={counts:?}; logs={:?}",
            daemons.iter().map(Daemon::log).collect::<Vec<_>>()
        );
        thread::sleep(Duration::from_secs(2));
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
fn cli(cli: &Path, data: &Path, guardians: &[Guardian], args: &[&str]) -> Value {
    let mut command = Command::new(cli);
    reference_environment(&mut command, guardians);
    let output = command
        .arg("--data-dir")
        .arg(data)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fedimint-cli {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    minimint_ng::json::parse(&output.stdout, 16 * 1024 * 1024, 64).unwrap_or_else(|_| {
        panic!(
            "fedimint-cli {args:?} output: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}
fn version_hash(executable: &Path) -> String {
    let output = Command::new(executable)
        .arg("version-hash")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
#[ignore = "requires the pinned reference daemon and a live regtest Core node"]
fn mixed_iroh_federation_setup_sessions_and_client() {
    let reference = PathBuf::from(
        std::env::var_os("MINIMINT_REFERENCE_DAEMON").expect("MINIMINT_REFERENCE_DAEMON"),
    );
    assert_eq!(version_hash(&reference), REVISION);
    let client = std::env::var_os("MINIMINT_REFERENCE_CLI").map(PathBuf::from);
    if let Some(client) = &client {
        assert_eq!(version_hash(client), REVISION);
    }
    let aontas = std::env::var_os("MINIMINT_AONTAS_GUARDIAN").map(PathBuf::from);
    let sessions: u64 = std::env::var("MINIMINT_IROH_SESSIONS")
        .map(|value| value.parse().unwrap())
        .unwrap_or(1);
    let catchup =
        std::env::var_os("MINIMINT_IROH_CATCHUP").as_deref() == Some(std::ffi::OsStr::new("1"));
    let paths = Paths {
        reference,
        aontas: aontas.clone(),
        bitcoin: std::env::var("MINIMINT_BITCOIN_RPC")
            .expect("MINIMINT_BITCOIN_RPC")
            .parse()
            .unwrap(),
        credentials: fs::read_to_string(
            std::env::var_os("MINIMINT_BITCOIN_CREDENTIALS_FILE")
                .expect("MINIMINT_BITCOIN_CREDENTIALS_FILE"),
        )
        .unwrap()
        .trim_end()
        .to_owned(),
    };
    let kinds = [
        Kind::Reference,
        Kind::Independent,
        if aontas.is_some() {
            Kind::Aontas
        } else {
            Kind::Reference
        },
        Kind::Reference,
    ];
    let guardians: Vec<_> = kinds
        .iter()
        .map(|kind| Guardian {
            kind: *kind,
            api: dual_port(),
            p2p: dual_port(),
            identity: IrohIdentity::generate().unwrap(),
        })
        .collect();
    let started = Instant::now();
    // Retained outside a Nix shell TMPDIR, which is deleted on exit.
    let evidence = PathBuf::from("/tmp").join(format!(
        "minimint-iroh-evidence-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&evidence).unwrap();
    eprintln!("mixed iroh public evidence {}", evidence.display());
    fs::write(
        evidence.join("roles.json"),
        json!({"reference_revision": REVISION, "roles": kinds.iter().map(|k| format!("{k:?}")).collect::<Vec<_>>(),
            "api_keys": guardians.iter().map(|g| hex_encode(&g.identity.api_public())).collect::<Vec<_>>(),
            "p2p_keys": guardians.iter().map(|g| hex_encode(&g.identity.p2p_public())).collect::<Vec<_>>()})
        .to_string(),
    )
    .unwrap();
    let root = fixture::TestDir::new();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut daemons: Vec<_> = (0..4)
        .map(|i| launch(root.path(), i, &guardians, &paths))
        .collect();

    // SET-002/003: every setup code is endpoint variant 1 carrying the keys.
    let mut rpcs: Vec<_> = daemons.iter_mut().map(Daemon::connect).collect();
    let mut codes = vec![];
    let mut records = BTreeMap::new();
    for (i, rpc) in rpcs.iter_mut().enumerate() {
        let params = if i == 0 {
            json!({"name":NAMES[i],"federation_name":"mixed iroh federation","federation_size":4,
                "disable_base_fees":false,"enabled_modules":["mintv2","walletv2"]})
        } else {
            json!({"name":NAMES[i]})
        };
        let code = rpc.call("set_local_params", params, true);
        let record = SetupRecord::from_code(code.as_str().unwrap()).unwrap();
        assert_eq!(
            record.endpoints,
            SetupEndpoints::Iroh {
                api_key: guardians[i].identity.api_public(),
                p2p_key: guardians[i].identity.p2p_public(),
            },
            "{:?} setup code endpoints",
            kinds[i]
        );
        assert_eq!(record.to_code(), code.as_str().unwrap());
        records.insert(PeerId(i as u16), record);
        codes.push(code);
    }
    config::validate_setup_set(&records).unwrap();
    fs::write(evidence.join("setup-codes.json"), json!(codes).to_string()).unwrap();
    for (i, rpc) in rpcs.iter_mut().enumerate() {
        for (j, code) in codes.iter().enumerate() {
            if i != j {
                assert_eq!(
                    rpc.call("add_peer_setup_code", code.clone(), true),
                    json!(NAMES[j])
                );
            }
        }
    }
    for rpc in &mut rpcs {
        rpc.call("start_dkg", json!(null), true);
    }
    let setup_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let states: Vec<_> = daemons
            .iter_mut()
            .map(|daemon| {
                daemon
                    .connect()
                    .try_call("setup_status", json!(null), false)
                    .unwrap_or(json!("Unavailable"))
            })
            .collect();
        if states
            .iter()
            .all(|state| state.as_str() == Some("ConsensusIsRunning"))
        {
            break;
        }
        assert!(
            Instant::now() < setup_deadline,
            "Iroh DKG deadline states={states:?}; logs={:?}",
            daemons.iter().map(Daemon::log).collect::<Vec<_>>()
        );
        thread::sleep(Duration::from_millis(250));
    }
    eprintln!("mixed iroh DKG complete after {:?}", started.elapsed());

    // CFG-001/002: identical configurations whose endpoints are Iroh API URLs.
    rpcs = daemons.iter_mut().map(Daemon::connect).collect();
    let configs: Vec<_> = rpcs
        .iter_mut()
        .map(|rpc| rpc.call("client_config", json!(null), false))
        .collect();
    fs::write(evidence.join("client_config.json"), configs[0].to_string()).unwrap();
    for (i, config) in configs.iter().enumerate() {
        assert_eq!(config, &configs[0], "client_config guardian {i}");
    }
    let endpoints = configs[0]["api_endpoints"].as_object().unwrap();
    for (i, guardian) in guardians.iter().enumerate() {
        let endpoint = endpoints.get(&i.to_string().as_str()).unwrap();
        assert_eq!(
            endpoint["url"].as_str().unwrap(),
            CanonicalUrl::iroh(&guardian.identity.api_public()).as_str()
        );
        assert_eq!(endpoint["name"].as_str(), Some(NAMES[i]));
    }
    for method in ["federation_id", "server_config_consensus_hash"] {
        let values: Vec<_> = rpcs
            .iter_mut()
            .map(|rpc| rpc.call(method, json!(null), false))
            .collect();
        assert!(
            values.iter().all(|v| v == &values[0]),
            "{method} {values:?}"
        );
        eprintln!("mixed iroh {method}={}", values[0]);
    }

    // API-002: this implementation's Iroh 0.35 client reaches every guardian.
    let options = IrohOptions {
        discovery: false,
        addresses: guardians
            .iter()
            .map(|g| (g.identity.api_public(), g.api))
            .collect(),
    };
    let iroh_client = IrohApiClient::new(options).unwrap();
    for (i, guardian) in guardians.iter().enumerate() {
        let config = iroh_client
            .call(
                &guardian.identity.api_public(),
                "client_config",
                json!(null),
                Instant::now() + Duration::from_secs(30),
                16 * 1024 * 1024,
                &|| false,
            )
            .unwrap_or_else(|error| panic!("Iroh client_config from {:?}: {error:?}", kinds[i]));
        assert_eq!(config, configs[0], "Iroh client_config guardian {i}");
    }

    // CON: signed sessions advance with identical outcomes and valid quorum signatures.
    let all: Vec<usize> = (0..4).collect();
    let deadline = Instant::now() + Duration::from_secs(300 * sessions.max(1) + 120);
    wait_sessions(&mut daemons, &all, sessions, deadline);
    // Idle WebSocket connections may be closed by guardians during the wait.
    rpcs = daemons.iter_mut().map(Daemon::connect).collect();
    let keys: BTreeMap<PeerId, [u8; 33]> = configs[0]["broadcast_public_keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(peer, key)| {
            (
                PeerId(peer.parse().unwrap()),
                minimint_ng::codec::text::hex_decode(key.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    let verifier = HistoryVerifier::new(keys).unwrap();
    for index in 0..sessions {
        let outcomes: Vec<_> = rpcs
            .iter_mut()
            .map(|rpc| signed_history(rpc, index))
            .collect();
        for (i, signed) in outcomes.iter().enumerate() {
            verifier
                .verify(index, signed, SignaturePolicy::GuardianAdoption)
                .unwrap_or_else(|error| panic!("session {index} guardian {i}: {error:?}"));
            assert_eq!(
                signed.outcome, outcomes[0].outcome,
                "session {index} guardian {i}"
            );
        }
        eprintln!(
            "mixed iroh session {index}: {} items, signers {:?}",
            outcomes[0].outcome.items.len(),
            outcomes
                .iter()
                .map(|s| s.signatures.keys().map(|p| p.0).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
    }

    // The reference client joins through an invite naming only minimint-ng.
    if let Some(cli_path) = &client {
        let federation_id: [u8; 32] = minimint_ng::codec::text::hex_decode(
            rpcs[INDEPENDENT]
                .call("federation_id", json!(null), false)
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let invite = Invite::new(vec![
            InviteRecord::Endpoint {
                url: CanonicalUrl::iroh(&guardians[INDEPENDENT].identity.api_public()),
                peer: PeerId(INDEPENDENT as u16),
            },
            InviteRecord::FederationId(federation_id),
        ])
        .unwrap()
        .to_bech32m();
        let served = rpcs[INDEPENDENT].call("invite_code", json!(null), false);
        eprintln!("mixed iroh served invite {served}; single-guardian invite {invite}");
        let data = root.path().join("client");
        let joined = cli(cli_path, &data, &guardians, &["join", &invite]);
        eprintln!("fedimint-cli join: {joined}");
        let direct = cli(
            cli_path,
            &data,
            &guardians,
            &[
                "dev",
                "api",
                "--peer-id",
                &INDEPENDENT.to_string(),
                "session_count",
            ],
        );
        let count = direct.as_u64().or_else(|| direct["value"].as_u64());
        assert!(
            count.is_some_and(|c| c >= sessions),
            "direct session_count {direct}"
        );
        let config = cli(
            cli_path,
            &data,
            &guardians,
            &[
                "dev",
                "api",
                "--peer-id",
                &INDEPENDENT.to_string(),
                "client_config",
            ],
        );
        eprintln!(
            "fedimint-cli minimint-ng client_config over Iroh: {} bytes",
            config.to_string().len()
        );
        let info = cli(cli_path, &data, &guardians, &["info"]);
        eprintln!("fedimint-cli info: {info}");
        fs::write(
            evidence.join("client.json"),
            json!({"join": joined, "direct_session_count": direct, "info": info}).to_string(),
        )
        .unwrap();
    }

    // Optional: minimint-ng misses a session and catches up over the Iroh API.
    if catchup {
        let current = rpcs[0]
            .call("session_count", json!(null), false)
            .as_u64()
            .unwrap();
        drop(rpcs);
        daemons[INDEPENDENT].stop();
        let others: Vec<usize> = (0..4).filter(|p| *p != INDEPENDENT).collect();
        wait_sessions(
            &mut daemons,
            &others,
            current + 1,
            Instant::now() + Duration::from_secs(420),
        );
        daemons[INDEPENDENT].restart();
        wait_sessions(
            &mut daemons,
            &[INDEPENDENT],
            current + 1,
            Instant::now() + Duration::from_secs(120),
        );
        let mut rpc = daemons[INDEPENDENT].connect();
        let caught = signed_history(&mut rpc, current);
        verifier
            .verify(current, &caught, SignaturePolicy::GuardianAdoption)
            .unwrap();
        let mut reference = daemons[0].connect();
        assert_eq!(
            signed_history(&mut reference, current).outcome,
            caught.outcome
        );
        eprintln!("mixed iroh catch-up of session {current} verified");
    }
    iroh_client.close();
    for daemon in &mut daemons {
        daemon.check();
    }
    eprintln!("mixed iroh federation passed in {:?}", started.elapsed());
}
