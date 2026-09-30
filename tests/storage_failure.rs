//! Linux OS write-error injection against public Store APIs. Only the owned
//! child's RLIMIT_FSIZE changes; no disk filling, host limit or production hook.
#![cfg(target_os = "linux")]
use minimint_ng::storage::{Namespace, Store};
use minimint_ng::{
    codec::{ConsensusEncode, decode_whole},
    core::{
        history::HistoryVerifier,
        session::{self, Session, SessionError},
    },
    protocol::{
        AcceptedItem, ConsensusItem, DynamicValue, ModuleId, PeerId, SessionOutcome,
        SessionStatusV2, SignedSessionOutcome,
    },
};
use std::{
    io::{BufRead, BufReader, Write},
    os::{
        fd::OwnedFd,
        unix::{net::UnixStream, process::ExitStatusExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
#[path = "fixtures/runtime/mod.rs"]
mod runtime_fixture;

const NAMESPACES: [Namespace; 5] = [
    Namespace::Replicated,
    Namespace::Local,
    Namespace::Agreement,
    Namespace::Outbox,
    Namespace::ClientBackup,
];
const SESSION: u64 = 19;
const PREFIX: &[u8] = b"acknowledged\x00first\xffsecond";
const ACK: &[u8] = b"durably acknowledged namespace value";
fn attempted() -> Vec<u8> {
    vec![0xa7; 32768]
}

fn seed(path: &Path) {
    let store = Store::open(path).unwrap();
    let mut writer = store.transaction().unwrap();
    for namespace in NAMESPACES {
        writer.put(namespace, b"ack", ACK).unwrap();
    }
    writer.commit().unwrap();
    store
        .append_agreement(SESSION, b"acknowledged\x00first")
        .unwrap();
    store.append_agreement(SESSION, b"\xffsecond").unwrap();
    assert_eq!(store.read_agreement(SESSION).unwrap(), PREFIX);
}

fn runtime_config() -> Arc<minimint_ng::daemon::config::RuntimeConfig> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    runtime_fixture::configs(1, 3600, &[listener])
        .pop()
        .unwrap()
}

fn prepare_completion(store: &Store, path: &Path) -> Session {
    // Legitimate n=1/q=1 avoids bypassing the multi-peer owned-engine invariant.
    // This exercises the shared completion store transaction, not engine joining.
    let config = runtime_config();
    let session_config = config.session_config().unwrap();
    let verifier = HistoryVerifier::new(session_config.broadcast_keys.clone()).unwrap();
    let outcome = SessionOutcome {
        items: vec![AcceptedItem {
            peer: PeerId(0),
            item: ConsensusItem::Module(DynamicValue {
                module_id: ModuleId(1),
                payload: minimint_ng::modules::wallet::ConsensusItem::FeeRate(Some(1000))
                    .consensus_encode(),
            }),
        }],
    };
    let signature = verifier
        .sign(0, &outcome, PeerId(0), &session_config.local_key)
        .unwrap();
    let signed = SignedSessionOutcome {
        outcome,
        signatures: [(PeerId(0), signature)].into_iter().collect(),
    };
    let mut session = Session::open(store.clone(), session_config).unwrap();
    session
        .adopt(
            signed.clone(),
            config.modules(),
            &runtime_fixture::Backend::new(),
        )
        .unwrap();
    assert_eq!(session.ready_outcome(), Some(&signed));
    assert_eq!(
        config
            .modules()
            .wallet()
            .snapshot(&store.snapshot().unwrap())
            .unwrap()
            .consensus_fee_rate,
        Some(1000)
    );
    store.append_agreement(0, PREFIX).unwrap();
    assert_eq!(
        session::session_count(&store.snapshot().unwrap()).unwrap(),
        0
    );
    assert_eq!(
        session::persisted_status(&store.snapshot().unwrap(), 0).unwrap(),
        Some(SessionStatusV2::Pending(signed.outcome.items.clone()))
    );
    let rows = store
        .snapshot()
        .unwrap()
        .scan_prefix(Namespace::Replicated, b"wallet/v1/")
        .unwrap();
    assert!(!rows.is_empty());
    for (name, bytes) in [
        ("ready-outcome", signed.consensus_encode()),
        (
            "wallet-checkpoint",
            rows.into_iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .consensus_encode(),
        ),
    ] {
        let file = path.parent().unwrap().join(name);
        std::fs::write(&file, bytes).unwrap();
        std::fs::File::open(file).unwrap().sync_all().unwrap();
    }
    session
}

fn verify_completion_recovery(store: &Store, path: &Path) {
    let signed: SignedSessionOutcome =
        decode_whole(&std::fs::read(path.parent().unwrap().join("ready-outcome")).unwrap())
            .unwrap();
    let rows: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
        decode_whole(&std::fs::read(path.parent().unwrap().join("wallet-checkpoint")).unwrap())
            .unwrap();
    let snapshot = store.snapshot().unwrap();
    assert_eq!(
        snapshot
            .scan_prefix(Namespace::Replicated, b"wallet/v1/")
            .unwrap(),
        rows.into_iter().collect::<Vec<_>>()
    );
    assert_eq!(
        runtime_config()
            .modules()
            .wallet()
            .snapshot(&snapshot)
            .unwrap()
            .consensus_fee_rate,
        Some(1000)
    );
    assert_eq!(store.read_agreement(SESSION).unwrap(), PREFIX);
    match session::session_count(&snapshot).unwrap() {
        0 => {
            assert_eq!(session::completed(&snapshot, 0).unwrap(), None);
            assert_eq!(
                session::persisted_status(&snapshot, 0).unwrap(),
                Some(SessionStatusV2::Pending(signed.outcome.items))
            );
            assert_eq!(store.read_agreement(0).unwrap(), PREFIX);
        }
        1 => {
            assert_eq!(session::completed(&snapshot, 0).unwrap(), Some(signed));
            assert_eq!(
                session::persisted_status(&snapshot, 1).unwrap(),
                None,
                "no pending rows may survive a completed session"
            );
            assert!(store.read_agreement(0).unwrap().is_empty());
        }
        _ => panic!("completion count must recover wholly before or after"),
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn restrict_file_writes(pid: u32) {
    // Python is declared by shell.nix; resource.prlimit is Linux stdlib support.
    // This helper owns no storage and changes only the explicitly owned child.
    let mut helper = OwnedChild(Command::new("python3")
        .args(["-c", "import resource,sys; resource.prlimit(int(sys.argv[1]), resource.RLIMIT_FSIZE, (0,0))", &pid.to_string()])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("test requires Python3 from shell.nix"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = helper.0.try_wait().unwrap() {
            assert!(status.success(), "resource limit helper failed");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "resource limit helper deadline; guard kills and reaps it"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn marker(reader: &mut BufReader<UnixStream>, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "storage failure child boundary deadline"
        );
        reader.get_ref().set_read_timeout(Some(remaining)).unwrap();
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() != 0,
            "storage failure child exited before acknowledgement"
        );
        // The Rust test runner also writes its own short progress lines.
        if line.trim() == expected {
            return;
        }
        assert!(
            !line.starts_with("STORAGE-"),
            "unexpected storage boundary marker"
        );
    }
}

#[test]
fn storage_failure_child() {
    let Ok(mode) = std::env::var("MINIMINT_STORAGE_FAILURE_MODE") else {
        return;
    };
    let path = std::path::PathBuf::from(std::env::var_os("MINIMINT_STORAGE_FAILURE_PATH").unwrap());
    let store = Store::open(&path).unwrap();
    let snapshot = store.snapshot().unwrap();
    for namespace in NAMESPACES {
        assert_eq!(
            snapshot.get(namespace, b"ack").unwrap().as_deref(),
            Some(ACK)
        );
    }
    assert_eq!(store.read_agreement(SESSION).unwrap(), PREFIX);
    drop(snapshot);
    let completion = (mode == "finish").then(|| prepare_completion(&store, &path));
    let signal = Arc::new(AtomicBool::new(false));
    // Safe public handler turns SIGXFSZ into an observable flag, so the kernel's
    // EFBIG write failure reaches the storage API rather than killing the child.
    let _registration =
        signal_hook::flag::register(signal_hook::consts::SIGXFSZ, signal.clone()).unwrap();
    println!("STORAGE-READY");
    std::io::stdout().flush().unwrap();
    let mut go = String::new();
    std::io::stdin().read_line(&mut go).unwrap();
    assert_eq!(go, "GO\n");
    let result = match mode.as_str() {
        "append" => store.append_agreement(SESSION, &attempted()).is_err(),
        "commit" => {
            let mut writer = store.transaction().unwrap();
            for namespace in NAMESPACES {
                writer.put(namespace, b"attempt", &attempted()).unwrap();
            }
            writer.commit().is_err()
        }
        "finish" => matches!(completion.unwrap().finish(), Err(SessionError::Storage(_))),
        _ => panic!("unknown failure mode"),
    };
    assert!(
        result,
        "durable API must report storage failure, not success or an earlier session guard"
    );
    assert!(
        signal.load(Ordering::Acquire),
        "actual file-size write error must raise SIGXFSZ"
    );
    println!("STORAGE-WRITE-ERROR-OBSERVED");
    std::io::stdout().flush().unwrap();
    // The caller must stop and reopen after an indeterminate persistence error.
    // Do not keep operating on this engine or rely on its tentative snapshot.
    loop {
        thread::park();
    }
}

#[test]
fn os_file_size_errors_preserve_append_commit_and_session_completion_atomicity() {
    for mode in ["append", "commit", "finish"] {
        let directory = fixture::TestDir::new();
        let path = directory.path().join("store");
        seed(&path);
        let (reader, writer) = UnixStream::pair().unwrap();
        let descriptor: OwnedFd = writer.into();
        let mut child = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage_failure_child", "--nocapture"])
                .env("MINIMINT_STORAGE_FAILURE_MODE", mode)
                .env("MINIMINT_STORAGE_FAILURE_PATH", &path)
                .stdin(Stdio::piped())
                .stdout(Stdio::from(descriptor))
                .spawn()
                .unwrap(),
        );
        let mut reader = BufReader::new(reader);
        marker(&mut reader, "STORAGE-READY");
        // Change only this already-open, acknowledged child's regular-file cap.
        restrict_file_writes(child.0.id());
        child.0.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
        marker(&mut reader, "STORAGE-WRITE-ERROR-OBSERVED");
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
        // This process retains its original limits. Every observation below is
        // from a newly opened engine after the limited process has been reaped.
        let reopened = Store::open(&path).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        if mode == "finish" {
            for namespace in NAMESPACES {
                assert_eq!(
                    snapshot.get(namespace, b"ack").unwrap().as_deref(),
                    Some(ACK)
                );
            }
            verify_completion_recovery(&reopened, &path);
            continue;
        }
        let attempted = attempted();
        let mut present = Vec::new();
        for namespace in NAMESPACES {
            assert_eq!(
                snapshot.get(namespace, b"ack").unwrap().as_deref(),
                Some(ACK)
            );
            let value = snapshot.get(namespace, b"attempt").unwrap();
            assert!(
                value.as_ref().is_none_or(|value| value == &attempted),
                "no partial persisted namespace value"
            );
            present.push(value.is_some());
            assert_eq!(
                snapshot.scan_prefix(namespace, b"").unwrap().len(),
                1 + usize::from(value.is_some())
            );
        }
        let agreement = reopened.read_agreement(SESSION).unwrap();
        assert!(
            agreement.starts_with(PREFIX),
            "acknowledged agreement prefix must survive write failure"
        );
        if mode == "append" {
            assert!(present.iter().all(|value| !value));
            let complete = [PREFIX, attempted.as_slice()].concat();
            assert!(
                agreement == PREFIX || agreement == complete,
                "failed append may recover before or after, never a partial chunk"
            );
        } else {
            assert_eq!(agreement, PREFIX);
            assert!(
                present.iter().all(|value| *value == present[0]),
                "failed commit may recover before or after, never a partial cross-namespace batch"
            );
        }
        // A returned persistence error has an indeterminate outcome. This test
        // intentionally permits either whole transaction outcome, not rollback
        // as an API guarantee. It does require preserved acknowledged data.
    }
}
