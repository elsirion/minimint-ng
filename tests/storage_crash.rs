use minimint_ng::storage::{Namespace::*, Store};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
use fixture::TestDir;

// The child reports an exact boundary, then waits until the parent sends SIGKILL.
// No Rust destructors or database drop flushes execute after that boundary.
#[test]
fn crash_child() {
    let Ok(path) = std::env::var("MINIMINT_STORAGE_CRASH_PATH") else {
        return;
    };
    let mode = std::env::var("MINIMINT_STORAGE_CRASH_MODE").unwrap();
    if mode == "locked" {
        assert!(matches!(
            Store::open(path),
            Err(minimint_ng::storage::StoreError::Database(
                fjall::Error::Locked
            ))
        ));
        return;
    }
    let store = Store::open(path).unwrap();
    if mode == "continuous" {
        for sequence in 0_u64.. {
            store.append_agreement(99, &append_chunk(sequence)).unwrap();
            println!("APPEND_ACK {sequence}");
            std::io::stdout().flush().unwrap();
        }
        unreachable!();
    }
    if mode == "append" {
        store
            .append_agreement(42, b"\0\xffopaque-backup\r\n")
            .unwrap();
    } else {
        let mut tx = store.transaction().unwrap();
        for ns in [Replicated, Local, Agreement, Outbox, ClientBackup] {
            tx.put(ns, b"atomic", b"committed").unwrap();
        }
        tx.clear_agreement(42).unwrap();
        if mode == "after" {
            tx.commit().unwrap();
            ready();
        }
        std::hint::black_box(&tx);
        ready();
    }
    ready();
}
fn ready() -> ! {
    println!("STORAGE_BOUNDARY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
fn kill_at_boundary(path: &std::path::Path, mode: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture"])
        .env("MINIMINT_STORAGE_CRASH_PATH", path)
        .env("MINIMINT_STORAGE_CRASH_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let reached = BufReader::new(stdout)
            .lines()
            .any(|line| line.unwrap() == "STORAGE_BOUNDARY");
        let _ = sender.send(reached);
    });
    let reached = receiver.recv_timeout(std::time::Duration::from_secs(30));
    let _ = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert!(
        matches!(reached, Ok(true)),
        "child failed or timed out before boundary: {reached:?}"
    );
    assert!(!status.success());
}
#[test]
fn process_kill_before_after_commit_and_agreement_append() {
    let dir = TestDir::new();
    kill_at_boundary(dir.path(), "append");
    {
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(
            store.read_agreement(42).unwrap(),
            b"\0\xffopaque-backup\r\n"
        );
    }
    kill_at_boundary(dir.path(), "before");
    {
        let store = Store::open(dir.path()).unwrap();
        for ns in [Replicated, Local, Agreement, Outbox, ClientBackup] {
            assert_eq!(store.snapshot().unwrap().get(ns, b"atomic").unwrap(), None);
        }
        assert_eq!(
            store.read_agreement(42).unwrap(),
            b"\0\xffopaque-backup\r\n"
        );
    }
    kill_at_boundary(dir.path(), "after");
    let store = Store::open(dir.path()).unwrap();
    for ns in [Replicated, Local, Agreement, Outbox, ClientBackup] {
        assert_eq!(
            store.snapshot().unwrap().get(ns, b"atomic").unwrap(),
            Some(b"committed".to_vec())
        );
    }
    assert!(store.read_agreement(42).unwrap().is_empty());
}

#[test]
fn separate_process_cannot_open_live_database() {
    let dir = TestDir::new();
    let _store = Store::open(dir.path()).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture"])
        .env("MINIMINT_STORAGE_CRASH_PATH", dir.path())
        .env("MINIMINT_STORAGE_CRASH_MODE", "locked")
        .status()
        .unwrap();
    assert!(status.success());
}

const APPEND_CHUNK_SIZE: usize = 256 * 1024;
fn append_chunk(sequence: u64) -> Vec<u8> {
    let mut chunk = vec![(sequence % 251) as u8; APPEND_CHUNK_SIZE];
    chunk[..8].copy_from_slice(&sequence.to_be_bytes());
    chunk
}

#[test]
fn kill_continuous_appends_preserves_every_acknowledged_byte() {
    let dir = TestDir::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture"])
        .env("MINIMINT_STORAGE_CRASH_PATH", dir.path())
        .env("MINIMINT_STORAGE_CRASH_MODE", "continuous")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    // A surviving parent witnesses flushed acknowledgments on a pipe. The child
    // immediately starts another append, without waiting at a clean boundary.
    let reader = std::thread::spawn(move || {
        let mut acknowledgments = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if let Some(sequence) = line.strip_prefix("APPEND_ACK ") {
                let sequence: u64 = sequence.parse().unwrap();
                acknowledgments.push(sequence);
                let _ = sender.send(sequence);
            }
        }
        acknowledgments
    });
    let mut reached = true;
    for expected in 0..8 {
        if receiver.recv_timeout(std::time::Duration::from_secs(30)) != Ok(expected) {
            reached = false;
            break;
        }
    }
    let _ = child.kill();
    let status = child.wait().unwrap();
    // Include all acknowledgments already in the pipe, even those delivered
    // while the parent was issuing SIGKILL.
    let acknowledgments = reader.join().unwrap();
    assert!(
        reached,
        "continuous writer failed before eight acknowledgments"
    );
    assert!(!status.success());
    let recovered = Store::open(dir.path()).unwrap().read_agreement(99).unwrap();
    assert_eq!(
        recovered.len() % APPEND_CHUNK_SIZE,
        0,
        "torn committed chunk"
    );
    assert!(recovered.len() >= acknowledgments.len() * APPEND_CHUNK_SIZE);
    for (expected, sequence) in acknowledgments.into_iter().enumerate() {
        assert_eq!(sequence, expected as u64);
        assert_eq!(
            &recovered[expected * APPEND_CHUNK_SIZE..(expected + 1) * APPEND_CHUNK_SIZE],
            append_chunk(sequence)
        );
    }
    // A final commit may have completed before its acknowledgment. Its bytes
    // must still be an exact complete chunk, never a partially applied append.
    for (sequence, chunk) in recovered.chunks_exact(APPEND_CHUNK_SIZE).enumerate() {
        assert_eq!(chunk, append_chunk(sequence as u64));
    }
}
