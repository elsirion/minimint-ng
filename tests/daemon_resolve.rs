#![cfg(unix)]
use minimint_ng::daemon::resolve::{ResolveError, resolve};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_fedimintd"))
}
fn script(root: &Path, content: &str) -> PathBuf {
    let path = root.join("resolver");
    fs::write(&path, format!("#!/usr/bin/env bash\n{content}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn reaped(pidfile: &Path) {
    let pid = fs::read_to_string(pidfile).unwrap();
    assert!(
        !Command::new("kill")
            .args(["-0", pid.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "resolver helper must be reaped before return"
    );
}

#[test]
fn actual_binary_resolves_numeric_ipv4_ipv6_and_localhost_without_startup() {
    let cancelled = AtomicBool::new(false);
    for authority in ["127.0.0.1:18444", "[::1]:18444", "localhost:18444"] {
        let addresses = resolve(binary(), authority, Duration::from_secs(3), &cancelled).unwrap();
        assert!(!addresses.is_empty());
        assert!(
            addresses
                .iter()
                .all(|address| address.port() == 18444 && address.ip().is_loopback())
        );
    }
}

#[test]
fn invalid_and_cancelled_requests_never_spawn_a_helper() {
    let missing = Path::new("/nonexistent/minimint-resolver-test");
    let cancelled = AtomicBool::new(false);
    assert_eq!(
        resolve(
            missing,
            "localhost:80\n",
            Duration::from_secs(1),
            &cancelled
        ),
        Err(ResolveError::InvalidInput)
    );
    assert_eq!(
        resolve(missing, "localhost:80", Duration::ZERO, &cancelled),
        Err(ResolveError::InvalidInput)
    );
    cancelled.store(true, Ordering::Release);
    assert_eq!(
        resolve(missing, "localhost:80", Duration::from_secs(1), &cancelled),
        Err(ResolveError::Cancelled)
    );
    cancelled.store(false, Ordering::Release);
    assert_eq!(
        resolve(missing, "localhost:80", Duration::from_secs(1), &cancelled),
        Err(ResolveError::Spawn)
    );
}

#[test]
fn helper_exit_and_output_are_validated_and_addresses_normalized() {
    for (content, expected) in [
        ("exit 7", Err(ResolveError::Failed)),
        (
            "printf 'not-an-address\\n'",
            Err(ResolveError::InvalidOutput),
        ),
        ("printf '127.0.0.1:80'", Err(ResolveError::InvalidOutput)),
        ("printf '%070000d' 1", Err(ResolveError::InvalidOutput)),
        (
            "printf '[::1]:80\\n127.0.0.1:80\\n127.0.0.1:80\\n'",
            Ok(vec![
                "127.0.0.1:80".parse().unwrap(),
                "[::1]:80".parse().unwrap(),
            ]),
        ),
    ] {
        let root = fixture::TestDir::new();
        let executable = script(root.path(), content);
        assert_eq!(
            resolve(
                &executable,
                "ignored:80",
                Duration::from_secs(3),
                &AtomicBool::new(false)
            ),
            expected
        );
    }
}

#[test]
fn blocked_helper_timeout_kills_and_reaps_without_stopping_parent() {
    let root = fixture::TestDir::new();
    let pidfile = root.path().join("pid");
    let executable = script(
        root.path(),
        &format!(
            "printf '%s' \"$$\" > '{}'; exec sleep 30",
            pidfile.display()
        ),
    );
    let start = Instant::now();
    assert_eq!(
        resolve(
            &executable,
            "ignored:80",
            Duration::from_millis(300),
            &AtomicBool::new(false)
        ),
        Err(ResolveError::Timeout)
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    reaped(&pidfile);
    // Successful independent resolution remains available after this timeout.
    assert!(
        resolve(
            binary(),
            "127.0.0.1:80",
            Duration::from_secs(3),
            &AtomicBool::new(false)
        )
        .is_ok()
    );
}

#[test]
fn cancellation_interrupts_a_running_helper_and_joins_it() {
    let root = fixture::TestDir::new();
    let pidfile = root.path().join("pid");
    let executable = script(
        root.path(),
        &format!(
            "printf '%s' \"$$\" > '{}'; exec sleep 30",
            pidfile.display()
        ),
    );
    let cancelled = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !pidfile.exists() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
            cancelled.store(true, Ordering::Release);
        });
        assert_eq!(
            resolve(
                &executable,
                "ignored:80",
                Duration::from_secs(10),
                &cancelled
            ),
            Err(ResolveError::Cancelled)
        );
    });
    reaped(&pidfile);
}
