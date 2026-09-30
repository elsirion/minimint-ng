//! Signals/forced exits run only in bounded subprocesses, never in the test host.
use minimint_ng::daemon::shutdown::{Shutdown, ShutdownError};
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
fn shutdown_child() {
    let Some(mode) = std::env::var_os("MINIMINT_SHUTDOWN_MODE") else {
        return;
    };
    let shutdown = Shutdown::install(Duration::from_millis(200)).unwrap();
    assert!(!shutdown.flag().load(std::sync::atomic::Ordering::Acquire));
    let marker = std::env::var_os("MINIMINT_SHUTDOWN_READY").unwrap();
    if mode == "deadline" {
        let guard = shutdown.deadline(Duration::from_millis(200)).unwrap();
        std::fs::write(marker, b"ready").unwrap();
        thread::sleep(Duration::from_secs(20));
        drop(guard);
        panic!("operation watchdog did not terminate child");
    }
    std::fs::write(marker, b"ready").unwrap();
    if mode == "scopeclear" {
        drop(shutdown.deadline(Duration::from_millis(100)).unwrap());
        thread::sleep(Duration::from_millis(250));
        assert!(!shutdown.is_requested());
        shutdown.finish().unwrap();
        return;
    }
    if mode == "finish" {
        let first = shutdown.deadline(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            shutdown.deadline(Duration::from_secs(1)),
            Err(ShutdownError::ActiveDeadline)
        ));
        drop(first);
        drop(shutdown.deadline(Duration::from_secs(1)).unwrap());
        shutdown.request();
        assert!(shutdown.is_requested());
        shutdown.finish().unwrap();
        thread::sleep(Duration::from_millis(350));
        return;
    }
    if mode == "cooperative" {
        while !shutdown.is_requested() {
            thread::sleep(Duration::from_millis(2));
        }
        shutdown.finish().unwrap();
        return;
    }
    if mode == "drop" {
        shutdown.request();
        drop(shutdown);
        thread::sleep(Duration::from_millis(350));
        return;
    }
    // Deliberately uncooperative startup/join stand-in. Watchdog must exit even
    // though the owner does not poll the signal flag or drop its deadline guard.
    thread::sleep(Duration::from_secs(20));
    panic!("watchdog did not terminate child");
}
fn scenario(mode: &str, signal: Option<&str>, expected: i32) {
    let marker = std::env::temp_dir().join(format!(
        "minimint-shutdown-{}-{mode}-{}",
        std::process::id(),
        signal.unwrap_or("none")
    ));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "shutdown_child"])
        .env("MINIMINT_SHUTDOWN_MODE", mode)
        .env("MINIMINT_SHUTDOWN_READY", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < end {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    if marker.exists()
        && let Some(signal) = signal
    {
        assert!(
            Command::new("kill")
                .args([signal, &child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= end {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let _ = std::fs::remove_file(marker);
    assert_eq!(status.and_then(|status| status.code()), Some(expected));
}
#[test]
fn signal_cooperation_watchdog_deadlines_and_joined_finish() {
    scenario("cooperative", Some("-INT"), 0);
    scenario("cooperative", Some("-TERM"), 0);
    scenario("blocked", Some("-INT"), 2);
    scenario("blocked", Some("-TERM"), 2);
    scenario("deadline", None, 2);
    scenario("scopeclear", None, 0);
    scenario("finish", None, 0);
    scenario("drop", None, 0);
}
