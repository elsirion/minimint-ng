use minimint_ng::daemon::options::{self, Command, OptionsError};
use std::{ffi::OsString, time::Duration};
fn args() -> Vec<OsString> {
    [
        "--data-dir",
        "state",
        "--api-bind",
        "127.0.0.1:18100",
        "--p2p-bind",
        "127.0.0.1:18101",
        "--api-url",
        "ws://127.0.0.1:18100/",
        "--p2p-url",
        "fedimint://127.0.0.1:18101/",
        "--bitcoin-rpc",
        "127.0.0.1:18443",
        "--bitcoin-rpc-credentials-file",
        "cookie",
        "--admin-secret-file",
        "admin",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}
#[test]
fn explicit_endpoints_and_ordinary_delay_without_secret_cli_values() {
    let Command::Run(run) = options::parse(args()).ok().unwrap() else {
        panic!("run");
    };
    assert_eq!(run.round_delay, Duration::from_millis(50));
    assert_eq!(run.bitcoin_rpc.port(), 18443);
    assert!(matches!(
        options::parse(Vec::<OsString>::new()),
        Ok(Command::Help)
    ));
    assert!(matches!(
        options::parse([OsString::from("--version")]),
        Ok(Command::Version)
    ));
    let mut duplicate = args();
    duplicate.extend(["--data-dir".into(), "other".into()]);
    assert_eq!(
        options::parse(duplicate).err(),
        Some(OptionsError::Argument)
    );
    let mut secret = args();
    secret.extend(["--admin-secret".into(), "not-in-process-list".into()]);
    assert_eq!(options::parse(secret).err(), Some(OptionsError::Argument));
    let mut delay = args();
    delay.extend(["--round-delay-ms".into(), "0".into()]);
    assert_eq!(options::parse(delay).err(), Some(OptionsError::Profile));
}
#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn secret_file_bounds_permissions_and_exact_newline_policy() {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let path = std::env::temp_dir().join(format!("minimint-secret-options-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(b"admin value\r\n").unwrap();
    drop(file);
    assert_eq!(&*options::read_secret(&path).unwrap(), "admin value");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        options::read_secret(&path).err(),
        Some(OptionsError::SecretFile)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, vec![b'x'; 65537]).unwrap();
    assert_eq!(
        options::read_secret(&path).err(),
        Some(OptionsError::SecretFile)
    );
    fs::write(&path, b"admin\n\n").unwrap();
    assert_eq!(
        options::read_secret(&path).err(),
        Some(OptionsError::SecretFile)
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn p2p_endpoint_uses_runtime_authority_contract() {
    for endpoint in [
        "fedimint://localhost/",
        "fedimint://localhost:9000/path/",
        "tcp://localhost:9000/",
    ] {
        let mut values = args();
        values[9] = endpoint.into();
        assert_eq!(options::parse(values).err(), Some(OptionsError::Profile));
    }
    let mut values = args();
    values[9] = "fedimint://unresolved.invalid:9000/".into();
    assert!(matches!(options::parse(values), Ok(Command::Run(_))));
    for delay in ["-1", "18446744073709551616", "1.5", "1e3"] {
        let mut values = args();
        values.extend(["--round-delay-ms".into(), delay.into()]);
        assert_eq!(options::parse(values).err(), Some(OptionsError::Argument));
    }
}

// Run potentially blocking file-open regressions in a killable process so a
// regression cannot hang the test suite or leave a stuck reader thread behind.
#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn special_secret_file_child() {
    if let Some(path) = std::env::var_os("MINIMINT_TEST_SPECIAL_SECRET") {
        assert_eq!(
            options::read_secret(std::path::Path::new(&path)).err(),
            Some(OptionsError::SecretFile)
        );
    }
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn special_secret_files_are_rejected_without_blocking() {
    use std::{
        fs,
        process::{Command, Stdio},
        thread,
        time::Instant,
    };
    let directory =
        std::env::temp_dir().join(format!("minimint-special-secret-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let fifo = directory.join("fifo");
    assert!(
        Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let link = directory.join("link");
    std::os::unix::fs::symlink(&fifo, &link).unwrap();
    let paths = [fifo, link, directory.clone(), "/dev/null".into()];
    for path in paths {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "special_secret_file_child"])
            .env("MINIMINT_TEST_SPECIAL_SECRET", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(2);
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
        if !status.is_some_and(|status| status.success()) {
            fs::remove_dir_all(&directory).unwrap();
            panic!("special secret file was not rejected within deadline");
        }
    }
    fs::remove_dir_all(directory).unwrap();
}
