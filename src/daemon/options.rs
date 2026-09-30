//! Narrow daemon CLI. Secrets are supplied by files, never command-line values.
use crate::config::CanonicalUrl;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

pub const USAGE: &str = "fedimintd --data-dir PATH --api-bind IP:PORT --p2p-bind IP:PORT \
--api-url ws://HOST:PORT/ --p2p-url fedimint://HOST:PORT/ \
--bitcoin-rpc IP:PORT --bitcoin-rpc-credentials-file PATH --admin-secret-file PATH \
[--access-secret-file PATH] [--round-delay-ms 50]\n\nInitial deployment profile: Bitcoin regtest, built-in Mint v2 and Wallet v2.\nCredentials file contains username:password (or Bitcoin Core cookie contents).\nSecret files require Linux x86_64 with /proc/self/fd mounted.\nThey must be private regular files without a final symlink; one final LF or CRLF is stripped.\n";
pub struct Options {
    pub data_dir: PathBuf,
    pub api_bind: SocketAddr,
    pub p2p_bind: SocketAddr,
    pub api_url: CanonicalUrl,
    pub p2p_url: CanonicalUrl,
    pub bitcoin_rpc: SocketAddr,
    pub bitcoin_credentials_file: PathBuf,
    pub admin_secret_file: PathBuf,
    pub access_secret_file: Option<PathBuf>,
    pub round_delay: Duration,
}
pub enum Command {
    Run(Box<Options>),
    Help,
    Version,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionsError {
    Argument,
    Missing,
    Address,
    Url,
    Profile,
    SecretFile,
}
impl std::fmt::Display for OptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Argument => "Invalid or duplicate daemon argument",
            Self::Missing => "Required daemon argument missing",
            Self::Address => "Invalid daemon socket address",
            Self::Url => "Unsupported daemon URL",
            Self::Profile => "Unsupported daemon profile",
            Self::SecretFile => "Cannot read a valid private secret file",
        })
    }
}
impl std::error::Error for OptionsError {}
fn string(value: OsString) -> Result<String, OptionsError> {
    value.into_string().map_err(|_| OptionsError::Argument)
}
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, OptionsError> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };
    if first == "--help" || first == "--version" {
        if args.next().is_some() {
            return Err(OptionsError::Argument);
        }
        return Ok(if first == "--help" {
            Command::Help
        } else {
            Command::Version
        });
    }
    let mut args = std::iter::once(first).chain(args);
    let mut fields = BTreeMap::new();
    while let Some(flag) = args.next() {
        let flag = string(flag)?;
        if !matches!(
            flag.as_str(),
            "--data-dir"
                | "--api-bind"
                | "--p2p-bind"
                | "--api-url"
                | "--p2p-url"
                | "--bitcoin-rpc"
                | "--bitcoin-rpc-credentials-file"
                | "--admin-secret-file"
                | "--access-secret-file"
                | "--round-delay-ms"
        ) {
            return Err(OptionsError::Argument);
        }
        let value = args
            .next()
            .filter(|v| !v.is_empty())
            .ok_or(OptionsError::Missing)?;
        if fields.insert(flag, value).is_some() {
            return Err(OptionsError::Argument);
        }
    }
    let mut take = |name: &str| fields.remove(name).ok_or(OptionsError::Missing);
    let data_dir = PathBuf::from(take("--data-dir")?);
    let api_bind = string(take("--api-bind")?)?
        .parse()
        .map_err(|_| OptionsError::Address)?;
    let p2p_bind = string(take("--p2p-bind")?)?
        .parse()
        .map_err(|_| OptionsError::Address)?;
    let api_url =
        CanonicalUrl::simple(&string(take("--api-url")?)?).map_err(|_| OptionsError::Url)?;
    let p2p_url =
        CanonicalUrl::simple(&string(take("--p2p-url")?)?).map_err(|_| OptionsError::Url)?;
    if !api_url.as_str().starts_with("ws://") || super::config::tcp_authority(&p2p_url).is_err() {
        return Err(OptionsError::Profile);
    }
    let bitcoin_rpc: SocketAddr = string(take("--bitcoin-rpc")?)?
        .parse()
        .map_err(|_| OptionsError::Address)?;
    if !bitcoin_rpc.ip().is_loopback() {
        return Err(OptionsError::Profile);
    }
    let bitcoin_credentials_file = PathBuf::from(take("--bitcoin-rpc-credentials-file")?);
    let admin_secret_file = PathBuf::from(take("--admin-secret-file")?);
    let access_secret_file = fields.remove("--access-secret-file").map(PathBuf::from);
    let delay = fields
        .remove("--round-delay-ms")
        .map(string)
        .transpose()?
        .map(|s| s.parse::<u64>().map_err(|_| OptionsError::Argument))
        .transpose()?
        .unwrap_or(50);
    if delay == 0 || delay > 60_000 {
        return Err(OptionsError::Profile);
    }
    Ok(Command::Run(Box::new(Options {
        data_dir,
        api_bind,
        p2p_bind,
        api_url,
        p2p_url,
        bitcoin_rpc,
        bitcoin_credentials_file,
        admin_secret_file,
        access_secret_file,
        round_delay: Duration::from_millis(delay),
    })))
}
// Linux x86_64 UAPI constants, checked against <fcntl.h> in the pinned Nix
// environment: __O_PATH=010000000 and __O_NOFOLLOW=0400000. Do not generalize
// these values to other ABIs. O_PATH invokes no device/FIFO open operation.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn open_private_regular(path: &Path) -> Result<std::fs::File, OptionsError> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    const O_PATH: i32 = 0o10000000;
    const O_NOFOLLOW: i32 = 0o400000;
    let reference = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH | O_NOFOLLOW)
        .open(path)
        .map_err(|_| OptionsError::SecretFile)?;
    let before = reference.metadata().map_err(|_| OptionsError::SecretFile)?;
    if !before.is_file() || before.mode() & 0o077 != 0 {
        return Err(OptionsError::SecretFile);
    }
    // Keep reference alive while reopening the already-validated inode through
    // procfs. Replacing the original pathname cannot redirect this read-open to
    // a FIFO/device. Revalidate the readable descriptor, including permissions.
    let file = std::fs::File::open(format!("/proc/self/fd/{}", reference.as_raw_fd()))
        .map_err(|_| OptionsError::SecretFile)?;
    let after = file.metadata().map_err(|_| OptionsError::SecretFile)?;
    if !after.is_file()
        || after.mode() & 0o077 != 0
        || (after.dev(), after.ino()) != (before.dev(), before.ino())
    {
        return Err(OptionsError::SecretFile);
    }
    Ok(file)
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn open_private_regular(_: &Path) -> Result<std::fs::File, OptionsError> {
    Err(OptionsError::SecretFile)
}
/// Read at most 64KiB from a private regular file. Linux x86_64 and procfs are
/// required; other platforms fail closed. Final symlinks and special files are
/// rejected before read-open. Regular filesystem I/O can still block; this is
/// not a general filesystem deadline. Errors omit path/content; files are not modified.
pub fn read_secret(path: &Path) -> Result<Zeroizing<String>, OptionsError> {
    let file = open_private_regular(path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(65_537));
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| OptionsError::SecretFile)?;
    if bytes.len() > 65_536 {
        return Err(OptionsError::SecretFile);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| OptionsError::SecretFile)?;
    let text = if let Some(text) = text.strip_suffix('\n') {
        text.strip_suffix('\r').unwrap_or(text)
    } else {
        text
    };
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(OptionsError::SecretFile);
    }
    Ok(Zeroizing::new(text.to_owned()))
}
