//! Bounded address resolution in an owned helper process. The executable must
//! implement the internal helper mode below and must not spawn descendants.
//! DNS may block inside the helper; cancellation kills and reaps that process.
use std::{
    ffi::OsStr,
    io::{Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const MAX_AUTHORITY: usize = 4096;
const MAX_OUTPUT: usize = 64 * 1024;
const MAX_ADDRESSES: usize = 1024;
const TICK: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    InvalidInput,
    Spawn,
    Timeout,
    Cancelled,
    Failed,
    InvalidOutput,
}
impl std::fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "Invalid resolver input",
            Self::Spawn => "Cannot start resolver",
            Self::Timeout => "Address resolution timed out",
            Self::Cancelled => "Address resolution cancelled",
            Self::Failed => "Address resolution failed",
            Self::InvalidOutput => "Invalid resolver response",
        })
    }
}
impl std::error::Error for ResolveError {}

fn authority(value: &OsStr) -> Result<&str, ResolveError> {
    let text = value.to_str().ok_or(ResolveError::InvalidInput)?;
    if text.is_empty()
        || text.len() > MAX_AUTHORITY
        || text
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ResolveError::InvalidInput);
    }
    Ok(text)
}

fn normalize(addresses: &mut Vec<SocketAddr>) {
    addresses.sort_by_key(|address| (!address.is_ipv4(), *address));
    addresses.dedup();
}

/// Invoke only for the exact internal command before loading options, secrets,
/// signal handlers, storage or guardian workers. Output is a bounded internal
/// newline-delimited SocketAddr protocol, not a guardian API response.
pub fn run_helper(value: &OsStr) -> Result<(), ResolveError> {
    let mut addresses: Vec<_> = authority(value)?
        .to_socket_addrs()
        .map_err(|_| ResolveError::Failed)?
        .take(MAX_ADDRESSES + 1)
        .collect();
    if addresses.is_empty() || addresses.len() > MAX_ADDRESSES {
        return Err(ResolveError::Failed);
    }
    normalize(&mut addresses);
    let mut output = String::new();
    for address in addresses {
        use std::fmt::Write;
        writeln!(&mut output, "{address}").map_err(|_| ResolveError::Failed)?;
    }
    if output.len() > MAX_OUTPUT {
        return Err(ResolveError::Failed);
    }
    std::io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(|_| ResolveError::Failed)
}

struct Helper(Option<Child>);
impl Helper {
    fn stop_and_join(&mut self) -> Result<(), ResolveError> {
        let Some(mut child) = self.0.take() else {
            return Ok(());
        };
        if child.try_wait().ok().flatten().is_none() {
            // A race with normal exit can make kill report an error; wait is
            // still required and is the evidence that the owned child joined.
            let _ = child.kill();
        }
        child.wait().map_err(|_| ResolveError::Failed)?;
        Ok(())
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn check(deadline: Instant, cancelled: &AtomicBool) -> Result<(), ResolveError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(ResolveError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(ResolveError::Timeout);
    }
    Ok(())
}

fn decode(output: &[u8]) -> Result<Vec<SocketAddr>, ResolveError> {
    let text = std::str::from_utf8(output).map_err(|_| ResolveError::InvalidOutput)?;
    if !text.ends_with('\n') {
        return Err(ResolveError::InvalidOutput);
    }
    let mut addresses = Vec::new();
    for line in text.lines() {
        if addresses.len() == MAX_ADDRESSES {
            return Err(ResolveError::InvalidOutput);
        }
        addresses.push(line.parse().map_err(|_| ResolveError::InvalidOutput)?);
    }
    if addresses.is_empty() {
        return Err(ResolveError::InvalidOutput);
    }
    normalize(&mut addresses);
    Ok(addresses)
}

/// The caller supplies its own executable (normally current_exe), which must
/// recognize `--internal-resolve-authority AUTHORITY` without normal startup.
/// No resolver threads are created. A nonblocking socket drains helper output
/// while the parent checks cancellation, deadline, output limits and child exit.
pub fn resolve(
    executable: &Path,
    value: &str,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Vec<SocketAddr>, ResolveError> {
    authority(OsStr::new(value))?;
    if timeout.is_zero() {
        return Err(ResolveError::InvalidInput);
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ResolveError::InvalidInput)?;
    check(deadline, cancelled)?;
    let (mut reader, writer) = UnixStream::pair().map_err(|_| ResolveError::Spawn)?;
    reader
        .set_nonblocking(true)
        .map_err(|_| ResolveError::Spawn)?;
    let descriptor: OwnedFd = writer.into();
    let child = Command::new(executable)
        .args(["--internal-resolve-authority", value])
        .stdin(Stdio::null())
        .stdout(Stdio::from(descriptor))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ResolveError::Spawn)?;
    let mut helper = Helper(Some(child));
    let result = (|| {
        let mut output = Vec::new();
        let mut eof = false;
        loop {
            check(deadline, cancelled)?;
            while !eof {
                check(deadline, cancelled)?;
                let mut bytes = [0u8; 4096];
                match reader.read(&mut bytes) {
                    Ok(0) => eof = true,
                    Ok(length) => {
                        if output.len() + length > MAX_OUTPUT {
                            return Err(ResolveError::InvalidOutput);
                        }
                        output.extend_from_slice(&bytes[..length]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(ResolveError::Failed),
                }
            }
            check(deadline, cancelled)?;
            let status = helper
                .0
                .as_mut()
                .ok_or(ResolveError::Failed)?
                .try_wait()
                .map_err(|_| ResolveError::Failed)?;
            check(deadline, cancelled)?;
            if let Some(status) = status {
                if !status.success() {
                    return Err(ResolveError::Failed);
                }
                if eof {
                    return decode(&output);
                }
            }
            thread::sleep(TICK.min(deadline.saturating_duration_since(Instant::now())));
        }
    })();
    helper.stop_and_join()?;
    result
}
