//! RFC6455 plain WebSocket transport for the local API and daemon peer RPC.
//! No extensions or subprotocols are negotiated. API-001 transport access auth
//! is Basic(base64(UTF8("fedimint:" + secret))), separate from JSON admin auth.
//! Each handshake/message operation has a total local deadline. Returned message
//! buffers belong to callers and may contain secrets; no message implements Debug.
use crate::{codec::text, crypto::random_bytes};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_header_bytes: usize,
    pub max_message_bytes: usize,
    pub handshake_timeout: Duration,
    pub operation_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 16 * 1024,
            max_message_bytes: 16 * 1024 * 1024,
            handshake_timeout: Duration::from_secs(10),
            operation_timeout: Duration::from_secs(60),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsError {
    Io,
    Timeout,
    Protocol,
    Version,
    Unauthorized,
    Limit,
    Utf8,
    Closed,
    Crypto,
}
impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebSocket transport failed: {self:?}")
    }
}
impl std::error::Error for WsError {}
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Close { code: Option<u16>, reason: String },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}
pub struct ShutdownHandle(TcpStream);
impl ShutdownHandle {
    pub fn shutdown(&self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
pub struct WebSocket {
    stream: TcpStream,
    role: Role,
    limits: Limits,
    writer: WebSocketWriter,
}
fn deadline(duration: Duration) -> Result<Instant, WsError> {
    Instant::now().checked_add(duration).ok_or(WsError::Limit)
}
fn remaining(end: Instant) -> Result<Duration, WsError> {
    end.checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(WsError::Timeout)
}
fn io_error(e: std::io::Error) -> WsError {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => WsError::Timeout,
        _ => WsError::Io,
    }
}
fn read_exact(stream: &mut TcpStream, mut out: &mut [u8], end: Instant) -> Result<(), WsError> {
    while !out.is_empty() {
        stream
            .set_read_timeout(Some(remaining(end)?))
            .map_err(io_error)?;
        let count = stream.read(out).map_err(io_error)?;
        if count == 0 {
            return Err(WsError::Closed);
        }
        out = &mut out[count..];
    }
    Ok(())
}
fn write_all(stream: &mut TcpStream, mut bytes: &[u8], end: Instant) -> Result<(), WsError> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(end)?))
            .map_err(io_error)?;
        let count = stream.write(bytes).map_err(io_error)?;
        if count == 0 {
            return Err(WsError::Closed);
        }
        bytes = &bytes[count..];
    }
    Ok(())
}
fn base64(bytes: &[u8]) -> Zeroizing<String> {
    let raw = Zeroizing::new(text::base64url_encode(bytes));
    let mut out = Zeroizing::new(String::with_capacity(raw.len() + 3));
    out.extend(raw.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        _ => c,
    }));
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}
fn basic(secret: &str) -> Result<Zeroizing<String>, WsError> {
    if secret.chars().any(char::is_control) {
        return Err(WsError::Protocol);
    }
    let bytes = Zeroizing::new(format!("fedimint:{secret}"));
    let encoded = base64(bytes.as_bytes());
    Ok(Zeroizing::new(format!("Basic {}", *encoded)))
}
fn accept_key(key: &str) -> Zeroizing<String> {
    let value = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64(&openssl::sha::sha1(value.as_bytes()))
}
fn valid_key(key: &str) -> bool {
    if !key.is_ascii() || key.len() != 24 || !key.ends_with("==") {
        return false;
    }
    let raw: String = key[..22]
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            _ => c,
        })
        .collect();
    text::base64url_decode(&raw).is_ok_and(|bytes| bytes.len() == 16 && *base64(&bytes) == key)
}
fn header_read(
    stream: &mut TcpStream,
    limits: Limits,
    end: Instant,
) -> Result<Zeroizing<Vec<u8>>, WsError> {
    let mut bytes = Zeroizing::new(Vec::new());
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= limits.max_header_bytes {
            return Err(WsError::Limit);
        }
        let mut one = [0];
        read_exact(stream, &mut one, end)?;
        append_secret(&mut bytes, &one, limits.max_header_bytes);
    }
    Ok(bytes)
}
struct Headers<'a> {
    first: &'a str,
    fields: Vec<(&'a str, &'a str)>,
}
impl<'a> Headers<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, WsError> {
        let text = std::str::from_utf8(bytes).map_err(|_| WsError::Protocol)?;
        let mut lines = text.split("\r\n");
        let first = lines.next().ok_or(WsError::Protocol)?;
        if first.bytes().any(|b| b.is_ascii_control()) {
            return Err(WsError::Protocol);
        }
        let mut fields = Vec::new();
        for line in lines.filter(|s| !s.is_empty()) {
            let (name, value) = line.split_once(':').ok_or(WsError::Protocol)?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
            {
                return Err(WsError::Protocol);
            }
            fields.push((name, value.trim_matches([' ', '\t'])));
        }
        Ok(Self { first, fields })
    }
    fn one(&self, name: &str) -> Result<Option<&'a str>, WsError> {
        let mut values = self
            .fields
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v);
        let value = values.next();
        if values.next().is_some() {
            return Err(WsError::Protocol);
        }
        Ok(value)
    }
    fn token(&self, name: &str, token: &str) -> bool {
        self.fields
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .any(|(_, v)| v.split(',').any(|s| s.trim().eq_ignore_ascii_case(token)))
    }
    fn upgrade(&self) -> Result<(), WsError> {
        if !self.token("upgrade", "websocket")
            || !self.token("connection", "upgrade")
            || self.one("transfer-encoding")?.is_some()
            || self.one("content-length")?.is_some_and(|v| v != "0")
        {
            return Err(WsError::Protocol);
        }
        Ok(())
    }
}
impl WebSocket {
    fn validate(limits: Limits) -> Result<(), WsError> {
        if limits.max_header_bytes == 0
            || limits.max_message_bytes == 0
            || limits.handshake_timeout.is_zero()
            || limits.operation_timeout.is_zero()
        {
            return Err(WsError::Limit);
        }
        Ok(())
    }
    pub fn accept(
        mut stream: TcpStream,
        access_secret: Option<&str>,
        limits: Limits,
    ) -> Result<Self, WsError> {
        Self::validate(limits)?;
        stream.set_nonblocking(false).map_err(io_error)?;
        let end = deadline(limits.handshake_timeout)?;
        let expected = access_secret.map(basic).transpose()?;
        let result = (|| {
            let bytes = header_read(&mut stream, limits, end)?;
            let headers = Headers::parse(&bytes)?;
            let parts: Vec<_> = headers.first.split(' ').collect();
            if parts.len() != 3
                || parts[0] != "GET"
                || !valid_path(parts[1])
                || parts[2] != "HTTP/1.1"
                || headers.one("host")?.is_none_or(|h| !valid_host(h))
            {
                return Err(WsError::Protocol);
            }
            if let Some(expected) = &expected {
                let actual = headers.one("authorization")?.unwrap_or("");
                if actual.len() != expected.len()
                    || !openssl::memcmp::eq(actual.as_bytes(), expected.as_bytes())
                {
                    return Err(WsError::Unauthorized);
                }
            } else {
                headers.one("authorization")?;
            }
            headers.upgrade()?;
            if headers.one("sec-websocket-version")? != Some("13") {
                return Err(WsError::Version);
            }
            let key = headers.one("sec-websocket-key")?.ok_or(WsError::Protocol)?;
            if !valid_key(key) {
                return Err(WsError::Protocol);
            }
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                *accept_key(key)
            );
            if response.len() > limits.max_header_bytes {
                return Err(WsError::Limit);
            }
            write_all(&mut stream, response.as_bytes(), end)
        })();
        if let Err(error) = result {
            let response: &[u8] = match error {
                WsError::Unauthorized => b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"fedimint\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                WsError::Version => b"HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                _ => b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            };
            let _ = write_all(&mut stream, response, end);
            let _ = stream.shutdown(Shutdown::Both);
            return Err(error);
        }
        Self::upgraded(stream, Role::Server, limits)
    }
    pub fn connect(
        mut stream: TcpStream,
        host: &str,
        path: &str,
        access_secret: Option<&str>,
        limits: Limits,
    ) -> Result<Self, WsError> {
        Self::validate(limits)?;
        if !valid_host(host) || !valid_path(path) {
            return Err(WsError::Protocol);
        }
        stream.set_nonblocking(false).map_err(io_error)?;
        let end = deadline(limits.handshake_timeout)?;
        let key = base64(&random_bytes::<16>().map_err(|_| WsError::Crypto)?);
        let authorization = access_secret.map(basic).transpose()?;
        let mut request = Zeroizing::new(format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n",
            *key
        ));
        // Reserve before inserting credentials so String growth cannot retain
        // an old allocation containing the authorization header.
        request.reserve(authorization.as_ref().map_or(0, |a| a.len()) + 32);
        if let Some(auth) = authorization {
            request.push_str("Authorization: ");
            request.push_str(&auth);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        if request.len() > limits.max_header_bytes {
            return Err(WsError::Limit);
        }
        write_all(&mut stream, request.as_bytes(), end)?;
        let bytes = header_read(&mut stream, limits, end)?;
        let headers = Headers::parse(&bytes)?;
        let mut status = headers.first.split(' ');
        if status.next() != Some("HTTP/1.1") {
            return Err(WsError::Protocol);
        }
        match status.next() {
            Some("401") => return Err(WsError::Unauthorized),
            Some("101") => (),
            _ => return Err(WsError::Protocol),
        }
        headers.upgrade()?;
        if headers.one("sec-websocket-accept")? != Some(&*accept_key(&key))
            || headers.one("sec-websocket-extensions")?.is_some()
            || headers.one("sec-websocket-protocol")?.is_some()
        {
            return Err(WsError::Protocol);
        }
        Self::upgraded(stream, Role::Client, limits)
    }
    pub fn shutdown_handle(&self) -> Result<ShutdownHandle, WsError> {
        Ok(ShutdownHandle(self.stream.try_clone().map_err(io_error)?))
    }
    fn upgraded(stream: TcpStream, role: Role, limits: Limits) -> Result<Self, WsError> {
        let writer = WebSocketWriter {
            state: Arc::new(Mutex::new(WriteState {
                stream: stream.try_clone().map_err(io_error)?,
                role,
            })),
            shutdown: Arc::new(stream.try_clone().map_err(io_error)?),
            closed: Arc::new(AtomicBool::new(false)),
            close_sent: Arc::new(AtomicBool::new(false)),
            limits,
        };
        Ok(Self {
            stream,
            role,
            limits,
            writer,
        })
    }
    /// Independent serialized writer. Dropping the read owner closes every handle.
    pub fn writer(&self) -> WebSocketWriter {
        self.writer.clone()
    }
    fn abort(&mut self) {
        self.writer.abort();
    }
    pub fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        self.writer.send_text(text)
    }
    pub fn send_binary(&mut self, bytes: &[u8]) -> Result<(), WsError> {
        self.writer.send_binary(bytes)
    }
    pub fn ping(&mut self, bytes: &[u8]) -> Result<(), WsError> {
        self.writer.ping(bytes)
    }
    pub fn send_close(&mut self, code: Option<u16>, reason: &str) -> Result<(), WsError> {
        self.writer.send_close(code, reason)
    }
    pub fn receive(&mut self) -> Result<Message, WsError> {
        if self.writer.closed.load(Ordering::Acquire) {
            return Err(WsError::Closed);
        }
        let end = deadline(self.limits.operation_timeout)?;
        let result = self.receive_inner(end);
        if let Err(error) = result {
            let code: u16 = match error {
                WsError::Utf8 => 1007,
                WsError::Limit => 1009,
                _ => 1002,
            };
            let _ = self.writer.reply_close(&code.to_be_bytes(), end);
            self.abort();
        }
        result
    }
    fn receive_inner(&mut self, end: Instant) -> Result<Message, WsError> {
        let mut assembled = Zeroizing::new(Vec::new());
        let mut kind = None;
        loop {
            let mut header = [0; 2];
            read_exact(&mut self.stream, &mut header, end)?;
            let fin = header[0] & 0x80 != 0;
            let opcode = header[0] & 15;
            let masked = header[1] & 0x80 != 0;
            if header[0] & 0x70 != 0
                || !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10)
                || masked != (self.role == Role::Server)
            {
                return Err(WsError::Protocol);
            }
            let short = header[1] & 127;
            let length = match short {
                126 => {
                    let mut n = [0; 2];
                    read_exact(&mut self.stream, &mut n, end)?;
                    let n = u16::from_be_bytes(n);
                    if n < 126 {
                        return Err(WsError::Protocol);
                    }
                    u64::from(n)
                }
                127 => {
                    let mut n = [0; 8];
                    read_exact(&mut self.stream, &mut n, end)?;
                    let n = u64::from_be_bytes(n);
                    if n < 65536 || n >> 63 != 0 {
                        return Err(WsError::Protocol);
                    }
                    n
                }
                n => u64::from(n),
            };
            if opcode >= 8 {
                if !fin || length > 125 {
                    return Err(WsError::Protocol);
                }
            } else {
                if opcode == 0 && kind.is_none() || opcode != 0 && kind.is_some() {
                    return Err(WsError::Protocol);
                }
                if length
                    > self
                        .limits
                        .max_message_bytes
                        .saturating_sub(assembled.len()) as u64
                {
                    return Err(WsError::Limit);
                }
            }
            let mut mask = [0; 4];
            if masked {
                read_exact(&mut self.stream, &mut mask, end)?;
            }
            let length = usize::try_from(length).map_err(|_| WsError::Limit)?;
            let mut body = Zeroizing::new(vec![0; length]);
            read_exact(&mut self.stream, &mut body, end)?;
            if masked {
                for (i, b) in body.iter_mut().enumerate() {
                    *b ^= mask[i % 4];
                }
            }
            match opcode {
                8 => {
                    if body.len() == 1 {
                        return Err(WsError::Protocol);
                    }
                    let (code, reason) = if body.is_empty() {
                        (None, String::new())
                    } else {
                        let code = u16::from_be_bytes([body[0], body[1]]);
                        if !valid_close(code) {
                            return Err(WsError::Protocol);
                        }
                        (
                            Some(code),
                            std::str::from_utf8(&body[2..])
                                .map_err(|_| WsError::Utf8)?
                                .to_owned(),
                        )
                    };
                    self.writer.reply_close(&body, end)?;
                    self.abort();
                    return Ok(Message::Close { code, reason });
                }
                9 => {
                    self.writer.control(10, &body, end)?;
                }
                10 => (),
                _ => {
                    if opcode != 0 {
                        kind = Some(opcode);
                    }
                    append_secret(&mut assembled, &body, self.limits.max_message_bytes);
                    if fin {
                        let kind = kind.take().ok_or(WsError::Protocol)?;
                        if self.writer.closing() {
                            assembled = Zeroizing::new(Vec::new());
                            continue;
                        }
                        if kind == 1 {
                            std::str::from_utf8(&assembled).map_err(|_| WsError::Utf8)?;
                            return String::from_utf8(std::mem::take(&mut *assembled))
                                .map(Message::Text)
                                .map_err(|_| WsError::Utf8);
                        }
                        return Ok(Message::Binary(std::mem::take(&mut *assembled)));
                    }
                }
            }
        }
    }
}
impl Drop for WebSocket {
    fn drop(&mut self) {
        self.abort();
    }
}
fn valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path.is_ascii()
        && !path
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'#')
}
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.is_ascii()
        && !host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}
fn valid_close(code: u16) -> bool {
    matches!(code,1000..=1003|1007..=1014|3000..=4999)
}
// Replace a growing secret buffer while its previous allocation remains guarded;
// ordinary Vec growth frees the old allocation without erasing its bytes.
// Callers have checked that current length + added bytes fits `maximum`.
fn append_secret(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8], maximum: usize) {
    let needed = buffer.len() + bytes.len();
    if needed > buffer.capacity() {
        let capacity = needed.max(buffer.capacity().saturating_mul(2)).min(maximum);
        let mut next = Zeroizing::new(Vec::with_capacity(capacity));
        next.extend_from_slice(buffer);
        *buffer = next;
    }
    buffer.extend_from_slice(bytes);
}

/// Cloneable write side for concurrent RPC responses. All writes, including
/// reader-generated control replies, share one lock. The deadline starts before
/// that lock is acquired. Abort shuts down the raw socket without acquiring it,
/// interrupting an active write and releasing any waiting writers.
#[derive(Clone)]
pub struct WebSocketWriter {
    state: Arc<Mutex<WriteState>>,
    shutdown: Arc<TcpStream>,
    closed: Arc<AtomicBool>,
    close_sent: Arc<AtomicBool>,
    limits: Limits,
}
struct WriteState {
    stream: TcpStream,
    role: Role,
}
impl WriteState {
    fn frame(&mut self, opcode: u8, bytes: &[u8], end: Instant) -> Result<(), WsError> {
        let mask = if self.role == Role::Client {
            Some(random_bytes::<4>().map_err(|_| WsError::Crypto)?)
        } else {
            None
        };
        let mut header = Vec::with_capacity(14);
        header.push(0x80 | opcode);
        let mask_flag = if mask.is_some() { 0x80 } else { 0 };
        match bytes.len() {
            0..=125 => header.push(mask_flag | bytes.len() as u8),
            126..=65535 => {
                header.push(mask_flag | 126);
                header.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            }
            _ => {
                header.push(mask_flag | 127);
                header.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            }
        }
        if let Some(mask) = mask {
            header.extend_from_slice(&mask);
            write_all(&mut self.stream, &header, end)?;
            let mut masked = Zeroizing::new(bytes.to_vec());
            for (i, b) in masked.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
            write_all(&mut self.stream, &masked, end)
        } else {
            write_all(&mut self.stream, &header, end)?;
            write_all(&mut self.stream, bytes, end)
        }
    }
}
impl WebSocketWriter {
    fn lock_before(&self, end: Instant) -> Result<std::sync::MutexGuard<'_, WriteState>, WsError> {
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(WsError::Closed);
            }
            let left = remaining(end)?;
            match self.state.try_lock() {
                Ok(guard) => {
                    remaining(end)?;
                    if self.closed.load(Ordering::Acquire) {
                        return Err(WsError::Closed);
                    }
                    return Ok(guard);
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(WsError::Closed),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(left.min(Duration::from_millis(2)));
                }
            }
        }
    }
    pub fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }
    fn closing(&self) -> bool {
        self.close_sent.load(Ordering::Acquire)
    }
    fn control(&self, opcode: u8, bytes: &[u8], end: Instant) -> Result<(), WsError> {
        let mut state = self.lock_before(end)?;
        let result = (|| {
            if self.closed.load(Ordering::Acquire) {
                return Err(WsError::Closed);
            }
            remaining(end)?;
            state.frame(opcode, bytes, end)
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }
    fn reply_close(&self, bytes: &[u8], end: Instant) -> Result<(), WsError> {
        let mut state = self.lock_before(end)?;
        let result = (|| {
            if self.closed.load(Ordering::Acquire) {
                return Err(WsError::Closed);
            }
            if self.close_sent.load(Ordering::Acquire) {
                return Ok(());
            }
            remaining(end)?;
            state.frame(8, bytes, end)?;
            self.close_sent.store(true, Ordering::Release);
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }
    fn send(&self, opcode: u8, bytes: &[u8]) -> Result<(), WsError> {
        self.send_before(opcode, bytes, deadline(self.limits.operation_timeout)?)
    }
    fn send_before(&self, opcode: u8, bytes: &[u8], end: Instant) -> Result<(), WsError> {
        if bytes.len()
            > if opcode >= 8 {
                125
            } else {
                self.limits.max_message_bytes
            }
        {
            return Err(WsError::Limit);
        }
        // No frame has started while waiting for this lock. A local waiter
        // timeout must not abort a different caller's active write.
        let mut state = self.lock_before(end)?;
        let result = (|| {
            if self.close_sent.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
                return Err(WsError::Closed);
            }
            remaining(end)?;
            state.frame(opcode, bytes, end)?;
            if opcode == 8 {
                self.close_sent.store(true, Ordering::Release);
            }
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }
    pub fn send_text(&self, text: &str) -> Result<(), WsError> {
        self.send(1, text.as_bytes())
    }
    pub(crate) fn send_text_before(&self, text: &str, end: Instant) -> Result<(), WsError> {
        self.send_before(
            1,
            text.as_bytes(),
            end.min(deadline(self.limits.operation_timeout)?),
        )
    }
    pub fn send_binary(&self, bytes: &[u8]) -> Result<(), WsError> {
        self.send(2, bytes)
    }
    pub fn ping(&self, bytes: &[u8]) -> Result<(), WsError> {
        self.send(9, bytes)
    }
    pub fn send_close(&self, code: Option<u16>, reason: &str) -> Result<(), WsError> {
        if code.is_none() && !reason.is_empty() || code.is_some_and(|c| !valid_close(c)) {
            return Err(WsError::Protocol);
        }
        if reason.len() > 123 {
            return Err(WsError::Limit);
        }
        let mut body = Zeroizing::new(Vec::with_capacity(2 + reason.len()));
        if let Some(code) = code {
            body.extend_from_slice(&code.to_be_bytes());
            body.extend_from_slice(reason.as_bytes());
        }
        self.send(8, &body)
    }
}

#[cfg(test)]
mod writer_deadline_tests {
    use super::*;
    #[test]
    fn earlier_waiter_deadline_leaves_later_active_write_running() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let _unread_peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        // Test the post-upgrade writer boundary directly; handshake and role
        // validation have separate real socket integration tests.
        let owner = WebSocket::upgraded(socket, Role::Server, Limits::default()).unwrap();
        let first = owner.writer();
        let waiter = owner.writer();
        let writing = std::thread::spawn(move || first.send_binary(&vec![1; 16 * 1024 * 1024]));
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(Instant::now() < until);
            if matches!(
                waiter.state.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let begin = Instant::now();
        assert_eq!(
            waiter.send_text_before("short deadline", begin + Duration::from_millis(30)),
            Err(WsError::Timeout)
        );
        assert!(begin.elapsed() < Duration::from_millis(500));
        assert!(!writing.is_finished());
        assert!(!waiter.closed.load(Ordering::Acquire));
        waiter.abort();
        assert!(writing.join().unwrap().is_err());
    }
}
