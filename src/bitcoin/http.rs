//! Minimal bounded HTTP/1.1 client exchange for Bitcoin service adapters.
//! One request per connection (`Connection: close`); no pooling, redirects,
//! compression or proxy support. Every read/write is bounded by one deadline.
use super::BackendError;
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

pub const MAX_HEADER: usize = 16 * 1024;

/// A blocking byte stream whose socket timeouts can be bounded per operation.
pub trait TimedStream: Read + Write {
    fn set_timeouts(&self, timeout: Duration) -> std::io::Result<()>;
}
impl TimedStream for TcpStream {
    fn set_timeouts(&self, timeout: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(timeout))?;
        self.set_write_timeout(Some(timeout))
    }
}
impl TimedStream for openssl::ssl::SslStream<TcpStream> {
    fn set_timeouts(&self, timeout: Duration) -> std::io::Result<()> {
        self.get_ref().set_timeouts(timeout)
    }
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// `check` is consulted before every blocking operation (cancellation).
pub struct Exchange<'a> {
    pub deadline: Instant,
    pub max_body: usize,
    pub check: &'a dyn Fn() -> Result<(), BackendError>,
}
impl Exchange<'_> {
    fn remaining(&self) -> Result<Duration, BackendError> {
        (self.check)()?;
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(BackendError)
    }
    fn read(&self, stream: &mut impl TimedStream, out: &mut [u8]) -> Result<usize, BackendError> {
        stream
            .set_timeouts(self.remaining()?)
            .map_err(|_| BackendError)?;
        stream.read(out).map_err(|_| BackendError)
    }
    fn write_all(
        &self,
        stream: &mut impl TimedStream,
        mut bytes: &[u8],
    ) -> Result<(), BackendError> {
        while !bytes.is_empty() {
            stream
                .set_timeouts(self.remaining()?)
                .map_err(|_| BackendError)?;
            let count = stream.write(bytes).map_err(|_| BackendError)?;
            if count == 0 {
                return Err(BackendError);
            }
            bytes = &bytes[count..];
        }
        stream.flush().map_err(|_| BackendError)
    }
    fn byte(&self, stream: &mut impl TimedStream) -> Result<u8, BackendError> {
        let mut one = [0];
        if self.read(stream, &mut one)? != 1 {
            return Err(BackendError);
        }
        Ok(one[0])
    }
    /// A CRLF-terminated line (without CRLF), bounded by `limit` bytes.
    fn line(&self, stream: &mut impl TimedStream, limit: usize) -> Result<Vec<u8>, BackendError> {
        let mut line = Vec::new();
        while !line.ends_with(b"\r\n") {
            if line.len() >= limit {
                return Err(BackendError);
            }
            line.push(self.byte(stream)?);
        }
        line.truncate(line.len() - 2);
        Ok(line)
    }
    fn exact(&self, stream: &mut impl TimedStream, out: &mut [u8]) -> Result<(), BackendError> {
        let mut offset = 0;
        while offset < out.len() {
            let count = self.read(stream, &mut out[offset..])?;
            if count == 0 {
                return Err(BackendError);
            }
            offset += count;
        }
        Ok(())
    }
    /// Send `request` (complete head and body) and read one response.
    pub fn run(
        &self,
        stream: &mut impl TimedStream,
        request: &[u8],
    ) -> Result<Response, BackendError> {
        self.write_all(stream, request)?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= MAX_HEADER {
                return Err(BackendError);
            }
            head.push(self.byte(stream)?);
        }
        let head = std::str::from_utf8(&head).map_err(|_| BackendError)?;
        let mut lines = head.split("\r\n");
        let mut first = lines.next().ok_or(BackendError)?.splitn(3, ' ');
        if !matches!(first.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(BackendError);
        }
        let status = first
            .next()
            .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(BackendError)?
            .parse::<u16>()
            .map_err(|_| BackendError)?;
        let (mut length, mut chunked) = (None, false);
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, field) = line.split_once(':').ok_or(BackendError)?;
            let field = field.trim_matches([' ', '\t']);
            if name.eq_ignore_ascii_case("transfer-encoding") {
                // Only the plain chunked coding is supported; no repeats.
                if chunked || !field.eq_ignore_ascii_case("chunked") {
                    return Err(BackendError);
                }
                chunked = true;
            } else if name.eq_ignore_ascii_case("content-length") {
                if length.is_some()
                    || field.is_empty()
                    || !field.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(BackendError);
                }
                length = Some(field.parse::<usize>().map_err(|_| BackendError)?);
            }
        }
        let body = match (chunked, length) {
            // Ambiguous framing is rejected rather than resolved.
            (true, Some(_)) => return Err(BackendError),
            (true, None) => self.chunked(stream)?,
            (false, Some(length)) => {
                if length > self.max_body {
                    return Err(BackendError);
                }
                let mut body = vec![0; length];
                self.exact(stream, &mut body)?;
                body
            }
            // Connection: close delimits the body by end of stream.
            (false, None) => {
                let mut body = Vec::new();
                let mut buffer = [0; 8192];
                loop {
                    let count = self.read(stream, &mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    if count > self.max_body - body.len() {
                        return Err(BackendError);
                    }
                    body.extend_from_slice(&buffer[..count]);
                }
                body
            }
        };
        Ok(Response { status, body })
    }
    fn chunked(&self, stream: &mut impl TimedStream) -> Result<Vec<u8>, BackendError> {
        let mut body = Vec::new();
        loop {
            let line = self.line(stream, 1024)?;
            let line = std::str::from_utf8(&line).map_err(|_| BackendError)?;
            let size = line
                .split(';')
                .next()
                .unwrap_or("")
                .trim_matches([' ', '\t']);
            if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(BackendError);
            }
            let size = usize::from_str_radix(size, 16).map_err(|_| BackendError)?;
            if size == 0 {
                break;
            }
            if size > self.max_body - body.len() {
                return Err(BackendError);
            }
            let start = body.len();
            body.resize(start + size, 0);
            self.exact(stream, &mut body[start..])?;
            if !self.line(stream, 2)?.is_empty() {
                return Err(BackendError);
            }
        }
        // Discard bounded trailer fields up to the terminating empty line.
        let mut trailers = 0usize;
        loop {
            let line = self.line(stream, MAX_HEADER)?;
            if line.is_empty() {
                return Ok(body);
            }
            trailers += line.len();
            if trailers > MAX_HEADER {
                return Err(BackendError);
            }
        }
    }
}
