//! Narrow Bitcoin Core HTTP/1.1 backend for a local regtest node.
//! A new connection per call avoids pooling and ambiguous response framing.
use super::{BackendError, BitcoinBackend, Block, Transaction, Txid};
use crate::{codec::text, json};
use sonic_rs::{JsonValueTrait, Value, json as value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_BODY: usize = 16 * 1024 * 1024;
const MAX_HEADER: usize = 16 * 1024;

/// Credentials are never Debug-formatted. Plain HTTP is limited to loopback;
/// remote Bitcoin service transport requires a separately reviewed TLS adapter.
pub struct CoreRpc {
    address: SocketAddr,
    authorization: Zeroizing<String>,
    timeout: Duration,
    fee_target: u16,
    stop: Arc<AtomicBool>,
}
impl CoreRpc {
    pub fn new(
        address: SocketAddr,
        credentials: &str,
        timeout: Duration,
        fee_target: u16,
    ) -> Result<Self, BackendError> {
        if !address.ip().is_loopback()
            || timeout.is_zero()
            || !(1..=1008).contains(&fee_target)
            || !credentials.contains(':')
            || credentials.bytes().any(|b| b.is_ascii_control())
        {
            return Err(BackendError);
        }
        // RFC4648 standard padded Base64 from the existing URL-safe primitive.
        let url_encoded = Zeroizing::new(text::base64url_encode(credentials.as_bytes()));
        let mut encoded = Zeroizing::new(
            url_encoded
                .chars()
                .map(|c| match c {
                    '-' => '+',
                    '_' => '/',
                    c => c,
                })
                .collect::<String>(),
        );
        while encoded.len() % 4 != 0 {
            encoded.push('=');
        }
        Ok(Self {
            address,
            authorization: encoded,
            timeout,
            fee_target,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn request_shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
    fn remaining(&self, deadline: Instant) -> Result<Duration, BackendError> {
        if self.stop.load(Ordering::Acquire) {
            return Err(BackendError);
        }
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(BackendError)
    }
    fn read(
        &self,
        stream: &mut TcpStream,
        deadline: Instant,
        bytes: &mut [u8],
    ) -> Result<usize, BackendError> {
        stream
            .set_read_timeout(Some(self.remaining(deadline)?))
            .map_err(|_| BackendError)?;
        stream.read(bytes).map_err(|_| BackendError)
    }
    fn call(&self, method: &str, params: Value) -> Result<Value, BackendError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(BackendError)?;
        let body = json::encode(&value!({"jsonrpc":"1.0","id":1,"method":method,"params":params}))
            .map_err(|_| BackendError)?;
        if body.len() > MAX_BODY {
            return Err(BackendError);
        }
        let mut stream = TcpStream::connect_timeout(&self.address, self.remaining(deadline)?)
            .map_err(|_| BackendError)?;
        let header = Zeroizing::new(format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            self.address,
            *self.authorization,
            body.len()
        ));
        for bytes in [header.as_bytes(), body.as_slice()] {
            let mut remaining = bytes;
            while !remaining.is_empty() {
                stream
                    .set_write_timeout(Some(self.remaining(deadline)?))
                    .map_err(|_| BackendError)?;
                let count = stream.write(remaining).map_err(|_| BackendError)?;
                if count == 0 {
                    return Err(BackendError);
                }
                remaining = &remaining[count..];
            }
        }
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= MAX_HEADER {
                return Err(BackendError);
            }
            let mut byte = [0];
            if self.read(&mut stream, deadline, &mut byte)? != 1 {
                return Err(BackendError);
            }
            header.push(byte[0]);
        }
        let header = std::str::from_utf8(&header).map_err(|_| BackendError)?;
        let mut lines = header.split("\r\n");
        let mut status = lines.next().ok_or(BackendError)?.split_whitespace();
        if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) || status.next() != Some("200") {
            return Err(BackendError);
        }
        let mut length = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, field) = line.split_once(':').ok_or(BackendError)?;
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(BackendError);
            }
            if name.eq_ignore_ascii_case("content-length") {
                let field = field.trim();
                if length.is_some()
                    || field.is_empty()
                    || !field.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(BackendError);
                }
                length = Some(field.parse::<usize>().map_err(|_| BackendError)?);
            }
        }
        let length = length.filter(|n| *n <= MAX_BODY).ok_or(BackendError)?;
        let mut body = vec![0; length];
        let mut offset = 0;
        while offset < length {
            let count = self.read(&mut stream, deadline, &mut body[offset..])?;
            if count == 0 {
                return Err(BackendError);
            }
            offset += count;
        }
        let response = json::parse(&body, MAX_BODY, 64).map_err(|_| BackendError)?;
        if response.get("id").and_then(|v| json::unsigned(v).ok()) != Some(1)
            || !response.get("error").is_some_and(|e| e.is_null())
        {
            return Err(BackendError);
        }
        response.get("result").cloned().ok_or(BackendError)
    }
}
fn hash(value: &Value) -> Result<[u8; 32], BackendError> {
    let mut bytes: [u8; 32] = text::hex_decode(value.as_str().ok_or(BackendError)?)
        .map_err(|_| BackendError)?
        .try_into()
        .map_err(|_| BackendError)?;
    bytes.reverse();
    Ok(bytes)
}
impl BitcoinBackend for CoreRpc {
    fn block_count(&self) -> Result<u64, BackendError> {
        json::unsigned(&self.call("getblockcount", value!([]))?)
            .map_err(|_| BackendError)?
            .checked_add(1)
            .ok_or(BackendError)
    }
    fn wait_for_count(&self, count: u64) -> Result<(), BackendError> {
        loop {
            if self.stop.load(Ordering::Acquire) {
                return Err(BackendError);
            }
            if self.block_count().is_ok_and(|n| n >= count) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    fn block_hash(&self, height: u64) -> Result<[u8; 32], BackendError> {
        hash(&self.call("getblockhash", value!([height]))?)
    }
    fn block(&self, expected: [u8; 32]) -> Result<Block, BackendError> {
        let result = self.call("getblock", value!([Txid(expected).display_hex(), 0]))?;
        let bytes =
            text::hex_decode(result.as_str().ok_or(BackendError)?).map_err(|_| BackendError)?;
        let block = Block::decode(&bytes).map_err(|_| BackendError)?;
        if block.hash() != expected {
            return Err(BackendError);
        }
        Ok(block)
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        let result = self.call(
            "estimatesmartfee",
            value!([self.fee_target, "CONSERVATIVE"]),
        )?;
        if !result.is_object() {
            return Err(BackendError);
        }
        match result.get("feerate") {
            Some(fee) => json::scaled_unsigned(fee, 8)
                .map(Some)
                .map_err(|_| BackendError),
            None => Ok(None),
        }
    }
    fn broadcast(&self, transaction: &Transaction) -> Result<(), BackendError> {
        let result = self.call(
            "sendrawtransaction",
            // The replicated Wallet has already authorized the fee. Disable
            // Core's additional local maxfeerate veto; standard destinations
            // remain subject to normal transaction/mempool validation.
            value!([text::hex_encode(&transaction.encode()), 0]),
        )?;
        if hash(&result)? != transaction.txid().0 {
            return Err(BackendError);
        }
        Ok(())
    }
}
