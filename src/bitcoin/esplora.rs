//! Esplora HTTP(S) Bitcoin backend, an alternative to the local Core RPC adapter.
//! The service is trusted for chain data exactly as a local node would be: block
//! bytes are still decoded locally and checked against the requested hash.
//! TLS uses the already reviewed OpenSSL binding with the system trust store and
//! hostname verification; plain HTTP is limited to loopback IP literals.
use super::{
    BackendError, BitcoinBackend, Block, Transaction, Txid,
    http::{Exchange, Response, TimedStream},
};
use crate::{codec::text, json};
use openssl::{
    ssl::{SslConnector, SslMethod, SslVersion},
    x509::X509,
};
use sonic_rs::JsonValueTrait;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_SMALL_BODY: usize = 64 * 1024;
const MAX_BLOCK_BODY: usize = 8 * 1024 * 1024;
const ADDRESS_TTL: Duration = Duration::from_secs(300);
const WAIT_POLL: Duration = Duration::from_secs(1);
/// Suggested interval between Wallet backend polls against a shared service.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Resolves `host:port` to addresses. Implementations must honour the
/// cancellation flag and bound their own duration.
pub type Resolver =
    Box<dyn Fn(&str, &AtomicBool) -> Result<Vec<SocketAddr>, BackendError> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsploraUrl {
    tls: bool,
    host: String,
    port: u16,
    prefix: String,
}
impl EsploraUrl {
    /// `https://HOST[:PORT][/PATH]`, or `http://` with a loopback IPv4 literal.
    /// No credentials, query, fragment, IPv6 literal or percent-encoding.
    pub fn parse(text: &str) -> Result<Self, BackendError> {
        let (tls, rest) = if let Some(rest) = text.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = text.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(BackendError);
        };
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(BackendError);
                }
                (host, port.parse::<u16>().map_err(|_| BackendError)?)
            }
            None => (authority, if tls { 443 } else { 80 }),
        };
        let host = host.to_ascii_lowercase();
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        let path = path.trim_end_matches('/');
        let valid_path = path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_' | b'~'))
            && !path.contains("//");
        if !valid_host || port == 0 || !valid_path {
            return Err(BackendError);
        }
        if !tls && !host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback()) {
            return Err(BackendError);
        }
        Ok(Self {
            tls,
            host,
            port,
            prefix: path.to_owned(),
        })
    }
    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
    fn host_header(&self) -> String {
        if self.port == if self.tls { 443 } else { 80 } {
            self.host.clone()
        } else {
            self.authority()
        }
    }
}
impl std::fmt::Display for EsploraUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.host_header(), self.prefix)
    }
}

pub struct EsploraOptions {
    /// Total bound for one request, including connect and TLS handshake.
    pub timeout: Duration,
    /// Confirmation target key read from `/fee-estimates`.
    pub fee_target: u16,
    /// Additional trust anchors beyond the system store (private services, tests).
    pub extra_roots: Vec<X509>,
}

pub struct Esplora {
    url: EsploraUrl,
    tls: Option<SslConnector>,
    timeout: Duration,
    fee_target: u16,
    resolver: Resolver,
    addresses: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
    stop: Arc<AtomicBool>,
}
impl Esplora {
    pub fn new(
        url: EsploraUrl,
        options: EsploraOptions,
        resolver: Resolver,
    ) -> Result<Self, BackendError> {
        if options.timeout.is_zero() || !(1..=1008).contains(&options.fee_target) {
            return Err(BackendError);
        }
        let tls = if url.tls {
            let mut builder =
                SslConnector::builder(SslMethod::tls_client()).map_err(|_| BackendError)?;
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|_| BackendError)?;
            for root in options.extra_roots {
                builder
                    .cert_store_mut()
                    .add_cert(root)
                    .map_err(|_| BackendError)?;
            }
            Some(builder.build())
        } else {
            None
        };
        Ok(Self {
            url,
            tls,
            timeout: options.timeout,
            fee_target: options.fee_target,
            resolver,
            addresses: Mutex::new(None),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn url(&self) -> &EsploraUrl {
        &self.url
    }
    pub fn request_shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
    fn check(&self) -> Result<(), BackendError> {
        if self.stop.load(Ordering::Acquire) {
            Err(BackendError)
        } else {
            Ok(())
        }
    }
    fn addresses(&self) -> Result<Vec<SocketAddr>, BackendError> {
        if let Ok(ip) = self.url.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, self.url.port)]);
        }
        let mut cache = self.addresses.lock().map_err(|_| BackendError)?;
        if let Some((resolved, addresses)) = cache.as_ref()
            && resolved.elapsed() < ADDRESS_TTL
        {
            return Ok(addresses.clone());
        }
        let addresses = (self.resolver)(&self.url.authority(), &self.stop)?;
        if addresses.is_empty() || addresses.iter().any(|a| a.port() != self.url.port) {
            return Err(BackendError);
        }
        *cache = Some((Instant::now(), addresses.clone()));
        Ok(addresses)
    }
    fn forget_addresses(&self) {
        if let Ok(mut cache) = self.addresses.lock() {
            *cache = None;
        }
    }
    fn connect(&self, deadline: Instant) -> Result<TcpStream, BackendError> {
        for address in self.addresses()? {
            self.check()?;
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(BackendError)?;
            if let Ok(stream) = TcpStream::connect_timeout(&address, remaining) {
                return Ok(stream);
            }
        }
        // Resolve again next time: the service may have moved.
        self.forget_addresses();
        Err(BackendError)
    }
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Vec<u8>, BackendError> {
        self.check()?;
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(BackendError)?;
        let mut request = format!(
            "{method} {}{path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: minimint-ng/{}\r\nAccept: */*\r\nConnection: close\r\n",
            self.url.prefix,
            self.url.host_header(),
            env!("CARGO_PKG_VERSION"),
        )
        .into_bytes();
        if let Some(body) = body {
            request.extend(
                format!(
                    "Content-Type: text/plain\r\nContent-Length: {}\r\n",
                    body.len()
                )
                .bytes(),
            );
        }
        request.extend(b"\r\n");
        request.extend(body.unwrap_or_default());
        let check = || self.check();
        let exchange = Exchange {
            deadline,
            max_body,
            check: &check,
        };
        let stream = self.connect(deadline)?;
        let Response { status, body } = match &self.tls {
            Some(connector) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|d| !d.is_zero())
                    .ok_or(BackendError)?;
                stream.set_timeouts(remaining).map_err(|_| BackendError)?;
                let mut tls = connector
                    .configure()
                    .map_err(|_| BackendError)?
                    .connect(&self.url.host, stream)
                    .map_err(|_| BackendError)?;
                let response = exchange.run(&mut tls, &request);
                let _ = tls.shutdown();
                response?
            }
            None => {
                let mut stream = stream;
                exchange.run(&mut stream, &request)?
            }
        };
        if status != 200 {
            return Err(BackendError);
        }
        Ok(body)
    }
    fn text(&self, path: &str) -> Result<String, BackendError> {
        let body = self.request("GET", path, None, MAX_SMALL_BODY)?;
        let text = String::from_utf8(body).map_err(|_| BackendError)?;
        Ok(text.trim_end_matches(['\r', '\n']).to_owned())
    }
}
fn hash(text: &str) -> Result<[u8; 32], BackendError> {
    if text.len() != 64 {
        return Err(BackendError);
    }
    let mut bytes: [u8; 32] = text::hex_decode(text)
        .map_err(|_| BackendError)?
        .try_into()
        .map_err(|_| BackendError)?;
    bytes.reverse();
    Ok(bytes)
}
impl BitcoinBackend for Esplora {
    fn block_count(&self) -> Result<u64, BackendError> {
        let height = self.text("/blocks/tip/height")?;
        if height.is_empty() || height.len() > 20 || !height.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BackendError);
        }
        height
            .parse::<u64>()
            .map_err(|_| BackendError)?
            .checked_add(1)
            .ok_or(BackendError)
    }
    fn wait_for_count(&self, count: u64) -> Result<(), BackendError> {
        loop {
            self.check()?;
            if self.block_count().is_ok_and(|n| n >= count) {
                return Ok(());
            }
            let until = Instant::now() + WAIT_POLL;
            while Instant::now() < until {
                self.check()?;
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    fn block_hash(&self, height: u64) -> Result<[u8; 32], BackendError> {
        hash(&self.text(&format!("/block-height/{height}"))?)
    }
    fn block(&self, expected: [u8; 32]) -> Result<Block, BackendError> {
        let path = format!("/block/{}/raw", Txid(expected).display_hex());
        let bytes = self.request("GET", &path, None, MAX_BLOCK_BODY)?;
        let block = Block::decode(&bytes).map_err(|_| BackendError)?;
        if block.hash() != expected {
            return Err(BackendError);
        }
        Ok(block)
    }
    /// sat/vB estimate for the configured target, rounded half-up to sat/kvB.
    /// A reachable service without that target reports an absent estimate.
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        let body = self.request("GET", "/fee-estimates", None, MAX_SMALL_BODY)?;
        let estimates = json::parse(&body, MAX_SMALL_BODY, 2).map_err(|_| BackendError)?;
        if !estimates.is_object() {
            return Err(BackendError);
        }
        match estimates.get(&self.fee_target.to_string()) {
            Some(rate) => json::rounded_scaled_unsigned(rate, 3)
                .map(Some)
                .map_err(|_| BackendError),
            None => Ok(None),
        }
    }
    fn broadcast(&self, transaction: &Transaction) -> Result<(), BackendError> {
        let hex = text::hex_encode(&transaction.encode());
        let body = self.request("POST", "/tx", Some(hex.as_bytes()), MAX_SMALL_BODY)?;
        let txid = String::from_utf8(body).map_err(|_| BackendError)?;
        if hash(txid.trim_end_matches(['\r', '\n']))? != transaction.txid().0 {
            return Err(BackendError);
        }
        Ok(())
    }
}
