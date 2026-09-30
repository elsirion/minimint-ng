use minimint_ng::bitcoin::{
    BackendError, BitcoinBackend, Block, OutPoint, Transaction, TxIn, TxOut, Txid, double_sha256,
    esplora::{Esplora, EsploraOptions, EsploraUrl},
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    method: String,
    path: String,
    host: String,
    body: Vec<u8>,
}

fn read_request(socket: &mut impl Read) -> Request {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0];
        socket.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap().split(' ');
    let (method, path) = (first.next().unwrap(), first.next().unwrap());
    assert_eq!(first.next(), Some("HTTP/1.1"));
    let mut host = String::new();
    let mut length = 0;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(": ").unwrap();
        match name {
            "Host" => host = value.to_owned(),
            "Content-Length" => length = value.parse().unwrap(),
            "Connection" => assert_eq!(value, "close"),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    Request {
        method: method.to_owned(),
        path: path.to_owned(),
        host,
        body,
    }
}

/// Serves one canned raw response per connection, fragmented across writes.
fn server(replies: Vec<Vec<u8>>) -> (SocketAddr, thread::JoinHandle<Vec<Request>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            requests.push(read_request(&mut socket));
            for part in reply.chunks(7) {
                if socket.write_all(part).is_err() {
                    break;
                }
            }
        }
        requests
    });
    (address, worker)
}
fn ok(body: &[u8]) -> Vec<u8> {
    [
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
        body,
    ]
    .concat()
}
fn status(code: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {code} Nope\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn no_dns() -> minimint_ng::bitcoin::esplora::Resolver {
    Box::new(|_, _| panic!("IP literal URLs must not use the resolver"))
}
fn esplora(url: &str) -> Esplora {
    Esplora::new(
        EsploraUrl::parse(url).unwrap(),
        EsploraOptions {
            timeout: Duration::from_secs(3),
            fee_target: 6,
            extra_roots: vec![],
        },
        no_dns(),
    )
    .unwrap()
}
fn transaction() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid([7; 32]),
                vout: 1,
            },
            script_sig: vec![],
            sequence: 0xffff_fffd,
            witness: vec![vec![1, 2, 3]],
        }],
        outputs: vec![TxOut {
            value_sat: 50_000,
            script_pubkey: [vec![0x00, 0x20], vec![9; 32]].concat(),
        }],
        lock_time: 0,
    }
}
fn block_bytes() -> (Vec<u8>, [u8; 32]) {
    let header = [0x42u8; 80];
    let bytes = [header.to_vec(), vec![1], transaction().encode()].concat();
    (bytes, double_sha256(&header))
}

#[test]
fn chain_queries_use_esplora_paths_and_internal_byte_order() {
    let (block, hash) = block_bytes();
    let display = Txid(hash).display_hex();
    let (address, worker) = server(vec![
        ok(b"3467803\n"),
        ok(display.as_bytes()),
        ok(&block),
        ok(br#"{"1":2.5,"6":1.0699999999999998,"144":1.014}"#),
        ok(br#"{"1":2.5}"#),
        ok(br#"[1.0]"#),
        status(404, "Block not found"),
        ok(b"12a"),
    ]);
    let backend = esplora(&format!("http://{address}/api/"));
    assert_eq!(backend.block_count(), Ok(3_467_804));
    assert_eq!(backend.block_hash(3_467_803), Ok(hash));
    assert_eq!(backend.block(hash).unwrap(), Block::decode(&block).unwrap());
    assert_eq!(backend.fee_rate(), Ok(Some(1070)));
    assert_eq!(backend.fee_rate(), Ok(None));
    assert_eq!(backend.fee_rate(), Err(BackendError));
    assert_eq!(backend.block_hash(99_999_999), Err(BackendError));
    assert_eq!(backend.block_count(), Err(BackendError));
    let requests = worker.join().unwrap();
    let paths: Vec<_> = requests
        .iter()
        .map(|r| (r.method.as_str(), r.path.as_str()))
        .collect();
    assert_eq!(
        paths,
        [
            ("GET", "/api/blocks/tip/height"),
            ("GET", "/api/block-height/3467803"),
            ("GET", format!("/api/block/{display}/raw").as_str()),
            ("GET", "/api/fee-estimates"),
            ("GET", "/api/fee-estimates"),
            ("GET", "/api/fee-estimates"),
            ("GET", "/api/block-height/99999999"),
            ("GET", "/api/blocks/tip/height"),
        ]
    );
    assert!(requests.iter().all(|r| r.host == address.to_string()));
}

#[test]
fn response_framing_supports_chunked_and_close_delimited_bodies() {
    let (block, hash) = block_bytes();
    let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for part in block.chunks(50) {
        chunked.extend(format!("{:x};ext=1\r\n", part.len()).bytes());
        chunked.extend(part);
        chunked.extend(b"\r\n");
    }
    chunked.extend(b"0\r\nX-Trailer: yes\r\n\r\n");
    let mut wrong = block.clone();
    wrong[0] ^= 1;
    let (address, worker) = server(vec![
        chunked,
        b"HTTP/1.0 200 OK\r\n\r\n100".to_vec(),
        ok(&wrong),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n1\r\n0\r\n\r\n"
            .to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12".to_vec(),
    ]);
    let backend = esplora(&format!("http://{address}"));
    assert_eq!(backend.block(hash).unwrap(), Block::decode(&block).unwrap());
    assert_eq!(backend.block_count(), Ok(101));
    // A block whose bytes hash differently from the request is rejected.
    assert_eq!(backend.block(hash), Err(BackendError));
    assert_eq!(backend.block_count(), Err(BackendError));
    assert_eq!(backend.block_count(), Err(BackendError));
    assert_eq!(backend.block_count(), Err(BackendError));
    let requests = worker.join().unwrap();
    assert_eq!(requests[1].path, "/blocks/tip/height");
}

#[test]
fn broadcast_posts_hex_and_checks_returned_txid() {
    let tx = transaction();
    let txid = tx.txid().display_hex();
    let (address, worker) = server(vec![
        ok(txid.as_bytes()),
        ok(Txid([1; 32]).display_hex().as_bytes()),
        status(
            400,
            "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"min relay fee not met\"}",
        ),
    ]);
    let backend = esplora(&format!("http://{address}/api"));
    assert_eq!(backend.broadcast(&tx), Ok(()));
    assert_eq!(backend.broadcast(&tx), Err(BackendError));
    assert_eq!(backend.broadcast(&tx), Err(BackendError));
    let requests = worker.join().unwrap();
    for request in &requests {
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/tx");
        assert_eq!(
            request.body,
            minimint_ng::codec::text::hex_encode(&tx.encode()).into_bytes()
        );
    }
}

#[test]
fn shutdown_fails_calls_without_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = esplora(&format!("http://{}/api", listener.local_addr().unwrap()));
    backend.request_shutdown();
    listener.set_nonblocking(true).unwrap();
    assert_eq!(backend.block_count(), Err(BackendError));
    assert_eq!(backend.wait_for_count(1), Err(BackendError));
    assert!(listener.accept().is_err());
}

#[test]
fn url_policy_limits_plain_http_to_loopback() {
    for url in [
        "https://mutinynet.com/api",
        "https://mutinynet.com/api/",
        "https://mutinynet.com",
        "https://blockstream.info:8443/signet/api",
        "http://127.0.0.1:3002",
    ] {
        assert!(EsploraUrl::parse(url).is_ok(), "{url}");
    }
    assert_eq!(
        EsploraUrl::parse("https://Mutinynet.com/api/")
            .unwrap()
            .to_string(),
        "https://mutinynet.com/api"
    );
    for url in [
        "http://mutinynet.com/api",
        "http://localhost:3002",
        "http://10.0.0.1:3002",
        "https://mutinynet.com:0/api",
        "https://mutinynet.com:/api",
        "https://user:pw@mutinynet.com/api",
        "https://mutinynet.com/api?x",
        "https://mutinynet.com/api#x",
        "https://mutinynet.com/a%20b",
        "https://mutinynet.com//api",
        "https://[::1]/api",
        "https://-bad.com/",
        "https:///api",
        "mutinynet.com/api",
    ] {
        assert!(EsploraUrl::parse(url).is_err(), "{url}");
    }
}

fn self_signed() -> (
    openssl::x509::X509,
    openssl::pkey::PKey<openssl::pkey::Private>,
) {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{X509Builder, X509NameBuilder, extension::SubjectAlternativeName},
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost")
        .unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (builder.build(), key)
}

#[test]
fn https_verifies_trust_anchor_and_host_name_and_uses_resolver() {
    use openssl::ssl::{SslAcceptor, SslMethod};
    let (certificate, key) = self_signed();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    let acceptor = Arc::new(acceptor.build());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_acceptor = acceptor.clone();
    let worker = thread::spawn(move || {
        let mut hosts = Vec::new();
        for _ in 0..4 {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            // The untrusted client aborts during the handshake.
            let Ok(mut tls) = server_acceptor.accept(socket) else {
                continue;
            };
            let request = read_request(&mut tls);
            hosts.push(request.host);
            tls.write_all(&ok(b"99")).unwrap();
            let _ = tls.shutdown();
        }
        hosts
    });
    let resolved = Arc::new(Mutex::new(Vec::new()));
    let make = |roots: Vec<openssl::x509::X509>, host: &str| {
        let resolved = resolved.clone();
        Esplora::new(
            EsploraUrl::parse(&format!("https://{host}:{}/api", address.port())).unwrap(),
            EsploraOptions {
                timeout: Duration::from_secs(3),
                fee_target: 6,
                extra_roots: roots,
            },
            Box::new(move |authority, _| {
                resolved.lock().unwrap().push(authority.to_owned());
                Ok(vec![address])
            }),
        )
        .unwrap()
    };
    let trusted = make(vec![certificate.clone()], "localhost");
    assert_eq!(trusted.block_count(), Ok(100));
    // Resolution is cached between requests.
    assert_eq!(trusted.block_count(), Ok(100));
    assert_eq!(make(vec![], "localhost").block_count(), Err(BackendError));
    // Wrong name for the presented certificate; IP literals skip the resolver.
    assert_eq!(
        make(vec![certificate], "127.0.0.1").block_count(),
        Err(BackendError)
    );
    assert_eq!(
        worker.join().unwrap(),
        vec![format!("localhost:{}", address.port()); 2]
    );
    assert_eq!(
        *resolved.lock().unwrap(),
        [
            format!("localhost:{}", address.port()),
            format!("localhost:{}", address.port())
        ]
    );
}

/// Live read-only check against a public signet Esplora (default: Mutinynet).
/// `cargo test --test bitcoin_esplora -- --ignored`; override with MINIMINT_ESPLORA_URL.
#[test]
#[ignore]
fn live_signet_esplora_chain_reads() {
    use std::net::ToSocketAddrs;
    let url = std::env::var("MINIMINT_ESPLORA_URL")
        .unwrap_or_else(|_| "https://mutinynet.com/api".into());
    let backend = Esplora::new(
        EsploraUrl::parse(&url).unwrap(),
        EsploraOptions {
            timeout: Duration::from_secs(20),
            fee_target: 6,
            extra_roots: vec![],
        },
        Box::new(|authority, _| {
            authority
                .to_socket_addrs()
                .map(|a| a.filter(SocketAddr::is_ipv4).collect())
                .map_err(|_| BackendError)
        }),
    )
    .unwrap();
    let count = backend.block_count().unwrap();
    // Every signet shares the default signet genesis block.
    let genesis = backend.block_hash(0).unwrap();
    assert_eq!(
        Txid(genesis).display_hex(),
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
    );
    let height = count - 7;
    let hash = backend.block_hash(height).unwrap();
    let block = backend.block(hash).unwrap();
    assert!(!block.transactions.is_empty());
    let fee = backend.fee_rate().unwrap();
    println!(
        "count {count}, block {height} {}, fee {fee:?}",
        Txid(hash).display_hex()
    );
}
