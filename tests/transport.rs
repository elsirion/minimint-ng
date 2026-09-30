use minimint_ng::{
    net::{
        self,
        tls::{Identity, PeerCertificate, TlsConfig},
    },
    protocol::PeerId,
};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};
fn peers(a: &Identity, b: &Identity) -> BTreeMap<PeerId, PeerCertificate> {
    BTreeMap::from([
        (
            PeerId(0),
            PeerCertificate {
                name: "Alice".into(),
                certificate_der: a.certificate_der().unwrap(),
            },
        ),
        (
            PeerId(1),
            PeerCertificate {
                name: "Bob".into(),
                certificate_der: b.certificate_der().unwrap(),
            },
        ),
    ])
}
fn timeout(stream: TcpStream) -> TcpStream {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
}
#[test]
fn real_mutual_tls_leaf_trust_and_frames() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let map = peers(&alice, &bob);
    let client = TlsConfig::new(&alice, map.clone()).unwrap();
    let server = TlsConfig::new(&bob, map).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut stream = server.accept(timeout(tcp)).unwrap();
        assert_eq!(stream.peer_id(), PeerId(0));
        assert_eq!(stream.read_frame().unwrap(), b"request");
        stream.write_frame(b"response").unwrap();
    });
    let mut stream = client
        .connect(timeout(TcpStream::connect(address).unwrap()), PeerId(1))
        .unwrap();
    assert_eq!(stream.peer_id(), PeerId(1));
    stream.write_frame(b"request").unwrap();
    assert_eq!(stream.read_frame().unwrap(), b"response");
    thread.join().unwrap();
}
#[test]
fn identity_import_and_duplicate_certificate_rejected() {
    assert_eq!(net::tls::sanitize_name("A li-ce.é💰"), "peerA_li_ce___");
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let imported = Identity::from_der(
        &alice.certificate_der().unwrap(),
        &alice.private_key_der().unwrap(),
    )
    .unwrap();
    assert_eq!(
        imported.certificate_der().unwrap(),
        alice.certificate_der().unwrap()
    );
    assert!(
        Identity::from_der(
            &alice.certificate_der().unwrap(),
            &bob.private_key_der().unwrap()
        )
        .is_err()
    );
    let mut map = peers(&alice, &bob);
    map.get_mut(&PeerId(1)).unwrap().certificate_der = alice.certificate_der().unwrap();
    assert!(TlsConfig::new(&alice, map).is_err());
}
struct Fragmented {
    bytes: io::Cursor<Vec<u8>>,
    chunk: usize,
}
impl Read for Fragmented {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = out.len().min(self.chunk);
        self.bytes.read(&mut out[..count])
    }
}
impl Write for Fragmented {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.bytes.write(&input[..input.len().min(self.chunk)])
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn frame_fragmentation_coalescing_and_bounds() {
    let mut writer = Fragmented {
        bytes: io::Cursor::new(Vec::new()),
        chunk: 2,
    };
    net::write_frame(&mut writer, b"abc").unwrap();
    net::write_frame(&mut writer, b"").unwrap();
    net::write_frame(&mut writer, b"xyz").unwrap();
    let mut wire = writer.bytes.into_inner();
    assert_eq!(&wire[..8], &3u64.to_be_bytes());
    let mut reader = Fragmented {
        bytes: io::Cursor::new(std::mem::take(&mut wire)),
        chunk: 1,
    };
    assert_eq!(net::read_frame(&mut reader).unwrap(), b"abc");
    assert_eq!(net::read_frame(&mut reader).unwrap(), b"");
    assert_eq!(net::read_frame(&mut reader).unwrap(), b"xyz");
    assert!(net::read_frame(&mut reader).is_err());
    assert!(net::read_frame(&mut io::Cursor::new(u64::MAX.to_be_bytes())).is_err());
    assert!(net::read_frame(&mut io::Cursor::new(8388609u64.to_be_bytes())).is_err());
    assert!(net::read_frame(&mut io::Cursor::new([0; 7])).is_err());
    let mut truncated = 2u64.to_be_bytes().to_vec();
    truncated.push(1);
    assert!(net::read_frame(&mut io::Cursor::new(truncated)).is_err());
    let mut sink = Vec::new();
    assert!(net::write_frame(&mut sink, &vec![0; net::MAX_FRAME_LEN + 1]).is_err());
    assert!(sink.is_empty());
    let maximum = vec![1; net::MAX_FRAME_LEN];
    net::write_frame(&mut sink, &maximum).unwrap();
    assert_eq!(
        net::read_frame(&mut io::Cursor::new(sink)).unwrap(),
        maximum
    );
}

fn connect_attempt(client: TlsConfig, server: TlsConfig, expected: PeerId) -> (bool, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        server.accept(timeout(tcp)).is_ok()
    });
    let client_ok = client
        .connect(timeout(TcpStream::connect(address).unwrap()), expected)
        .is_ok();
    (client_ok, thread.join().unwrap())
}
#[test]
fn outgoing_checks_both_name_and_requested_peer() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let mut map = peers(&alice, &bob);
    let server = TlsConfig::new(&bob, map.clone()).unwrap();
    map.get_mut(&PeerId(1)).unwrap().name = "Wrong Name".into();
    assert!(!connect_attempt(TlsConfig::new(&alice, map).unwrap(), server, PeerId(1)).0);
    // Both configured leafs have a matching Bob SAN. Exact requested-ID matching
    // must still reject a different configured guardian with the same name.
    let other = Identity::generate("Bob").unwrap();
    let mut map = peers(&alice, &bob);
    map.insert(
        PeerId(2),
        PeerCertificate {
            name: "Bob".into(),
            certificate_der: other.certificate_der().unwrap(),
        },
    );
    assert!(
        !connect_attempt(
            TlsConfig::new(&alice, map.clone()).unwrap(),
            TlsConfig::new(&other, map).unwrap(),
            PeerId(1)
        )
        .0
    );
}
#[test]
fn unconfigured_leaf_is_not_trusted() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let impostor = Identity::generate("Bob").unwrap();
    let map = peers(&alice, &bob);
    assert!(
        !connect_attempt(
            TlsConfig::new(&alice, map.clone()).unwrap(),
            TlsConfig::new(&impostor, map).unwrap(),
            PeerId(1)
        )
        .0
    );
}
fn altered_certificate(identity: &Identity, signer: &Identity, expired: bool) -> Identity {
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        x509::{X509, extension::SubjectAlternativeName},
    };
    let original = X509::from_der(&identity.certificate_der().unwrap()).unwrap();
    let key = PKey::private_key_from_pkcs8(&identity.private_key_der().unwrap()).unwrap();
    let signing_key = PKey::private_key_from_pkcs8(&signer.private_key_der().unwrap()).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(original.serial_number()).unwrap();
    builder.set_subject_name(original.subject_name()).unwrap();
    builder.set_issuer_name(original.issuer_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(original.not_before()).unwrap();
    let expiry = Asn1Time::from_str_x509(if expired {
        "20010101000000Z"
    } else {
        "40960101000000Z"
    })
    .unwrap();
    builder.set_not_after(&expiry).unwrap();
    let san = SubjectAlternativeName::new()
        .dns("peerBob")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();
    builder.sign(&signing_key, MessageDigest::sha256()).unwrap();
    Identity::from_der(
        &builder.build().to_der().unwrap(),
        &identity.private_key_der().unwrap(),
    )
    .unwrap()
}
#[test]
fn direct_anchor_still_checks_validity_and_self_signature() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let expired = altered_certificate(&bob, &bob, true);
    let map = peers(&alice, &expired);
    assert!(
        !connect_attempt(
            TlsConfig::new(&alice, map.clone()).unwrap(),
            TlsConfig::new(&expired, map).unwrap(),
            PeerId(1)
        )
        .0
    );
    let invalid_signature = altered_certificate(&bob, &alice, false);
    let map = peers(&alice, &invalid_signature);
    assert!(
        !connect_attempt(
            TlsConfig::new(&alice, map.clone()).unwrap(),
            TlsConfig::new(&invalid_signature, map).unwrap(),
            PeerId(1)
        )
        .0
    );
}
#[test]
fn incoming_requires_a_client_certificate() {
    use openssl::{
        ssl::{Ssl, SslContextBuilder, SslMethod, SslVerifyMode},
        x509::{X509, store::X509StoreBuilder},
    };
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let server = TlsConfig::new(&bob, peers(&alice, &bob)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        assert!(server.accept(timeout(tcp)).is_err());
    });
    let mut store = X509StoreBuilder::new().unwrap();
    store
        .add_cert(X509::from_der(&bob.certificate_der().unwrap()).unwrap())
        .unwrap();
    let mut context = SslContextBuilder::new(SslMethod::tls()).unwrap();
    context.set_cert_store(store.build());
    context.set_verify(SslVerifyMode::PEER);
    let mut ssl = Ssl::new(&context.build()).unwrap();
    ssl.param_mut().set_host("peerBob").unwrap();
    if let Ok(mut stream) = ssl.connect(timeout(TcpStream::connect(address).unwrap())) {
        let _ = stream.read(&mut [0; 1]);
    }
    thread.join().unwrap();
}
#[test]
fn incoming_rejects_unconfigured_client_leaf() {
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let unconfigured = Identity::generate("Alice").unwrap();
    let map = peers(&alice, &bob);
    assert!(
        !connect_attempt(
            TlsConfig::new(&unconfigured, map.clone()).unwrap(),
            TlsConfig::new(&bob, map).unwrap(),
            PeerId(1)
        )
        .1
    );
}
#[test]
fn envelope_errors_disconnect_authenticated_stream() {
    use minimint_ng::net::{TransportError, envelope::Envelope};
    let alice = Identity::generate("Alice").unwrap();
    let bob = Identity::generate("Bob").unwrap();
    let map = peers(&alice, &bob);
    let client = TlsConfig::new(&alice, map.clone()).unwrap();
    let server = TlsConfig::new(&bob, map).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut stream = server.accept(timeout(tcp)).unwrap();
        assert!(matches!(
            stream.read_envelope().unwrap(),
            Envelope::SessionIndex(7)
        ));
        stream.write_frame(&[255]).unwrap();
    });
    let mut stream = client
        .connect(timeout(TcpStream::connect(address).unwrap()), PeerId(1))
        .unwrap();
    stream.write_envelope(&Envelope::SessionIndex(7)).unwrap();
    assert!(matches!(
        stream.read_envelope(),
        Err(TransportError::InvalidEnvelope)
    ));
    assert!(matches!(
        stream.write_frame(b"later"),
        Err(TransportError::Closed)
    ));
    assert!(matches!(stream.read_frame(), Err(TransportError::Closed)));
    thread.join().unwrap();
}
#[test]
fn generated_certificate_uses_exact_sanitized_san_and_p256() {
    use openssl::{nid::Nid, x509::X509};
    let identity = Identity::generate("A li-ce.é💰").unwrap();
    let cert = X509::from_der(&identity.certificate_der().unwrap()).unwrap();
    let names = cert.subject_alt_names().unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].dnsname(), Some("peerA_li_ce___"));
    assert_eq!(
        cert.public_key()
            .unwrap()
            .ec_key()
            .unwrap()
            .group()
            .curve_name(),
        Some(Nid::X9_62_PRIME256V1)
    );
    assert_eq!(
        cert.signature_algorithm().object().nid(),
        Nid::ECDSA_WITH_SHA256
    );
}
