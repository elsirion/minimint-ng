//! NET-001: directly trusted configured certificates, followed by exact peer ID.
//! Standard OpenSSL validation remains enabled; no verification callback exists.
use super::{TransportError, read_frame, write_frame};
use crate::{crypto::random_bytes, protocol::PeerId};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{
        Ssl, SslContext, SslContextBuilder, SslMethod, SslSessionCacheMode, SslStream,
        SslVerifyMode, SslVersion,
    },
    x509::{
        X509, X509NameBuilder, X509VerifyResult,
        extension::SubjectAlternativeName,
        store::X509StoreBuilder,
        verify::{X509CheckFlags, X509VerifyFlags},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Shutdown, TcpStream},
};

pub fn sanitize_name(name: &str) -> String {
    let mut result = String::from("peer");
    result.extend(
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }),
    );
    result
}
/// Contains private key material; intentionally no Debug or Copy. The OpenSSL
/// key object owns and frees its private scalar. DER exports are caller-owned.
pub struct Identity {
    certificate: X509,
    key: PKey<Private>,
}
impl Identity {
    pub fn generate(name: &str) -> Result<Self, TransportError> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec = EcKey::generate(&group)?;
        let key = PKey::from_ec_key(ec)?;
        let mut subject = X509NameBuilder::new()?;
        subject.append_entry_by_nid(Nid::COMMONNAME, "rcgen self signed cert")?;
        let subject = subject.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let mut serial = random_bytes::<16>().map_err(|_| TransportError::InvalidIdentity)?;
        serial[0] |= 1;
        let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
        cert.set_serial_number(&serial)?;
        cert.set_subject_name(&subject)?;
        cert.set_issuer_name(&subject)?;
        cert.set_pubkey(&key)?;
        let before = Asn1Time::from_str_x509("19750101000000Z")?;
        let after = Asn1Time::from_str_x509("40960101000000Z")?;
        cert.set_not_before(&before)?;
        cert.set_not_after(&after)?;
        let san = SubjectAlternativeName::new()
            .dns(&sanitize_name(name))
            .build(&cert.x509v3_context(None, None))?;
        cert.append_extension(san)?;
        cert.sign(&key, MessageDigest::sha256())?;
        Ok(Self {
            certificate: cert.build(),
            key,
        })
    }
    pub fn from_der(certificate: &[u8], pkcs8: &[u8]) -> Result<Self, TransportError> {
        let certificate_value = X509::from_der(certificate)?;
        let key = PKey::private_key_from_pkcs8(pkcs8)?;
        if certificate_value.to_der()? != certificate
            || !certificate_value.public_key()?.public_eq(&key)
        {
            return Err(TransportError::InvalidIdentity);
        }
        Ok(Self {
            certificate: certificate_value,
            key,
        })
    }
    pub fn certificate_der(&self) -> Result<Vec<u8>, TransportError> {
        Ok(self.certificate.to_der()?)
    }
    /// PKCS#8 DER for private durable configuration only; caller must protect and
    /// erase exported bytes. Never include this value in diagnostic formatting.
    pub fn private_key_der(&self) -> Result<Vec<u8>, TransportError> {
        Ok(self.key.private_key_to_pkcs8()?)
    }
}
#[derive(Clone, Debug)]
pub struct PeerCertificate {
    pub name: String,
    pub certificate_der: Vec<u8>,
}
#[derive(Clone)]
pub struct TlsConfig {
    context: SslContext,
    peers: BTreeMap<PeerId, PeerCertificate>,
}
impl TlsConfig {
    pub(crate) fn validate_manager(
        &self,
        local: PeerId,
        mut ids: impl Iterator<Item = PeerId>,
    ) -> bool {
        let Some(cert) = self.context.certificate() else {
            return false;
        };
        self.peers
            .get(&local)
            .is_some_and(|p| cert.to_der().ok().as_ref() == Some(&p.certificate_der))
            && ids.all(|id| id != local && self.peers.contains_key(&id))
    }

    /// Deadline-bounded handshake for the local threaded manager. The socket is
    /// nonblocking throughout; cancellation is checked between SSL retries.
    pub(crate) fn managed_handshake(
        &self,
        tcp: TcpStream,
        expected: Option<PeerId>,
        stop: &std::sync::atomic::AtomicBool,
    ) -> Result<AuthenticatedStream, TransportError> {
        use openssl::ssl::ErrorCode;
        use std::{
            sync::atomic::Ordering,
            time::{Duration, Instant},
        };
        tcp.set_nonblocking(true)?;
        let mut ssl = Ssl::new(&self.context)?;
        if let Some(id) = expected {
            let peer = self.peers.get(&id).ok_or(TransportError::UnknownPeer)?;
            let name = sanitize_name(&peer.name);
            ssl.set_hostname(&name)?;
            ssl.param_mut()
                .set_hostflags(X509CheckFlags::NEVER_CHECK_SUBJECT);
            ssl.param_mut().set_host(&name)?;
        }
        let mut stream = SslStream::new(ssl, tcp)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(TransportError::Closed);
            }
            match if expected.is_some() {
                stream.connect()
            } else {
                stream.accept()
            } {
                Ok(()) => break,
                Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return Err(TransportError::Tls),
            }
        }
        let peer = self.authenticated_peer(&stream)?;
        if expected.is_some_and(|id| id != peer) {
            return Err(TransportError::UnknownPeer);
        }
        Ok(AuthenticatedStream {
            stream,
            peer,
            closed: false,
        })
    }
    pub fn new(
        local: &Identity,
        peers: BTreeMap<PeerId, PeerCertificate>,
    ) -> Result<Self, TransportError> {
        if peers.is_empty() {
            return Err(TransportError::InvalidIdentity);
        }
        let mut certificates = BTreeSet::new();
        let mut store = X509StoreBuilder::new()?;
        // CHECK_SS_SIGNATURE retains the normally optional self-signature check of
        // directly trusted self-signed leafs. PARTIAL_CHAIN terminates at the exact
        // configured leaf, including when other anchors share its issuer/subject CN.
        // No system roots or shared CA are loaded.
        store.set_flags(X509VerifyFlags::CHECK_SS_SIGNATURE | X509VerifyFlags::PARTIAL_CHAIN)?;
        for peer in peers.values() {
            if !certificates.insert(peer.certificate_der.clone()) {
                return Err(TransportError::InvalidIdentity);
            }
            let certificate = X509::from_der(&peer.certificate_der)?;
            if certificate.to_der()? != peer.certificate_der {
                return Err(TransportError::InvalidIdentity);
            }
            store.add_cert(certificate)?;
        }
        let mut context = SslContextBuilder::new(SslMethod::tls())?;
        context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        context.set_ciphersuites("TLS_AES_256_GCM_SHA384")?;
        context.set_groups_list("X25519")?;
        context.set_certificate(&local.certificate)?;
        context.set_private_key(&local.key)?;
        context.check_private_key()?;
        context.set_cert_store(store.build());
        context.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        context.set_max_early_data(0)?;
        context.set_num_tickets(0)?;
        context.set_session_cache_mode(SslSessionCacheMode::OFF);
        Ok(Self {
            context: context.build(),
            peers,
        })
    }
    /// The caller sets connect/read/write timeouts on the blocking socket before
    /// invoking this method. The outgoing peer must match both SAN and exact DER.
    pub fn connect(
        &self,
        tcp: TcpStream,
        expected: PeerId,
    ) -> Result<AuthenticatedStream, TransportError> {
        let peer = self
            .peers
            .get(&expected)
            .ok_or(TransportError::UnknownPeer)?;
        let name = sanitize_name(&peer.name);
        let mut ssl = Ssl::new(&self.context)?;
        ssl.set_hostname(&name)?;
        ssl.param_mut()
            .set_hostflags(X509CheckFlags::NEVER_CHECK_SUBJECT);
        ssl.param_mut().set_host(&name)?;
        let stream = ssl.connect(tcp).map_err(|_| TransportError::Tls)?;
        let actual = self.authenticated_peer(&stream)?;
        if actual != expected {
            return Err(TransportError::UnknownPeer);
        }
        Ok(AuthenticatedStream {
            stream,
            peer: actual,
            closed: false,
        })
    }
    /// Mutual TLS validates the presented chain and then maps its first leaf by
    /// exact configured DER. Caller-supplied blocking socket timeouts also apply.
    pub fn accept(&self, tcp: TcpStream) -> Result<AuthenticatedStream, TransportError> {
        let stream = Ssl::new(&self.context)?
            .accept(tcp)
            .map_err(|_| TransportError::Tls)?;
        let peer = self.authenticated_peer(&stream)?;
        Ok(AuthenticatedStream {
            stream,
            peer,
            closed: false,
        })
    }
    fn authenticated_peer(&self, stream: &SslStream<TcpStream>) -> Result<PeerId, TransportError> {
        if stream.ssl().verify_result() != X509VerifyResult::OK {
            return Err(TransportError::Tls);
        }
        let der = stream
            .ssl()
            .peer_certificate()
            .ok_or(TransportError::UnknownPeer)?
            .to_der()?;
        self.peers
            .iter()
            .find_map(|(id, peer)| {
                if peer.certificate_der == der {
                    Some(*id)
                } else {
                    None
                }
            })
            .ok_or(TransportError::UnknownPeer)
    }
}
/// A connection reaches this type only after certificate and peer validation.
/// A frame error permanently closes it, avoiding stream resynchronization guesses.
pub struct AuthenticatedStream {
    stream: SslStream<TcpStream>,
    peer: PeerId,
    closed: bool,
}
impl AuthenticatedStream {
    pub(crate) fn into_stream(self) -> SslStream<TcpStream> {
        self.stream
    }
    pub fn peer_id(&self) -> PeerId {
        self.peer
    }
    pub fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let result = read_frame(&mut self.stream);
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn write_frame(&mut self, body: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        let result = write_frame(&mut self.stream, body);
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read the common-first envelope; malformed application data disconnects.
    pub fn read_envelope(&mut self) -> Result<super::envelope::Envelope, TransportError> {
        let bytes = zeroize::Zeroizing::new(self.read_frame()?);
        match super::envelope::Envelope::decode(&bytes) {
            Ok(message) => Ok(message),
            Err(_) => {
                self.close();
                Err(TransportError::InvalidEnvelope)
            }
        }
    }
    /// NET-003 senders use legacy envelopes. Temporary private-share wire bytes
    /// are erased after the synchronous write.
    pub fn write_envelope(
        &mut self,
        message: &super::envelope::Envelope,
    ) -> Result<(), TransportError> {
        let bytes = match message.encode_legacy() {
            Ok(bytes) => zeroize::Zeroizing::new(bytes),
            Err(_) => {
                self.close();
                return Err(TransportError::InvalidEnvelope);
            }
        };
        self.write_frame(&bytes)
    }
    fn close(&mut self) {
        self.closed = true;
        let _ = self.stream.get_ref().shutdown(Shutdown::Both);
    }
}
