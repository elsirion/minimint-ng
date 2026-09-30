use minimint_ng::{
    net::{
        MAX_FRAME_LEN, PeerNetwork, TransportError,
        envelope::Envelope,
        tls::{Identity, PeerCertificate, TlsConfig},
    },
    protocol::PeerId,
};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
fn wait(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !check() {
        assert!(Instant::now() < deadline, "peer network deadline");
        thread::sleep(Duration::from_millis(5));
    }
}
struct Fixture {
    tls: Vec<TlsConfig>,
    addresses: BTreeMap<PeerId, SocketAddr>,
    listeners: Vec<Option<TcpListener>>,
}
impl Fixture {
    fn new(n: usize) -> Self {
        let identities: Vec<_> = (0..n)
            .map(|id| Identity::generate(&format!("guardian{id}")).unwrap())
            .collect();
        let certs: BTreeMap<_, _> = identities
            .iter()
            .enumerate()
            .map(|(id, i)| {
                (
                    PeerId(id as u16),
                    PeerCertificate {
                        name: format!("guardian{id}"),
                        certificate_der: i.certificate_der().unwrap(),
                    },
                )
            })
            .collect();
        let tls = identities
            .iter()
            .map(|i| TlsConfig::new(i, certs.clone()).unwrap())
            .collect();
        let listeners: Vec<_> = (0..n)
            .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
            .collect();
        let addresses = listeners
            .iter()
            .enumerate()
            .map(|(id, l)| (PeerId(id as u16), l.as_ref().unwrap().local_addr().unwrap()))
            .collect();
        Self {
            tls,
            addresses,
            listeners,
        }
    }
    fn start(&mut self, id: usize, capacity: usize) -> PeerNetwork {
        let listener = self.listeners[id]
            .take()
            .unwrap_or_else(|| TcpListener::bind(self.addresses[&PeerId(id as u16)]).unwrap());
        let addresses = self
            .addresses
            .iter()
            .filter(|(p, _)| p.0 as usize != id)
            .map(|(p, a)| (*p, *a))
            .collect();
        PeerNetwork::start(
            PeerId(id as u16),
            self.tls[id].clone(),
            addresses,
            listener,
            capacity,
        )
        .unwrap()
    }
    fn raw(&self, from: usize, to: usize) -> minimint_ng::net::tls::AuthenticatedStream {
        let tcp = TcpStream::connect(self.addresses[&PeerId(to as u16)]).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        self.tls[from].connect(tcp, PeerId(to as u16)).unwrap()
    }
}
#[test]
fn four_nodes_bidirectional_fifo_and_lower_peer_reconnect_after_restart() {
    let mut f = Fixture::new(4);
    let mut nodes: Vec<_> = (0..4).map(|id| Some(f.start(id, 32))).collect();
    wait(|| {
        (0..4).all(|id| {
            (0..4).all(|peer| {
                id == peer || nodes[id].as_ref().unwrap().connected(PeerId(peer as u16))
            })
        })
    });
    for (id, node) in nodes.iter().enumerate() {
        for peer in 0..4 {
            if id != peer {
                for index in 0..8 {
                    node.as_ref()
                        .unwrap()
                        .send(PeerId(peer as u16), Envelope::SessionIndex(index))
                        .unwrap();
                }
            }
        }
    }
    for (id, node) in nodes.iter().enumerate() {
        let node = node.as_ref().unwrap();
        let mut counts = [0; 4];
        for _ in 0..24 {
            let (peer, message) = node.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
            assert_ne!(peer.0 as usize, id);
            assert!(matches!(message, Envelope::SessionIndex(n) if n == counts[peer.0 as usize]));
            counts[peer.0 as usize] += 1;
        }
        assert!((0..4).all(|p| counts[p] == if p == id { 0 } else { 8 }));
    }
    nodes[3].take().unwrap().shutdown().unwrap();
    wait(|| (0..3).all(|id| !nodes[id].as_ref().unwrap().connected(PeerId(3))));
    assert!(matches!(
        nodes[0]
            .as_ref()
            .unwrap()
            .send(PeerId(3), Envelope::SessionIndex(9)),
        Err(TransportError::Closed)
    ));
    nodes[3] = Some(f.start(3, 32));
    wait(|| {
        (0..3).all(|id| {
            nodes[id].as_ref().unwrap().connected(PeerId(3))
                && nodes[3].as_ref().unwrap().connected(PeerId(id as u16))
        })
    });
    nodes[0]
        .as_ref()
        .unwrap()
        .send(PeerId(3), Envelope::SessionIndex(42))
        .unwrap();
    assert!(matches!(
        nodes[3]
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap(),
        Some((PeerId(0), Envelope::SessionIndex(42)))
    ));
    nodes[3]
        .as_ref()
        .unwrap()
        .send(PeerId(0), Envelope::SessionIndex(43))
        .unwrap();
    assert!(matches!(
        nodes[0]
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap(),
        Some((PeerId(3), Envelope::SessionIndex(43)))
    ));
    for node in nodes {
        node.unwrap().shutdown().unwrap();
    }
}
#[test]
fn accepted_replacement_supersedes_old_connection_and_shared_receive_fifo() {
    let mut f = Fixture::new(2);
    let node = f.start(1, 8);
    let mut old = f.raw(0, 1);
    wait(|| node.connected(PeerId(0)));
    old.write_envelope(&Envelope::SessionIndex(1)).unwrap();
    assert!(matches!(
        node.recv_timeout(Duration::from_secs(2)).unwrap(),
        Some((PeerId(0), Envelope::SessionIndex(1)))
    ));
    let mut replacement = f.raw(0, 1);
    replacement
        .write_envelope(&Envelope::SessionIndex(2))
        .unwrap();
    assert!(matches!(
        node.recv_timeout(Duration::from_secs(2)).unwrap(),
        Some((PeerId(0), Envelope::SessionIndex(2)))
    ));
    drop(old);
    thread::sleep(Duration::from_millis(30));
    assert!(node.connected(PeerId(0)));
    node.send(PeerId(0), Envelope::SessionIndex(3)).unwrap();
    assert!(matches!(
        replacement.read_envelope().unwrap(),
        Envelope::SessionIndex(3)
    ));
    replacement
        .write_envelope(&Envelope::SessionIndex(4))
        .unwrap();
    replacement
        .write_envelope(&Envelope::SessionIndex(5))
        .unwrap();
    let mut first = None;
    wait(|| {
        first = node.try_recv(PeerId(0)).unwrap();
        first.is_some()
    });
    assert!(matches!(first, Some(Envelope::SessionIndex(4))));
    assert!(matches!(
        node.recv_timeout(Duration::from_secs(2)).unwrap(),
        Some((PeerId(0), Envelope::SessionIndex(5)))
    ));
    assert!(node.try_recv(PeerId(0)).unwrap().is_none());
    node.shutdown().unwrap();
}
#[test]
fn malformed_envelope_and_full_incoming_queue_disconnect_without_reordering() {
    let mut f = Fixture::new(2);
    let node = f.start(1, 1);
    let mut stream = f.raw(0, 1);
    wait(|| node.connected(PeerId(0)));
    stream.write_frame(&[255]).unwrap();
    wait(|| !node.connected(PeerId(0)));
    let mut stream = f.raw(0, 1);
    wait(|| node.connected(PeerId(0)));
    stream.write_envelope(&Envelope::SessionIndex(10)).unwrap();
    stream.write_envelope(&Envelope::SessionIndex(11)).unwrap();
    wait(|| !node.connected(PeerId(0)));
    assert!(matches!(
        node.try_recv(PeerId(0)).unwrap(),
        Some(Envelope::SessionIndex(10))
    ));
    assert!(node.try_recv(PeerId(0)).unwrap().is_none());
    node.shutdown().unwrap();
}
#[test]
fn idle_unauthenticated_handshake_has_bounded_shutdown_and_higher_id_never_dials() {
    let mut f = Fixture::new(2);
    let node = f.start(1, 1);
    // Peer zero's bound listener has no acceptor. Higher ID must not initiate.
    f.listeners[0]
        .as_ref()
        .unwrap()
        .set_nonblocking(true)
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        f.listeners[0]
            .as_ref()
            .unwrap()
            .accept()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    let _idle = TcpStream::connect(f.addresses[&PeerId(1)]).unwrap();
    thread::sleep(Duration::from_millis(20));
    let start = Instant::now();
    node.shutdown().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
}
#[test]
fn outbound_queue_is_bounded_including_pending_partial_frame() {
    let mut f = Fixture::new(2);
    let node = f.start(1, 1);
    let _stream = f.raw(0, 1);
    wait(|| node.connected(PeerId(0)));
    // Larger than socket send buffers, so the raw peer's absent reader forces a
    // partial nonblocking write. The pending frame counts toward queue capacity.
    let payload = vec![7; MAX_FRAME_LEN - 128];
    node.send(PeerId(0), Envelope::Agreement(payload)).unwrap();
    assert!(matches!(
        node.send(PeerId(0), Envelope::SessionIndex(1)),
        Err(TransportError::QueueFull)
    ));
    let start = Instant::now();
    node.shutdown().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn large_simultaneous_transfers_progress_in_both_directions() {
    let mut f = Fixture::new(2);
    let low = f.start(0, 2);
    let high = f.start(1, 2);
    wait(|| low.connected(PeerId(1)) && high.connected(PeerId(0)));
    let a = vec![0x35; 4 * 1024 * 1024];
    let b = vec![0x72; 4 * 1024 * 1024];
    low.send(PeerId(1), Envelope::Agreement(a.clone())).unwrap();
    high.send(PeerId(0), Envelope::Agreement(b.clone()))
        .unwrap();
    assert!(
        matches!(high.recv_timeout(Duration::from_secs(10)).unwrap(), Some((PeerId(0),Envelope::Agreement(bytes))) if bytes == a)
    );
    assert!(
        matches!(low.recv_timeout(Duration::from_secs(10)).unwrap(), Some((PeerId(1),Envelope::Agreement(bytes))) if bytes == b)
    );
    assert!(low.connected(PeerId(1)) && high.connected(PeerId(0)));
    low.request_shutdown();
    assert!(low.is_closed());
    assert!(matches!(
        low.recv_timeout(Duration::ZERO),
        Err(TransportError::Closed)
    ));
    low.shutdown().unwrap();
    high.shutdown().unwrap();
}
