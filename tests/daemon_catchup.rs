use minimint_ng::{
    api::{
        announcements::{ApiAnnouncement, SignedAnnouncement},
        websocket::{Limits, Message, WebSocket},
    },
    codec::{ConsensusEncode, rpc},
    core::{history::HistoryVerifier, session::session_count},
    daemon::{
        catchup::{Catchup, CatchupEndpoint, CatchupError, CatchupOptions},
        config::RuntimeConfig,
        consensus::{Runtime, RuntimeHandle, RuntimeOptions},
    },
    modules::wallet,
    net::PeerNetwork,
    protocol::{
        AcceptedItem, ConsensusItem, DynamicValue, ModuleId, PeerId, SessionOutcome,
        SignedSessionOutcome,
    },
    storage::Store,
};
use sonic_rs::{JsonValueTrait, json};
use std::{
    net::TcpListener,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
#[path = "fixtures/runtime/mod.rs"]
mod runtime_fixture;
use runtime_fixture::{Backend, configs, key, url};
struct Running {
    _dir: fixture::TestDir,
    store: Store,
    config: Arc<RuntimeConfig>,
    runtime: Option<Runtime>,
    handle: RuntimeHandle,
    net: Arc<PeerNetwork>,
    // Keep unavailable peers' addresses reserved until PeerNetwork has joined.
    // Otherwise ephemeral API listeners can reuse a reconnect destination and
    // receive unrelated TLS connections during no-catchup-connection assertions.
    unavailable_peers: Vec<TcpListener>,
}
impl Running {
    fn new() -> Self {
        let mut listeners: Vec<_> = (0..4)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let config = configs(4, 12, &listeners).remove(0);
        let net = Arc::new(
            PeerNetwork::start(
                PeerId(0),
                config.tls_config().unwrap(),
                config.resolve_peer_addresses().unwrap(),
                listeners.remove(0),
                64,
            )
            .unwrap(),
        );
        let dir = fixture::TestDir::new();
        let store = Store::open(dir.path()).unwrap();
        let (runtime, handle) = Runtime::start(
            store.clone(),
            config.clone(),
            net.clone(),
            Arc::new(Backend::new()),
            RuntimeOptions {
                round_delay_ms: 20,
                queue_capacity: 16,
                tick: Duration::from_millis(2),
                wallet_poll_interval: Duration::from_millis(20),
            },
        )
        .unwrap();
        wait(|| handle.current_session() == Some(0));
        Self {
            _dir: dir,
            store,
            config,
            runtime: Some(runtime),
            handle,
            net,
            unavailable_peers: listeners,
        }
    }
    fn history(&self, index: u64, module: u16) -> SignedSessionOutcome {
        let outcome = SessionOutcome {
            items: vec![AcceptedItem {
                peer: PeerId(0),
                item: ConsensusItem::Module(DynamicValue {
                    module_id: ModuleId(module),
                    payload: wallet::ConsensusItem::FeeRate(Some(1000)).consensus_encode(),
                }),
            }],
        };
        let verifier =
            HistoryVerifier::new(self.config.server_config().broadcast_public_keys.clone())
                .unwrap();
        let signatures = (0..3)
            .map(|p| {
                (
                    PeerId(p),
                    verifier
                        .sign(index, &outcome, PeerId(p), &key(p as u8 + 1))
                        .unwrap(),
                )
            })
            .collect();
        SignedSessionOutcome {
            outcome,
            signatures,
        }
    }
    fn start(&self, endpoint: CatchupEndpoint, timeout: Duration) -> Catchup {
        Catchup::start(
            self.handle.clone(),
            vec![endpoint],
            Some(zeroize::Zeroizing::new("secret".into())),
            CatchupOptions {
                request_timeout: timeout,
                retry_interval: Duration::from_millis(20),
                max_response_bytes: 1024 * 1024,
            },
        )
        .unwrap()
    }
}
#[test]
fn unavailable_peer_ports_stay_reserved_while_peer_network_dials_tls() {
    use std::io::Read;
    let running = Running::new();
    for listener in &running.unavailable_peers {
        let address = listener.local_addr().unwrap();
        assert_eq!(
            TcpListener::bind(address).unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse
        );
    }
    // No Catchup exists here. A configured unavailable peer receives a TLS
    // ClientHello from the live reconnect worker, demonstrating the traffic
    // that could reach an API fixture if this address were released/reused.
    let listener = &running.unavailable_peers[0];
    listener.set_nonblocking(true).unwrap();
    let mut connection = None;
    wait(|| match listener.accept() {
        Ok((socket, _)) => {
            connection = Some(socket);
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("unavailable peer accept failed: {error}"),
    });
    let mut socket = connection.unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut record = [0; 5];
    socket.read_exact(&mut record).unwrap();
    assert_eq!(
        record[0], 22,
        "peer connection must be a TLS handshake record"
    );
    assert_eq!(record[1], 3, "TLS legacy record major version");
}
impl Drop for Running {
    fn drop(&mut self) {
        self.handle.request_shutdown();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown().unwrap();
        }
        self.net.request_shutdown();
    }
}
fn wait(mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < end, "bounded test wait expired");
        thread::sleep(Duration::from_millis(5));
    }
}
fn endpoint(listener: &TcpListener) -> CatchupEndpoint {
    let api_announcement = ApiAnnouncement {
        api_url: url(&format!("ws://{}/", listener.local_addr().unwrap())),
        nonce: 1,
    };
    let signature = key(2).schnorr_sign(&api_announcement.digest()).unwrap();
    CatchupEndpoint::announced(
        PeerId(1),
        SignedAnnouncement {
            api_announcement,
            signature,
        },
        vec![listener.local_addr().unwrap()],
    )
    .unwrap()
}
fn server(listener: TcpListener, response: String) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut ws = WebSocket::accept(stream, Some("secret"), Limits::default()).unwrap();
        let Message::Text(request) = ws.receive().unwrap() else {
            panic!("expected request")
        };
        let request: sonic_rs::Value = sonic_rs::from_str(&request).unwrap();
        assert_eq!(
            request["method"].as_str(),
            Some("await_signed_session_outcome")
        );
        assert_eq!(request["params"][0]["params"].as_u64(), Some(0));
        assert!(request["params"][0]["auth"].is_null());
        ws.send_text(&response).unwrap();
    })
}
#[test]
fn signed_module_history_is_adopted_over_authenticated_websocket() {
    let r = Running::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(&listener);
    let signed = r.history(0, 1);
    let worker = server(
        listener,
        json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&signed)}).to_string(),
    );
    let catchup = r.start(endpoint, Duration::from_secs(2));
    wait(|| session_count(&r.store.snapshot().unwrap()).unwrap() == 1);
    catchup.shutdown().unwrap();
    worker.join().unwrap();
}
#[test]
fn wrong_index_unknown_module_and_rpc_error_never_enter_runtime() {
    let r = Running::new();
    let mut extra = r.history(0, 1);
    let verifier =
        HistoryVerifier::new(r.config.server_config().broadcast_public_keys.clone()).unwrap();
    extra.signatures.insert(
        PeerId(3),
        verifier
            .sign(0, &extra.outcome, PeerId(3), &key(4))
            .unwrap(),
    );
    let mut trailing = rpc::hex(&r.history(0, 1));
    trailing[0].push_str("00");
    for (response, expected) in [
        (
            json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&extra)}),
            CatchupError::InvalidHistory,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"result":trailing}),
            CatchupError::InvalidHistory,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&r.history(1,1))}),
            CatchupError::InvalidHistory,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&r.history(0,99))}),
            CatchupError::InvalidHistory,
        ),
        (
            json!({"jsonrpc":"2.0","id":1,"error":{"code":404,"message":"unavailable"}}),
            CatchupError::Rpc,
        ),
        (
            json!({"jsonrpc":"2.0","id":2,"result":rpc::hex(&r.history(0,1))}),
            CatchupError::InvalidResponse,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = endpoint(&listener);
        let worker = server(listener, response.to_string());
        let catchup = r.start(endpoint, Duration::from_secs(2));
        wait(|| catchup.last_error() == Some(expected));
        catchup.shutdown().unwrap();
        worker.join().unwrap();
        assert_eq!(session_count(&r.store.snapshot().unwrap()).unwrap(), 0);
    }
}
#[test]
fn stalled_upgrade_has_absolute_deadline_and_shutdown_joins() {
    let r = Running::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(&listener);
    let catchup = r.start(endpoint, Duration::from_millis(100));
    let (socket, _) = listener.accept().unwrap();
    wait(|| catchup.last_error() == Some(CatchupError::Timeout));
    let start = Instant::now();
    catchup.shutdown().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(socket);
}
#[test]
fn runtime_stop_cancels_stalled_response() {
    let r = Running::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = endpoint(&listener);
    let catchup = r.start(endpoint, Duration::from_secs(30));
    let (socket, _) = listener.accept().unwrap();
    let mut ws = WebSocket::accept(socket, Some("secret"), Limits::default()).unwrap();
    assert!(matches!(ws.receive().unwrap(), Message::Text(_)));
    r.handle.request_shutdown();
    wait(|| catchup.is_finished());
    catchup.shutdown().unwrap();
}
#[test]
fn transport_and_unsigned_endpoint_changes_are_rejected() {
    assert!(matches!(
        CatchupEndpoint::new(
            PeerId(1),
            url("wss://127.0.0.1/"),
            vec!["127.0.0.1:443".parse().unwrap()]
        ),
        Err(CatchupError::UnsupportedTransport)
    ));
    let r = Running::new();
    let endpoint = CatchupEndpoint::new(
        PeerId(1),
        url("ws://127.0.0.1:12345/"),
        vec!["127.0.0.1:12345".parse().unwrap()],
    )
    .unwrap();
    assert!(matches!(
        Catchup::start(
            r.handle.clone(),
            vec![endpoint],
            None,
            CatchupOptions::default()
        ),
        Err(CatchupError::InvalidConfiguration)
    ));
}

fn announcement(listener: &TcpListener, peer: u8, nonce: u64) -> SignedAnnouncement {
    let api_announcement = ApiAnnouncement {
        api_url: url(&format!("ws://{}/", listener.local_addr().unwrap())),
        nonce,
    };
    let signature = key(peer + 1)
        .schnorr_sign(&api_announcement.digest())
        .unwrap();
    SignedAnnouncement {
        api_announcement,
        signature,
    }
}
#[test]
fn live_selection_cancels_old_request_and_rejects_stale_resolution() {
    use minimint_ng::daemon::catchup::EndpointUpdate;
    let r = Running::new();
    let original = r.config.server_config().clone();
    let old = TcpListener::bind("127.0.0.1:0").unwrap();
    let catchup = r.start(endpoint(&old), Duration::from_secs(30));
    let (socket, _) = old.accept().unwrap();
    let mut old_ws = WebSocket::accept(socket, Some("secret"), Limits::default()).unwrap();
    assert!(matches!(old_ws.receive().unwrap(), Message::Text(_)));
    let replaced = TcpListener::bind("127.0.0.1:0").unwrap();
    replaced.set_nonblocking(true).unwrap();
    let signed2 = announcement(&replaced, 1, 2);
    let began = Instant::now();
    assert_eq!(
        catchup.select_announcement(PeerId(1), signed2.clone()),
        Ok(EndpointUpdate::Updated)
    );
    assert!(old_ws.receive().is_err());
    assert!(began.elapsed() < Duration::from_secs(1));
    assert_eq!(
        catchup.select_announcement(PeerId(1), signed2.clone()),
        Ok(EndpointUpdate::Unchanged)
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        replaced.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let current = TcpListener::bind("127.0.0.1:0").unwrap();
    let signed3 = announcement(&current, 1, 3);
    assert_eq!(
        catchup.select_announcement(PeerId(1), announcement(&current, 1, 2)),
        Err(CatchupError::StaleAnnouncement)
    );
    assert_eq!(
        catchup.select_announcement(PeerId(1), signed3.clone()),
        Ok(EndpointUpdate::Updated)
    );
    assert_eq!(
        catchup.install_resolved(PeerId(1), &signed2, vec![replaced.local_addr().unwrap()]),
        Err(CatchupError::StaleAnnouncement)
    );
    assert_eq!(
        catchup.select_announcement(PeerId(1), signed2),
        Err(CatchupError::StaleAnnouncement)
    );
    let mut forged = announcement(&current, 1, 4);
    forged.signature[0] ^= 1;
    assert_eq!(
        catchup.select_announcement(PeerId(1), forged),
        Err(CatchupError::InvalidConfiguration)
    );
    assert_eq!(
        catchup.install_resolved(PeerId(1), &signed3, vec![replaced.local_addr().unwrap()]),
        Err(CatchupError::InvalidConfiguration)
    );
    let address = current.local_addr().unwrap();
    let worker = server(
        current,
        json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&r.history(0,1))}).to_string(),
    );
    assert_eq!(
        catchup.install_resolved(PeerId(1), &signed3, vec![address]),
        Ok(EndpointUpdate::Updated)
    );
    assert_eq!(
        catchup.install_resolved(PeerId(1), &signed3, vec![address]),
        Ok(EndpointUpdate::Unchanged)
    );
    wait(|| session_count(&r.store.snapshot().unwrap()).unwrap() == 1);
    assert_eq!(r.config.server_config(), &original);
    catchup.shutdown().unwrap();
    worker.join().unwrap();
}
#[test]
fn parked_unsupported_override_preserves_other_peer_availability() {
    use minimint_ng::daemon::catchup::EndpointUpdate;
    let r = Running::new();
    let old = TcpListener::bind("127.0.0.1:0").unwrap();
    let available = TcpListener::bind("127.0.0.1:0").unwrap();
    let available_signed = announcement(&available, 2, 0);
    let available_endpoint = CatchupEndpoint::announced(
        PeerId(2),
        available_signed,
        vec![available.local_addr().unwrap()],
    )
    .unwrap();
    let catchup = Catchup::start(
        r.handle.clone(),
        vec![endpoint(&old), available_endpoint],
        Some(zeroize::Zeroizing::new("secret".into())),
        CatchupOptions {
            request_timeout: Duration::from_secs(30),
            retry_interval: Duration::from_millis(20),
            max_response_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    let (socket, _) = old.accept().unwrap();
    let mut old_ws = WebSocket::accept(socket, Some("secret"), Limits::default()).unwrap();
    assert!(matches!(old_ws.receive().unwrap(), Message::Text(_)));
    let api_announcement = ApiAnnouncement {
        api_url: url("wss://localhost/"),
        nonce: 2,
    };
    let signature = key(2).schnorr_sign(&api_announcement.digest()).unwrap();
    let signed = SignedAnnouncement {
        api_announcement,
        signature,
    };
    assert_eq!(
        catchup.select_announcement(PeerId(1), signed.clone()),
        Ok(EndpointUpdate::Updated)
    );
    assert_eq!(
        catchup.install_resolved(PeerId(1), &signed, vec!["127.0.0.1:443".parse().unwrap()]),
        Err(CatchupError::UnsupportedTransport)
    );
    let worker = server(
        available,
        json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&r.history(0,1))}).to_string(),
    );
    wait(|| session_count(&r.store.snapshot().unwrap()).unwrap() == 1);
    catchup.shutdown().unwrap();
    worker.join().unwrap();
}
#[test]
fn runtime_shutdown_joins_when_every_endpoint_is_awaiting_resolution() {
    let r = Running::new();
    let old = TcpListener::bind("127.0.0.1:0").unwrap();
    let current = TcpListener::bind("127.0.0.1:0").unwrap();
    let catchup = r.start(endpoint(&old), Duration::from_secs(30));
    catchup
        .select_announcement(PeerId(1), announcement(&current, 1, 2))
        .unwrap();
    r.handle.request_shutdown();
    wait(|| catchup.is_finished());
    catchup.shutdown().unwrap();
}

#[test]
fn restored_pending_announcement_is_authenticated_and_resolves_without_fallback() {
    let r = Running::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let signed = announcement(&listener, 1, 0);
    let mut forged = signed.clone();
    forged.signature[0] ^= 1;
    assert!(matches!(
        Catchup::start(
            r.handle.clone(),
            vec![CatchupEndpoint::pending_announcement(PeerId(1), forged)],
            None,
            CatchupOptions::default()
        ),
        Err(CatchupError::InvalidConfiguration)
    ));
    let catchup = r.start(
        CatchupEndpoint::pending_announcement(PeerId(1), signed.clone()),
        Duration::from_secs(30),
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!catchup.is_finished());
    listener.set_nonblocking(false).unwrap();
    let address = listener.local_addr().unwrap();
    let worker = server(
        listener,
        json!({"jsonrpc":"2.0","id":1,"result":rpc::hex(&r.history(0,1))}).to_string(),
    );
    catchup
        .install_resolved(PeerId(1), &signed, vec![address])
        .unwrap();
    wait(|| session_count(&r.store.snapshot().unwrap()).unwrap() == 1);
    catchup.shutdown().unwrap();
    worker.join().unwrap();
}
