use minimint_ng::api::{
    rpc::{Request, RpcError},
    server::{CallContext, Handler, Server},
    websocket::{Limits, Message, WebSocket},
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::{
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
struct TestHandler {
    calls: AtomicUsize,
    waiting: AtomicUsize,
}
impl Handler for TestHandler {
    fn handle(&self, request: &Request, context: &CallContext<'_>) -> Result<Value, RpcError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match request.method.as_str() {
            "admin" => {
                request.require_admin("admin-secret")?;
                Ok(json!(true))
            }
            "wait" => {
                self.waiting.fetch_add(1, Ordering::SeqCst);
                while !context.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(RpcError::INTERNAL)
            }
            "echo" => Ok(request.params.clone()),
            _ => Err(RpcError::METHOD),
        }
    }
}
fn start() -> (Server, WebSocket, Arc<TestHandler>, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handler = Arc::new(TestHandler {
        calls: AtomicUsize::new(0),
        waiting: AtomicUsize::new(0),
    });
    let server = Server::start(
        listener,
        handler.clone(),
        Some(zeroize::Zeroizing::new("access-secret".into())),
        Limits::default(),
        4,
    )
    .unwrap();
    let ws = WebSocket::connect(
        TcpStream::connect(address).unwrap(),
        &address.to_string(),
        "/",
        Some("access-secret"),
        Limits::default(),
    )
    .unwrap();
    (server, ws, handler, address)
}
fn receive(ws: &mut WebSocket) -> Value {
    let Message::Text(text) = ws.receive().unwrap() else {
        panic!("expected text");
    };
    minimint_ng::json::parse(text.as_bytes(), 65536, 64).unwrap()
}
#[test]
fn real_socket_batch_notifications_and_admin_transport_separation() {
    let (server, mut ws, handler, _) = start();
    ws.send_text(r#"[{"jsonrpc":"2.0","method":"echo","params":[{"auth":null,"params":0}]},{"jsonrpc":"2.0","id":18446744073709551615,"method":"echo","params":[{"auth":null,"params":42}]},9,{"jsonrpc":"2.0","id":"admin","method":"admin","params":[{"auth":null,"params":null}]}]"#).unwrap();
    let reply = receive(&mut ws);
    assert_eq!(reply[0]["result"].as_u64(), Some(42));
    assert_eq!(
        minimint_ng::json::unsigned(&reply[0]["id"]).unwrap(),
        u64::MAX
    );
    assert_eq!(reply[1]["error"]["code"].as_i64(), Some(-32600));
    assert_eq!(reply[2]["error"]["code"].as_i64(), Some(401));
    assert_eq!(handler.calls.load(Ordering::SeqCst), 3);
    // A notification-only batch must emit no response frame. The following call
    // must be the very next received JSON reply.
    ws.send_text(r#"[{"jsonrpc":"2.0","method":"echo","params":[{"params":0}]}]"#)
        .unwrap();
    ws.send_text(r#"{"jsonrpc":"2.0","id":7,"method":"admin","params":[{"auth":"admin-secret","params":null}]}"#).unwrap();
    let reply = receive(&mut ws);
    assert_eq!(reply["id"].as_u64(), Some(7));
    assert_eq!(reply["result"].as_bool(), Some(true));
    ws.send_text("[]").unwrap();
    let reply = receive(&mut ws);
    assert!(reply.is_object());
    assert!(reply["id"].is_null());
    server.shutdown().unwrap();
}
#[test]
fn shutdown_interrupts_idle_handshake_socket_and_cooperative_long_poll() {
    let (server, mut ws, handler, address) = start();
    let _idle_handshake = TcpStream::connect(address).unwrap();
    ws.send_text(r#"{"jsonrpc":"2.0","id":1,"method":"wait","params":[{"params":null}]}"#)
        .unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while handler.waiting.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(2));
    }
    let begin = Instant::now();
    server.shutdown().unwrap();
    assert!(begin.elapsed() < Duration::from_secs(1));
    assert!(ws.receive().is_err());
}

struct ConcurrentHandler {
    active: AtomicUsize,
    finished: AtomicUsize,
    slow_started: AtomicUsize,
}
impl Handler for ConcurrentHandler {
    fn handle(&self, request: &Request, context: &CallContext<'_>) -> Result<Value, RpcError> {
        match request.method.as_str() {
            "wait" => {
                self.active.fetch_add(1, Ordering::SeqCst);
                while !context.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                self.active.fetch_sub(1, Ordering::SeqCst);
                self.finished.fetch_add(1, Ordering::SeqCst);
                Ok(json!("late success must be suppressed"))
            }
            "slow" => {
                self.slow_started.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(650));
                Ok(json!("too late"))
            }
            "large" => Ok(json!("x".repeat(4096))),
            _ => Ok(request.params.clone()),
        }
    }
}
fn concurrent_server(
    timeout: Duration,
    maximum: usize,
) -> (Server, Arc<ConcurrentHandler>, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handler = Arc::new(ConcurrentHandler {
        active: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
        slow_started: AtomicUsize::new(0),
    });
    let limits = Limits {
        operation_timeout: timeout,
        max_message_bytes: maximum,
        ..Limits::default()
    };
    (
        Server::start(listener, handler.clone(), None, limits, 2).unwrap(),
        handler,
        address,
    )
}
fn call(ws: &mut WebSocket, id: u64, method: &str) {
    ws.send_text(&format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":[{{"params":{id}}}]}}"#
    ))
    .unwrap();
}
fn until(mut condition: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(2);
    while !condition() {
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn pending_long_poll_does_not_block_fast_call_or_pong_and_disconnect_joins() {
    use std::io::Read;
    let (server, handler, address) = concurrent_server(Duration::from_secs(60), 65536);
    let socket = TcpStream::connect(address).unwrap();
    let mut observe = socket.try_clone().unwrap();
    observe
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut ws = WebSocket::connect(socket, "localhost", "/", None, Limits::default()).unwrap();
    call(&mut ws, 1, "wait");
    until(|| handler.active.load(Ordering::SeqCst) == 1);
    ws.ping(b"live").unwrap();
    let mut pong = [0; 6];
    observe.read_exact(&mut pong).unwrap();
    assert_eq!(pong, *b"\x8a\x04live");
    call(&mut ws, 2, "echo");
    let reply = receive(&mut ws);
    assert_eq!(reply["id"].as_u64(), Some(2));
    assert_eq!(reply["result"].as_u64(), Some(2));
    assert_eq!(handler.active.load(Ordering::SeqCst), 1);
    drop(ws);
    drop(observe);
    until(|| handler.finished.load(Ordering::SeqCst) == 1);
    let mut again = WebSocket::connect(
        TcpStream::connect(address).unwrap(),
        "localhost",
        "/",
        None,
        Limits::default(),
    )
    .unwrap();
    call(&mut again, 3, "echo");
    assert_eq!(receive(&mut again)["id"].as_u64(), Some(3));
    server.shutdown().unwrap();
    assert_eq!(handler.active.load(Ordering::SeqCst), 0);
}
#[test]
fn late_handler_success_is_suppressed_while_other_calls_keep_connection_live() {
    let (server, handler, address) = concurrent_server(Duration::from_millis(300), 65536);
    let mut ws = WebSocket::connect(
        TcpStream::connect(address).unwrap(),
        "localhost",
        "/",
        None,
        Limits::default(),
    )
    .unwrap();
    call(&mut ws, 1, "slow");
    until(|| handler.slow_started.load(Ordering::SeqCst) == 1);
    for id in [2, 3, 4] {
        thread::sleep(Duration::from_millis(150));
        call(&mut ws, id, "echo");
        let reply = receive(&mut ws);
        assert_eq!(reply["id"].as_u64(), Some(id));
    }
    let reply = receive(&mut ws);
    assert_eq!(reply["id"].as_u64(), Some(1));
    assert!(reply.get("result").is_none());
    assert_eq!(reply["error"]["code"].as_i64(), Some(500));
    server.shutdown().unwrap();
}
#[test]
fn in_flight_cap_cancels_and_joins_all_eight_workers() {
    let (server, handler, address) = concurrent_server(Duration::from_secs(60), 65536);
    let mut ws = WebSocket::connect(
        TcpStream::connect(address).unwrap(),
        "localhost",
        "/",
        None,
        Limits::default(),
    )
    .unwrap();
    for id in 0..8 {
        call(&mut ws, id, "wait");
    }
    until(|| handler.active.load(Ordering::SeqCst) == 8);
    call(&mut ws, 9, "echo");
    assert!(ws.receive().is_err());
    until(|| handler.finished.load(Ordering::SeqCst) == 8);
    server.shutdown().unwrap();
    assert_eq!(handler.active.load(Ordering::SeqCst), 0);
}
#[test]
fn oversized_result_closes_connection_before_unbounded_reply_aggregation() {
    let (server, _handler, address) = concurrent_server(Duration::from_secs(5), 512);
    let mut ws = WebSocket::connect(
        TcpStream::connect(address).unwrap(),
        "localhost",
        "/",
        None,
        Limits::default(),
    )
    .unwrap();
    call(&mut ws, 1, "large");
    assert!(ws.receive().is_err());
    server.shutdown().unwrap();
}
