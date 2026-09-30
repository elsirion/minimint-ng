use minimint_ng::api::websocket::{Limits, Message, WebSocket, WsError};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
fn limits() -> Limits {
    Limits {
        max_message_bytes: 1024 * 1024,
        handshake_timeout: Duration::from_secs(2),
        operation_timeout: Duration::from_secs(2),
        ..Limits::default()
    }
}
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    (client, server)
}
fn request(extra: &str) -> String {
    format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{extra}\r\n"
    )
}
fn header(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut one = [0];
        stream.read_exact(&mut one).unwrap();
        bytes.push(one[0]);
        assert!(bytes.len() < 16384);
    }
    String::from_utf8(bytes).unwrap()
}
fn frame(opcode: u8, fin: bool, body: &[u8], masked: bool) -> Vec<u8> {
    let mut v = vec![opcode | if fin { 128 } else { 0 }];
    let flag = if masked { 128 } else { 0 };
    match body.len() {
        0..=125 => v.push(flag | body.len() as u8),
        126..=65535 => {
            v.push(flag | 126);
            v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        _ => {
            v.push(flag | 127);
            v.extend_from_slice(&(body.len() as u64).to_be_bytes());
        }
    }
    let mask = [0x37, 0xfa, 0x21, 0x3d];
    if masked {
        v.extend_from_slice(&mask);
    }
    v.extend(
        body.iter()
            .enumerate()
            .map(|(i, b)| if masked { *b ^ mask[i % 4] } else { *b }),
    );
    v
}
fn raw_server() -> (TcpStream, thread::JoinHandle<Result<Message, WsError>>) {
    let (mut raw, server) = pair();
    let worker = thread::spawn(move || {
        let mut ws = WebSocket::accept(server, None, limits())?;
        ws.receive()
    });
    raw.write_all(request("").as_bytes()).unwrap();
    assert!(header(&mut raw).starts_with("HTTP/1.1 101"));
    (raw, worker)
}
#[test]
fn rfc_handshake_mask_vector_fragmented_utf8_binary_ping_and_close() {
    let (mut raw, server) = pair();
    let worker = thread::spawn(move || {
        let mut ws = WebSocket::accept(server, None, limits()).unwrap();
        assert!(matches!(ws.receive().unwrap(),Message::Text(s) if s=="Hello"));
        assert!(matches!(ws.receive().unwrap(),Message::Text(s) if s=="€"));
        assert!(matches!(ws.receive().unwrap(),Message::Binary(b) if b==[0,255,1,2]));
        assert!(
            matches!(ws.receive().unwrap(),Message::Close{code:Some(1000),reason} if reason=="bye")
        );
        assert!(matches!(ws.receive(), Err(WsError::Closed)));
    });
    for chunk in request("").as_bytes().chunks(3) {
        raw.write_all(chunk).unwrap();
    }
    let response = header(&mut raw);
    assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    raw.write_all(&[
        0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ])
    .unwrap();
    let mut all = frame(1, false, &[0xe2, 0x82], true);
    all.extend(frame(9, true, b"ping", true));
    all.extend(frame(0, true, &[0xac], true));
    all.extend(frame(2, false, &[0, 255], true));
    all.extend(frame(0, true, &[1, 2], true));
    for chunk in all.chunks(2) {
        raw.write_all(chunk).unwrap();
    }
    let mut pong = [0; 6];
    raw.read_exact(&mut pong).unwrap();
    assert_eq!(pong, *b"\x8a\x04ping");
    let close = frame(8, true, &[3, 232, b'b', b'y', b'e'], true);
    raw.write_all(&close).unwrap();
    let mut echoed = [0; 7];
    raw.read_exact(&mut echoed).unwrap();
    assert_eq!(echoed, [0x88, 5, 3, 232, b'b', b'y', b'e']);
    worker.join().unwrap();
}
#[test]
fn real_client_server_roles_all_canonical_length_widths_and_auth() {
    let (client, server) = pair();
    let worker = thread::spawn(move || {
        let mut ws = WebSocket::accept(server, Some("sëcret:two"), limits()).unwrap();
        for size in [0, 125, 126, 65535, 65536] {
            assert!(matches!(ws.receive().unwrap(),Message::Binary(b) if b==vec![42;size]));
            ws.send_binary(&vec![17; size]).unwrap();
        }
        assert!(matches!(
            ws.receive().unwrap(),
            Message::Close { code: None, .. }
        ));
    });
    let mut ws = WebSocket::connect(
        client,
        "localhost",
        "/api?x=1",
        Some("sëcret:two"),
        limits(),
    )
    .unwrap();
    for size in [0, 125, 126, 65535, 65536] {
        ws.send_binary(&vec![42; size]).unwrap();
        assert!(matches!(ws.receive().unwrap(),Message::Binary(b) if b==vec![17;size]));
    }
    ws.send_close(None, "").unwrap();
    assert!(matches!(
        ws.receive().unwrap(),
        Message::Close { code: None, .. }
    ));
    worker.join().unwrap();
}
#[test]
fn api_access_secret_exact_basic_header_and_401_gate() {
    for auth in [
        "",
        "Authorization: Basic wrong\r\n",
        "Authorization: Basic ZmVkaW1pbnQ6c2VjcmV0\r\n",
    ] {
        let (mut raw, server) = pair();
        let worker =
            thread::spawn(move || WebSocket::accept(server, Some("secret"), limits()).map(|_| ()));
        raw.write_all(request(auth).as_bytes()).unwrap();
        let response = header(&mut raw);
        if auth.contains("ZmVkaW1pbnQ6") {
            assert!(response.starts_with("HTTP/1.1 101"));
            assert_eq!(worker.join().unwrap(), Ok(()));
        } else {
            assert!(response.starts_with("HTTP/1.1 401"));
            assert_eq!(worker.join().unwrap(), Err(WsError::Unauthorized));
        }
    }
}
#[test]
fn invalid_handshakes_fail_without_secret_error_details() {
    let cases = [
        request("").replace("Version: 13", "Version: 12"),
        request("").replace("GET /", "POST /"),
        request("").replace("dGhlIHNhbXBsZSBub25jZQ==", "invalid"),
        request("").replace("dGhlIHNhbXBsZSBub25jZQ==", "ééééééééééé=="),
        request("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"),
        request("").replace("Connection: keep-alive, Upgrade", "Connection: keep-alive"),
        request("Transfer-Encoding: chunked\r\n"),
        request("Authorization: one\r\nAuthorization: two\r\n"),
    ];
    for request in cases {
        let (mut raw, server) = pair();
        let worker = thread::spawn(move || WebSocket::accept(server, None, limits()).map(|_| ()));
        raw.write_all(request.as_bytes()).unwrap();
        assert!(!header(&mut raw).starts_with("HTTP/1.1 101"));
        assert!(worker.join().unwrap().is_err());
    }
    for (host, path, secret) in [
        ("localhost\r\nInjected: yes", "/", None),
        ("localhost", "/\r\nInjected", None),
        ("localhost", "/", Some("private\r\nsecret")),
    ] {
        let (client, _server) = pair();
        let result = WebSocket::connect(client, host, path, secret, limits()).map(|_| ());
        assert_eq!(result, Err(WsError::Protocol));
        assert!(!format!("{}", result.unwrap_err()).contains("private"));
    }
}
#[test]
fn invalid_frames_lengths_masks_controls_fragments_and_utf8_disconnect() {
    let mut cases = vec![
        frame(1, true, b"unmasked", false),
        vec![0xc1, 0x80, 0, 0, 0, 0],
        frame(3, true, b"", true),
        frame(0, true, b"", true),
        frame(9, false, b"", true),
        frame(9, true, &[0; 126], true),
        frame(1, true, &[0xff], true),
        frame(8, true, &[0], true),
        frame(8, true, &1005u16.to_be_bytes(), true),
        frame(8, true, &[3, 232, 255], true),
        vec![0x82, 0xfe, 0, 125],
        vec![0x82, 0xff, 0, 0, 0, 0, 0, 0, 0, 126],
        vec![0x82, 0xff, 0x80, 0, 0, 0, 0, 1, 0, 0],
    ];
    let mut nested = frame(1, false, b"a", true);
    nested.extend(frame(2, true, b"b", true));
    cases.push(nested);
    for bytes in cases {
        let (mut raw, worker) = raw_server();
        raw.write_all(&bytes).unwrap();
        assert!(worker.join().unwrap().is_err());
    }
}
#[test]
fn message_aggregate_limit_and_deadline_are_finite() {
    let (mut raw, server) = pair();
    let worker = thread::spawn(move || {
        let mut limits = limits();
        limits.max_message_bytes = 3;
        let mut ws = WebSocket::accept(server, None, limits)?;
        ws.receive()
    });
    raw.write_all(request("").as_bytes()).unwrap();
    header(&mut raw);
    let mut bytes = frame(2, false, &[1, 2], true);
    bytes.extend(frame(0, true, &[3, 4], true));
    raw.write_all(&bytes).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(WsError::Limit)));
    let (mut raw, server) = pair();
    let worker = thread::spawn(move || {
        let mut limits = limits();
        limits.operation_timeout = Duration::from_millis(80);
        let mut ws = WebSocket::accept(server, None, limits)?;
        let start = Instant::now();
        let result = ws.receive();
        assert!(start.elapsed() < Duration::from_secs(1));
        result
    });
    raw.write_all(request("").as_bytes()).unwrap();
    header(&mut raw);
    raw.write_all(&[0x81]).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(WsError::Timeout)));
}
#[test]
fn shutdown_handle_interrupts_blocked_receive() {
    let (mut raw, server) = pair();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let mut options = limits();
        options.operation_timeout = Duration::from_secs(60);
        let mut ws = WebSocket::accept(server, None, options)?;
        tx.send(ws.shutdown_handle()?).unwrap();
        ws.receive()
    });
    raw.write_all(request("").as_bytes()).unwrap();
    header(&mut raw);
    let handle = rx.recv().unwrap();
    thread::sleep(Duration::from_millis(10));
    let start = Instant::now();
    handle.shutdown();
    assert!(worker.join().unwrap().is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}
#[test]
fn client_rejects_wrong_accept_and_masked_server_frames() {
    let (client, mut raw) = pair();
    let worker = thread::spawn(move || {
        WebSocket::connect(client, "localhost", "/", None, limits()).map(|_| ())
    });
    header(&mut raw);
    raw.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n").unwrap();
    assert_eq!(worker.join().unwrap(), Err(WsError::Protocol));
    let (client, server) = pair();
    let mut injected = server.try_clone().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let ws = WebSocket::accept(server, None, limits()).unwrap();
        tx.send(()).unwrap();
        ws
    });
    let mut client = WebSocket::connect(client, "localhost", "/", None, limits()).unwrap();
    rx.recv().unwrap();
    let _server = worker.join().unwrap();
    // A separate socket clone writes malformed test bytes while the WebSocket owner
    // remains idle, exercising the client's role check without changing production API.
    injected
        .write_all(&frame(1, true, b"bad mask", true))
        .unwrap();
    assert!(matches!(client.receive(), Err(WsError::Protocol)));
}

#[test]
fn upgrade_header_size_and_idle_deadline_are_bounded() {
    let (mut raw, server) = pair();
    let worker = thread::spawn(move || {
        let mut options = limits();
        options.max_header_bytes = 64;
        WebSocket::accept(server, None, options).map(|_| ())
    });
    raw.write_all(request("").as_bytes()).unwrap();
    assert!(header(&mut raw).starts_with("HTTP/1.1 400"));
    assert_eq!(worker.join().unwrap(), Err(WsError::Limit));
    let (_raw, server) = pair();
    let start = Instant::now();
    let mut options = limits();
    options.handshake_timeout = Duration::from_millis(50);
    assert!(matches!(
        WebSocket::accept(server, None, options),
        Err(WsError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn independent_writers_serialize_whole_frames_while_reader_waits() {
    let (client, server) = pair();
    let worker = thread::spawn(move || {
        let mut ws = WebSocket::accept(server, None, limits()).unwrap();
        let mut tasks = Vec::new();
        for id in 0..4u8 {
            let writer = ws.writer();
            tasks.push(thread::spawn(move || {
                for _ in 0..4 {
                    writer.send_binary(&vec![id; 65536]).unwrap();
                }
            }));
        }
        assert!(matches!(ws.receive().unwrap(), Message::Close { .. }));
        for task in tasks {
            task.join().unwrap();
        }
    });
    let mut ws = WebSocket::connect(client, "localhost", "/", None, limits()).unwrap();
    let mut counts = [0; 4];
    for _ in 0..16 {
        let Message::Binary(bytes) = ws.receive().unwrap() else {
            panic!("binary expected");
        };
        assert_eq!(bytes.len(), 65536);
        let id = usize::from(bytes[0]);
        assert!(id < 4);
        assert!(bytes.iter().all(|b| usize::from(*b) == id));
        counts[id] += 1;
    }
    assert_eq!(counts, [4; 4]);
    ws.send_close(None, "").unwrap();
    assert!(matches!(ws.receive().unwrap(), Message::Close { .. }));
    worker.join().unwrap();
}
#[test]
fn writer_abort_interrupts_active_write_and_waiter_without_taking_write_lock() {
    let (mut raw, server) = pair();
    let worker = thread::spawn(move || WebSocket::accept(server, None, Limits::default()).unwrap());
    raw.write_all(request("").as_bytes()).unwrap();
    header(&mut raw);
    let ws = worker.join().unwrap();
    let first = ws.writer();
    let second = ws.writer();
    let cancellation = ws.writer();
    let writing = thread::spawn(move || first.send_binary(&vec![7; 16 * 1024 * 1024]));
    thread::sleep(Duration::from_millis(50));
    assert!(!writing.is_finished());
    let waiting = thread::spawn(move || second.send_text("queued"));
    thread::sleep(Duration::from_millis(20));
    assert!(!waiting.is_finished());
    let begin = Instant::now();
    cancellation.abort();
    assert!(writing.join().unwrap().is_err());
    assert!(waiting.join().unwrap().is_err());
    assert!(begin.elapsed() < Duration::from_secs(1));
    drop(ws);
    assert!(cancellation.send_text("closed").is_err());
}
