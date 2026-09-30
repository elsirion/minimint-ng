use minimint_ng::{
    bitcoin::{BitcoinBackend, rpc::CoreRpc},
    json,
};
use sonic_rs::JsonValueTrait;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn server(replies: Vec<String>) -> (CoreRpc, thread::JoinHandle<Vec<sonic_rs::Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = CoreRpc::new(
        listener.local_addr().unwrap(),
        "user:pass",
        Duration::from_secs(2),
        6,
    )
    .unwrap();
    let worker = thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                socket.read_exact(&mut b).unwrap();
                header.push(b[0]);
            }
            let header = String::from_utf8(header).unwrap();
            assert!(header.contains("Authorization: Basic dXNlcjpwYXNz\r\n"));
            let length: usize = header
                .split("\r\n")
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            requests.push(json::parse(&body, 16 * 1024 * 1024, 64).unwrap());
            // Fragment headers and body across writes; client must not assume read boundaries.
            for part in reply.as_bytes().chunks(7) {
                if socket.write_all(part).is_err() {
                    break;
                }
            }
        }
        requests
    });
    (rpc, worker)
}
fn ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn height_includes_genesis_hash_reverses_and_fee_is_exact() {
    let (rpc, worker) = server(vec![
        ok(r#"{"id":1,"error":null,"result":0}"#),
        ok(
            r#"{"id":1,"error":null,"result":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}"#,
        ),
        ok(r#"{"id":1,"error":null,"result":{"feerate":0.00001001,"blocks":6}}"#),
        ok(r#"{"id":1,"error":null,"result":{"errors":["Insufficient data"],"blocks":0}}"#),
    ]);
    assert_eq!(rpc.block_count().unwrap(), 1);
    assert_eq!(
        rpc.block_hash(0).unwrap(),
        std::array::from_fn(|i| (31 - i) as u8)
    );
    assert_eq!(rpc.fee_rate().unwrap(), Some(1001));
    assert_eq!(rpc.fee_rate().unwrap(), None);
    let requests = worker.join().unwrap();
    assert_eq!(
        requests[0].get("method").unwrap().as_str(),
        Some("getblockcount")
    );
    assert_eq!(
        json::encode(requests[1].get("params").unwrap()).unwrap(),
        b"[0]"
    );
    assert_eq!(
        json::encode(requests[2].get("params").unwrap()).unwrap(),
        b"[6,\"CONSERVATIVE\"]"
    );
}
#[test]
fn invalid_framing_rpc_identity_and_numeric_responses_fail() {
    for reply in [
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n0".to_owned(),
        "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n".to_owned(),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_owned(),
        ok(r#"{"id":2,"error":null,"result":1}"#),
        ok(r#"{"id":1,"error":{"code":-1},"result":1}"#),
        ok(r#"{"id":1,"error":null,"result":18446744073709551615}"#),
        ok(r#"{"id":1,"error":null,"result":1.0}"#),
        ok(r#"{"id":1,"error":null,"result":1,"result":2}"#),
    ] {
        let (rpc, worker) = server(vec![reply]);
        assert!(rpc.block_count().is_err());
        worker.join().unwrap();
    }
}
#[test]
fn body_truncation_and_shutdown_do_not_produce_observations() {
    let (rpc, worker) = server(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_owned(),
    ]);
    assert!(rpc.block_count().is_err());
    worker.join().unwrap();
    rpc.request_shutdown();
    assert!(rpc.wait_for_count(1).is_err());
    assert!(rpc.block_count().is_err());
}
#[test]
fn rejects_remote_plaintext_invalid_auth_and_fractional_satoshis() {
    assert!(
        CoreRpc::new(
            "192.0.2.1:8332".parse().unwrap(),
            "u:p",
            Duration::from_secs(1),
            6
        )
        .is_err()
    );
    assert!(
        CoreRpc::new(
            "127.0.0.1:8332".parse().unwrap(),
            "u:p\r\nx",
            Duration::from_secs(1),
            6
        )
        .is_err()
    );
    let (rpc, worker) = server(vec![ok(
        r#"{"id":1,"error":null,"result":{"feerate":0.000000001}}"#,
    )]);
    assert!(rpc.fee_rate().is_err());
    worker.join().unwrap();
}

#[test]
fn block_bytes_and_broadcast_result_are_bound_to_requested_hashes() {
    use minimint_ng::{
        bitcoin::{self, OutPoint, Transaction, TxIn, TxOut, Txid},
        codec::text,
    };
    let transaction = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid([5; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: u32::MAX,
            witness: vec![],
        }],
        outputs: vec![TxOut {
            value_sat: 10000,
            script_pubkey: vec![0x51],
        }],
        lock_time: 0,
    };
    let mut block = vec![3; 80];
    block.push(1);
    block.extend(transaction.encode());
    let expected = bitcoin::double_sha256(&[3; 80]);
    let block_reply = ok(&format!(
        r#"{{"id":1,"error":null,"result":"{}"}}"#,
        text::hex_encode(&block)
    ));
    let tx_reply = ok(&format!(
        r#"{{"id":1,"error":null,"result":"{}"}}"#,
        transaction.txid().display_hex()
    ));
    let (rpc, worker) = server(vec![
        block_reply.clone(),
        block_reply,
        tx_reply,
        ok(
            r#"{"id":1,"error":null,"result":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
        ),
    ]);
    assert_eq!(
        rpc.block(expected).unwrap().transactions,
        [transaction.clone()]
    );
    assert!(rpc.block([0; 32]).is_err());
    rpc.broadcast(&transaction).unwrap();
    assert!(rpc.broadcast(&transaction).is_err());
    let requests = worker.join().unwrap();
    assert_eq!(
        requests[0]["params"][0].as_str(),
        Some(Txid(expected).display_hex().as_str())
    );
    assert_eq!(
        requests[2]["params"][0].as_str(),
        Some(text::hex_encode(&transaction.encode()).as_str())
    );
}

#[test]
fn malformed_fee_container_is_not_an_unavailable_estimate() {
    for result in ["null", "[]", "\"unavailable\"", "3"] {
        let (rpc, worker) = server(vec![ok(&format!(
            r#"{{"id":1,"error":null,"result":{result}}}"#
        ))]);
        assert!(rpc.fee_rate().is_err());
        worker.join().unwrap();
    }
}
