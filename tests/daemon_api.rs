//! Real socket routing into the real single-guardian ordered runtime. This does
//! not establish four-guardian or upstream interoperability.
use minimint_ng::{
    api::{
        backup::{BackupTimestamp, SignedBackup},
        server::Server,
        websocket::{Limits, Message, WebSocket},
    },
    codec::{rpc, text::hex_encode},
    config::{ApiVersions, CoreSupport, ModuleSupport, SupportSummary},
    core::transaction::{accepted_output_modules, transaction_id},
    daemon::{
        consensus::{Runtime, RuntimeOptions},
        service::{RunningApi, RunningApiOptions, Service},
    },
    net::PeerNetwork,
    protocol::{PeerId, Transaction, TransactionSignatures},
    storage::Store,
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::{
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[path = "fixtures/runtime/mod.rs"]
mod runtime_fixture;
#[path = "fixtures/storage/mod.rs"]
mod storage_fixture;

fn receive(ws: &mut WebSocket) -> Value {
    let Message::Text(text) = ws.receive().unwrap() else {
        panic!("text response");
    };
    minimint_ng::json::parse(text.as_bytes(), 65536, 64).unwrap()
}
fn send(ws: &mut WebSocket, id: u64, method: &str, params: Value, auth: Option<&str>) {
    let request = json!({"jsonrpc":"2.0", "id":id, "method":method,
        "params":[{"auth":auth,"params":params}]});
    ws.send_text(std::str::from_utf8(&minimint_ng::json::encode(&request).unwrap()).unwrap())
        .unwrap();
}
#[test]
fn running_routes_acceptance_concurrent_waits_and_admin_boundary() {
    let dir = storage_fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = runtime_fixture::configs(1, 3600, std::slice::from_ref(&listener))
        .pop()
        .unwrap();
    let network = Arc::new(
        PeerNetwork::start(
            PeerId(0),
            config.tls_config(),
            config.resolve_peer_addresses().unwrap(),
            listener,
            64,
        )
        .unwrap(),
    );
    let (runtime, handle) = Runtime::start(
        store.clone(),
        config.clone(),
        network.clone(),
        Arc::new(runtime_fixture::Backend::new()),
        RuntimeOptions::default(),
    )
    .unwrap();
    // Empty advertisements are deliberately confined to this routing test. It
    // cannot certify the missing diagnostic/schema endpoints at any API minor.
    let server_config = config.server_config().clone();
    let support = SupportSummary {
        core: CoreSupport {
            core_consensus: server_config.consensus_version,
            api: ApiVersions { versions: vec![] },
        },
        modules: server_config
            .modules
            .iter()
            .map(|(id, module)| {
                (
                    *id,
                    ModuleSupport {
                        core_consensus: server_config.consensus_version,
                        module_consensus: module.version,
                        api: ApiVersions { versions: vec![] },
                    },
                )
            })
            .collect(),
    };
    let running = Arc::new(
        RunningApi::new(
            handle.clone(),
            RunningApiOptions {
                software_identity: "minimint-ng/test".into(),
                support,
                access_secret: Some(Zeroizing::new("transport".into())),
                admin_secret: Zeroizing::new("admin".into()),
            },
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let limits = Limits {
        operation_timeout: Duration::from_secs(5),
        ..Limits::default()
    };
    let service = Arc::new(Service::restored(running.clone()));
    assert!(service.install(running).is_err());
    let server = Server::start(
        listener,
        service,
        Some(Zeroizing::new("transport".into())),
        limits,
        4,
    )
    .unwrap();
    let mut ws = WebSocket::connect(
        TcpStream::connect(address).unwrap(),
        &address.to_string(),
        "/",
        Some("transport"),
        limits,
    )
    .unwrap();

    send(&mut ws, 1, "setup_status", json!(null), None);
    assert_eq!(
        receive(&mut ws)["result"].as_str(),
        Some("ConsensusIsRunning")
    );
    send(&mut ws, 101, "client_config_json", json!(null), None);
    let diagnostic = receive(&mut ws);
    assert_eq!(
        diagnostic["result"]["global"]["consensus_version"]["major"].as_u64(),
        Some(2)
    );
    assert_eq!(
        diagnostic["result"]["modules"]["0"]["kind"].as_str(),
        Some("mintv2")
    );
    assert_eq!(
        diagnostic["result"]["modules"]["1"]["kind"].as_str(),
        Some("walletv2")
    );
    send(&mut ws, 102, "client_config_json", json!({}), None);
    assert_eq!(receive(&mut ws)["error"]["code"].as_i64(), Some(-32602));
    assert!(!handle.is_stopped());
    send(&mut ws, 2, "module_0_recovery_count", json!(null), None);
    assert_eq!(receive(&mut ws)["result"].as_u64(), Some(0));
    send(&mut ws, 3, "module_99_recovery_count", json!(null), None);
    assert_eq!(receive(&mut ws)["error"]["code"].as_i64(), Some(-32601));
    send(
        &mut ws,
        4,
        "sign_api_announcement",
        json!(null),
        Some("transport"),
    );
    assert_eq!(receive(&mut ws)["error"]["code"].as_i64(), Some(401));
    send(
        &mut ws,
        5,
        "sign_api_announcement",
        json!(null),
        Some("admin"),
    );
    assert_eq!(receive(&mut ws)["error"]["code"].as_i64(), Some(500));
    assert!(!handle.is_stopped());

    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [29; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    let txid = transaction_id(&tx);
    assert!(
        accepted_output_modules(&store.snapshot().unwrap(), &txid)
            .unwrap()
            .is_none()
    );
    send(
        &mut ws,
        6,
        "await_transaction",
        json!(hex_encode(&txid)),
        None,
    );
    send(&mut ws, 7, "submit_transaction", json!(rpc::hex(&tx)), None);
    let mut replies = vec![receive(&mut ws), receive(&mut ws)];
    replies.sort_by_key(|reply| reply["id"].as_u64().unwrap());
    assert_eq!(replies[0]["id"].as_u64(), Some(6));
    assert_eq!(
        replies[0]["result"].as_str(),
        Some(hex_encode(&txid).as_str())
    );
    assert_eq!(replies[1]["id"].as_u64(), Some(7));
    assert_eq!(
        replies[1]["result"],
        json!(rpc::hex(&Ok::<_, minimint_ng::protocol::TransactionError>(
            txid
        )))
    );
    assert_eq!(
        accepted_output_modules(&store.snapshot().unwrap(), &txid).unwrap(),
        Some(vec![])
    );

    let mut duplicate = tx.clone();
    duplicate.signatures = TransactionSignatures::Schnorr(vec![[9; 64]]);
    send(
        &mut ws,
        10,
        "submit_transaction",
        json!(rpc::hex(&duplicate)),
        None,
    );
    assert_eq!(receive(&mut ws)["result"], replies[1]["result"]);

    let backup_key = runtime_fixture::key(42);
    let mut backup = SignedBackup {
        id: backup_key.public_key(),
        payload: vec![0, 255, 19],
        timestamp: BackupTimestamp {
            secs_since_epoch: 1,
            nanos_since_epoch: 0,
        },
        signature: [0; 64],
    };
    backup.signature = backup_key.schnorr_sign(&backup.digest()).unwrap();
    send(
        &mut ws,
        11,
        "backup",
        json!({"id":hex_encode(&backup.id),
        "payload":hex_encode(&backup.payload), "timestamp":backup.timestamp.json(),
        "signature":hex_encode(&backup.signature)}),
        None,
    );
    let uploaded = receive(&mut ws);
    assert!(uploaded.get("result").is_some_and(|v| v.is_null()));
    send(&mut ws, 12, "recover", json!(hex_encode(&backup.id)), None);
    assert_eq!(
        receive(&mut ws)["result"],
        json!({"timestamp":backup.timestamp.json(), "data":"00ff13"})
    );

    // Pending long poll must not prevent another request on this connection,
    // and listener shutdown must cancel and join that waiting call promptly.
    send(
        &mut ws,
        8,
        "await_transaction",
        json!(hex_encode(&[255; 32])),
        None,
    );
    send(&mut ws, 9, "api_announcements", json!(null), None);
    assert_eq!(receive(&mut ws)["id"].as_u64(), Some(9));
    let before = Instant::now();
    server.shutdown().unwrap();
    assert!(before.elapsed() < Duration::from_secs(2));
    runtime.shutdown().unwrap();
    Arc::try_unwrap(network).ok().unwrap().shutdown().unwrap();
}
