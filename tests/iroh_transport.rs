//! Local Iroh transport evidence: NET-002 guardian streams over Iroh 1.0.3,
//! API-002 request streams over Iroh 0.35.0, and a four-guardian Iroh setup
//! (checksum, 42 G2 DKGs, key exchange) with restart. Discovery and relays are
//! disabled; direct loopback addresses are supplied as explicit overrides.
use minimint_ng::{
    api::{
        iroh::{CallError, IrohApiClient, IrohApiServer, decode_request, encode_response},
        rpc::{Request, RpcError},
        server::{CallContext, Handler},
        setup::GenerationJob,
    },
    config::{BitcoinNetwork, CanonicalUrl, SetupEndpoints, SetupRecord},
    daemon::lifecycle::{self, AdvertisedEndpoints, ExpectedTransport, SetupPlan},
    net::{
        PeerNetwork, TransportError,
        envelope::Envelope,
        iroh::{IrohIdentity, IrohOptions, MAX_P2P_MESSAGE_BYTES},
    },
    protocol::PeerId,
    setup::{self, GenerationInputs},
    storage::Store,
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;

fn udp_address() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn identities(n: usize) -> Vec<IrohIdentity> {
    (0..n).map(|_| IrohIdentity::generate().unwrap()).collect()
}
fn wait(deadline: Duration, mut ready: impl FnMut() -> bool) {
    let end = Instant::now() + deadline;
    while !ready() {
        assert!(Instant::now() < end, "Iroh test deadline");
        thread::sleep(Duration::from_millis(10));
    }
}
/// Local overrides for every guardian's P2P key (and API key when given).
fn overrides(pairs: impl IntoIterator<Item = ([u8; 32], SocketAddr)>) -> IrohOptions {
    IrohOptions {
        discovery: false,
        addresses: pairs.into_iter().collect(),
    }
}

#[test]
fn identity_seed_and_address_file_formats() {
    let identity = IrohIdentity::generate().unwrap();
    let secrets = identity.secret_bytes();
    let hex = minimint_ng::codec::text::hex_encode(secrets.as_slice());
    let imported = IrohIdentity::from_hex(&hex.to_ascii_uppercase()).unwrap();
    assert_eq!(imported.api_public(), identity.api_public());
    assert_eq!(imported.p2p_public(), identity.p2p_public());
    assert_ne!(identity.api_public(), identity.p2p_public());
    assert!(IrohIdentity::from_hex(&hex[..126]).is_err());
    assert!(IrohIdentity::from_hex(&format!("{}{}", &hex[..64], &hex[..64])).is_err());
    // RFC 8032 test vector 1: the seed determines the Ed25519 public key.
    let seed: [u8; 32] = minimint_ng::codec::text::hex_decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let vector = IrohIdentity::from_secret_bytes(&seed, &[1; 32]).unwrap();
    assert_eq!(
        minimint_ng::codec::text::hex_encode(&vector.api_public()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let key = minimint_ng::codec::text::hex_encode(&identity.p2p_public());
    let parsed =
        IrohOptions::parse_addresses(format!("{{\"{key}\":\"127.0.0.1:9\"}}").as_bytes()).unwrap();
    assert_eq!(
        parsed[&identity.p2p_public()],
        "127.0.0.1:9".parse().unwrap()
    );
    for invalid in [
        "[]".to_owned(),
        format!("{{\"{key}\":\"localhost:9\"}}"),
        format!("{{\"{}\":\"127.0.0.1:9\"}}", &key[..62]),
        format!("{{\"{key}\":9}}"),
    ] {
        assert!(
            IrohOptions::parse_addresses(invalid.as_bytes()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn iroh_api_url_form_and_derived_client_endpoints() {
    let key = [0xab; 32];
    let url = CanonicalUrl::iroh(&key);
    assert_eq!(url.as_str(), format!("iroh://{}", "ab".repeat(32)));
    assert_eq!(CanonicalUrl::simple(url.as_str()).unwrap(), url);
    assert_eq!(url.iroh_key(), Some(key));
    for invalid in [
        format!("iroh://{}/", "ab".repeat(32)),
        format!("iroh://{}", "AB".repeat(32)),
        format!("iroh://{}", "ab".repeat(31)),
        "iroh://".to_owned(),
    ] {
        assert!(CanonicalUrl::simple(&invalid).is_err(), "{invalid}");
    }
    assert!(
        CanonicalUrl::simple("ws://127.0.0.1:9/")
            .unwrap()
            .iroh_key()
            .is_none()
    );
}

#[test]
fn api_envelope_decoding_is_exact_and_maps_module_methods() {
    let request = decode_request(
        br#"{"method":{"Core":"session_count"},"request":{"auth":null,"params":null}}"#,
    )
    .unwrap();
    assert_eq!(request.method, "session_count");
    assert!(request.params.is_null());
    assert!(request.require_admin("secret").is_err());
    let request = decode_request(
        br#"{"method":{"Module":[1,"block_count"]},"request":{"auth":"secret","params":[7]}}"#,
    )
    .unwrap();
    assert_eq!(request.method, "module_1_block_count");
    assert!(request.require_admin("secret").is_ok());
    assert_eq!(request.params, json!([7]));
    for malformed in [
        &br#"{"method":{"Core":"x"}}"#[..],
        br#"{"method":{"Core":"x"},"request":{"auth":null}}"#,
        br#"{"method":{"Core":1},"request":{"auth":null,"params":null}}"#,
        br#"{"method":{"Module":[70000,"x"]},"request":{"auth":null,"params":null}}"#,
        br#"{"method":{"Core":"x","Module":[0,"y"]},"request":{"auth":null,"params":null}}"#,
        br#"{"method":{"Core":"x"},"request":{"auth":1,"params":null}}"#,
        br#"{"method":{"Core":"x"},"request":{"auth":null,"params":null},"id":1}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"x","params":[]}"#,
    ] {
        assert!(decode_request(malformed).is_none());
    }
    assert_eq!(encode_response(Ok(json!(3))), json!({"Ok":3}));
    assert_eq!(
        encode_response(Err(RpcError::METHOD)),
        json!({"Err":{"code":-32601,"message":"Method not found"}})
    );
}

struct Echo;
impl Handler for Echo {
    fn handle(&self, request: &Request, context: &CallContext<'_>) -> Result<Value, RpcError> {
        assert!(!context.is_cancelled());
        match request.method.as_str() {
            "admin" => request
                .require_admin("admin-secret")
                .map(|()| json!("authorized")),
            "slow" => {
                while !context.is_cancelled() {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(RpcError::INTERNAL)
            }
            method => Ok(json!({"method": method, "params": request.params.clone()})),
        }
    }
}

#[test]
fn iroh_api_serves_request_streams_and_client_reuses_connection() {
    let identity = IrohIdentity::generate().unwrap();
    let address = udp_address();
    let options = overrides([(identity.api_public(), address)]);
    let server = IrohApiServer::start(&identity, address, &options, Arc::new(Echo)).unwrap();
    let client = IrohApiClient::new(options).unwrap();
    let deadline = || Instant::now() + Duration::from_secs(20);
    let key = identity.api_public();
    let reply = client
        .call(
            &key,
            "session_count",
            json!(null),
            deadline(),
            1 << 20,
            &|| false,
        )
        .unwrap();
    assert_eq!(reply, json!({"method":"session_count","params":null}));
    let reply = client
        .call(
            &key,
            "module_0_note_spent",
            json!([1, 2]),
            deadline(),
            1 << 20,
            &|| false,
        )
        .unwrap();
    assert_eq!(
        reply,
        json!({"method":"module_0_note_spent","params":[1,2]})
    );
    // The client sends no credential: administrator methods are rejected.
    assert_eq!(
        client.call(&key, "admin", json!(null), deadline(), 1 << 20, &|| false),
        Err(CallError::Rejected)
    );
    // Local cancellation abandons one request without breaking the connection.
    let start = Instant::now();
    assert_eq!(
        client.call(&key, "slow", json!(null), deadline(), 1 << 20, &|| start
            .elapsed()
            > Duration::from_millis(200)),
        Err(CallError::Cancelled)
    );
    assert_eq!(
        client
            .call(&key, "after", json!(1), deadline(), 1 << 20, &|| false)
            .unwrap()["method"]
            .as_str(),
        Some("after")
    );
    // A response larger than the caller's bound fails closed.
    assert_eq!(
        client.call(
            &key,
            "bounded",
            json!("x".repeat(512)),
            deadline(),
            64,
            &|| false
        ),
        Err(CallError::Transport)
    );
    client.close();
    server.shutdown().unwrap();
}

#[test]
fn iroh_peer_network_connects_all_pairs_in_fifo_order_with_body_limit() {
    let ids = identities(4);
    let binds: Vec<_> = (0..4).map(|_| udp_address()).collect();
    let keys: BTreeMap<_, _> = ids
        .iter()
        .enumerate()
        .map(|(p, identity)| (PeerId(p as u16), identity.p2p_public()))
        .collect();
    let options = overrides(
        ids.iter()
            .map(|i| i.p2p_public())
            .zip(binds.iter().copied()),
    );
    let networks: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(p, identity)| {
            PeerNetwork::start_iroh(
                PeerId(p as u16),
                identity,
                keys.clone(),
                binds[p],
                options.clone(),
                64,
            )
            .unwrap()
        })
        .collect();
    wait(Duration::from_secs(30), || {
        networks.iter().enumerate().all(|(p, network)| {
            (0..4)
                .filter(|q| *q != p)
                .all(|q| network.connected(PeerId(q as u16)))
        })
    });
    for (p, network) in networks.iter().enumerate() {
        for q in (0..4).filter(|q| *q != p) {
            for n in 0..10 {
                network
                    .send(
                        PeerId(q as u16),
                        Envelope::SessionIndex((p * 100 + n) as u64),
                    )
                    .unwrap();
            }
        }
    }
    for (q, network) in networks.iter().enumerate() {
        let mut received: BTreeMap<u16, Vec<u64>> = BTreeMap::new();
        while received.values().map(Vec::len).sum::<usize>() < 30 {
            let (peer, message) = network
                .recv_timeout(Duration::from_secs(20))
                .unwrap()
                .expect("guardian message");
            let Envelope::SessionIndex(index) = message else {
                panic!("unexpected envelope");
            };
            received.entry(peer.0).or_default().push(index);
        }
        for (peer, indices) in received {
            assert_ne!(usize::from(peer), q);
            let base = u64::from(peer) * 100;
            assert_eq!(indices, (base..base + 10).collect::<Vec<_>>());
        }
    }
    // NET-002: a body above 10,000,000 bytes is never sent; one below passes.
    let too_large = Envelope::SetupExchange(vec![7; MAX_P2P_MESSAGE_BYTES]);
    assert!(matches!(
        networks[0].send(PeerId(1), too_large),
        Err(TransportError::FrameTooLarge)
    ));
    let large = vec![9; 9_000_000];
    networks[0]
        .send(PeerId(1), Envelope::SetupExchange(large.clone()))
        .unwrap();
    let (peer, message) = networks[1]
        .recv_timeout(Duration::from_secs(30))
        .unwrap()
        .expect("large message");
    assert_eq!(peer, PeerId(0));
    assert!(matches!(message, Envelope::SetupExchange(bytes) if bytes == large));
    // A local identity that is not the configured key for its ID is rejected.
    let stranger = IrohIdentity::generate().unwrap();
    assert!(
        PeerNetwork::start_iroh(
            PeerId(0),
            &stranger,
            keys.clone(),
            udp_address(),
            options,
            8
        )
        .is_err()
    );
    for network in networks {
        network.shutdown().unwrap();
    }
}

fn iroh_jobs(ids: &[IrohIdentity]) -> Vec<GenerationJob> {
    let n = ids.len();
    let records: BTreeMap<_, _> = {
        let mut records: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(p, identity)| SetupRecord {
                name: format!("Guardian {p:02}"),
                endpoints: SetupEndpoints::Iroh {
                    api_key: identity.api_public(),
                    p2p_key: identity.p2p_public(),
                },
                federation_name: (p == 0).then(|| "Iroh federation".into()),
                disable_base_fees: None,
                enabled_modules: None,
                federation_size: (p == 0).then_some(n as u32),
                network: BitcoinNetwork::Regtest,
                release: "0.13.0".into(),
            })
            .collect();
        records.sort();
        records
            .into_iter()
            .enumerate()
            .map(|(p, record)| (PeerId(p as u16), record))
            .collect()
    };
    ids.iter()
        .map(|identity| {
            let peer = *records
                .iter()
                .find(|(_, record)| {
                    record.endpoints
                        == SetupEndpoints::Iroh {
                            api_key: identity.api_public(),
                            p2p_key: identity.p2p_public(),
                        }
                })
                .unwrap()
                .0;
            GenerationJob {
                inputs: GenerationInputs {
                    peer,
                    records: records.clone(),
                },
                identity: identity.clone().into(),
            }
        })
        .collect()
}

#[test]
fn iroh_four_guardian_setup_commits_iroh_map_and_restarts() {
    let ids = identities(4);
    let jobs = iroh_jobs(&ids);
    let binds: BTreeMap<PeerId, SocketAddr> = jobs
        .iter()
        .map(|job| (job.inputs.peer, udp_address()))
        .collect();
    let options = overrides(
        jobs.iter()
            .map(|job| {
                let SetupEndpoints::Iroh { p2p_key, .. } =
                    job.inputs.records[&job.inputs.peer].endpoints
                else {
                    unreachable!()
                };
                (p2p_key, binds[&job.inputs.peer])
            })
            .collect::<Vec<_>>(),
    );
    let dirs: Vec<_> = (0..4).map(|_| fixture::TestDir::new()).collect();
    let tcp = AdvertisedEndpoints {
        api: CanonicalUrl::simple("ws://127.0.0.1:9/").unwrap(),
        p2p: CanonicalUrl::simple("fedimint://127.0.0.1:9/").unwrap(),
    };
    let mut peers = vec![];
    let generations: Vec<_> = jobs
        .into_iter()
        .zip(&dirs)
        .map(|(job, dir)| {
            let peer = job.inputs.peer;
            peers.push(peer);
            let store = Store::open(dir.path()).unwrap();
            let plan = SetupPlan::new(job, ExpectedTransport::Iroh).unwrap();
            assert!(plan.is_iroh() && plan.peer_urls().is_empty());
            plan.start_iroh(store, binds[&peer], options.clone(), 256)
                .unwrap()
        })
        .collect();
    wait(Duration::from_secs(120), || {
        generations
            .iter()
            .all(|generation| generation.is_finished())
    });
    let ready: Vec<_> = generations
        .into_iter()
        .map(|generation| generation.finish().unwrap())
        .collect();
    let server = ready[0].config.server_config().clone();
    assert!(server.api_endpoints.is_empty() && server.tls_certificates.is_empty());
    assert_eq!(server.iroh_endpoints.len(), 4);
    let client = server.client_config();
    for (peer, endpoint) in &client.api_endpoints {
        let iroh = &server.iroh_endpoints[peer];
        assert_eq!(endpoint.url, CanonicalUrl::iroh(&iroh.api_key));
        assert_eq!(endpoint.name, iroh.name);
    }
    for ready in &ready {
        assert_eq!(ready.config.server_config(), &server);
        assert!(ready.config.is_iroh() && ready.config.tls_config().is_none());
        assert!(ready.config.remote_peer_urls().is_empty());
    }
    for ready in ready {
        Arc::try_unwrap(ready.network)
            .ok()
            .unwrap()
            .shutdown()
            .unwrap();
    }
    // Restart all four from storage over the same bound UDP addresses.
    let restored: Vec<_> = dirs
        .iter()
        .zip(&peers)
        .map(|(dir, peer)| {
            let store = Store::open(dir.path()).unwrap();
            let loaded = setup::load_generated(&store).unwrap().unwrap();
            assert!(loaded.identity.iroh().is_some());
            // A TCP restart of an Iroh federation fails closed.
            assert!(lifecycle::load(&store, &tcp).is_err());
            let restored = lifecycle::load(&store, ExpectedTransport::Iroh)
                .unwrap()
                .unwrap();
            restored
                .connect_iroh(binds[peer], options.clone(), 64)
                .unwrap()
        })
        .collect();
    wait(Duration::from_secs(30), || {
        restored.iter().all(|ready| {
            let local = ready.config.peer();
            (0..4)
                .map(PeerId)
                .filter(|peer| *peer != local)
                .all(|peer| ready.network.connected(peer))
        })
    });
    for ready in restored {
        Arc::try_unwrap(ready.network)
            .ok()
            .unwrap()
            .shutdown()
            .unwrap();
    }
}
