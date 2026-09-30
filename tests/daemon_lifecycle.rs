use minimint_ng::{
    api::setup::GenerationJob,
    config::{BitcoinNetwork, CanonicalUrl, SetupEndpoints, SetupRecord},
    daemon::lifecycle::{self, AdvertisedEndpoints, LifecycleError, SetupPlan},
    net::{envelope::Envelope, tls::Identity},
    protocol::PeerId,
    setup::{self, GenerationInputs, SetupDefaults, SetupError, SetupTransport},
    storage::Store,
};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn url(s: &str) -> CanonicalUrl {
    CanonicalUrl::simple(s).unwrap()
}
fn jobs(n: u16, addresses: &BTreeMap<PeerId, SocketAddr>) -> Vec<GenerationJob> {
    let identities: Vec<_> = (0..n)
        .map(|p| Identity::generate(&format!("Guardian {p:02}")).unwrap())
        .collect();
    let records: BTreeMap<_, _> = identities
        .iter()
        .enumerate()
        .map(|(p, identity)| {
            (
                PeerId(p as u16),
                SetupRecord {
                    name: format!("Guardian {p:02}"),
                    endpoints: SetupEndpoints::Tcp {
                        api_url: url(&format!("ws://127.0.0.1:{}/", 10000 + p)),
                        p2p_url: url(&format!("fedimint://{}/", addresses[&PeerId(p as u16)])),
                        certificate: identity.certificate_der().unwrap(),
                    },
                    federation_name: (p == 0).then(|| "Federation".into()),
                    disable_base_fees: None,
                    enabled_modules: None,
                    federation_size: (p == 0).then_some(u32::from(n)),
                    network: BitcoinNetwork::Regtest,
                    release: "0.13.0".into(),
                },
            )
        })
        .collect();
    identities
        .into_iter()
        .enumerate()
        .map(|(p, identity)| GenerationJob {
            inputs: GenerationInputs {
                peer: PeerId(p as u16),
                records: records.clone(),
            },
            identity,
        })
        .collect()
}
fn expected(job: &GenerationJob) -> AdvertisedEndpoints {
    let SetupEndpoints::Tcp {
        api_url, p2p_url, ..
    } = &job.inputs.records[&job.inputs.peer].endpoints
    else {
        unreachable!()
    };
    AdvertisedEndpoints {
        api: api_url.clone(),
        p2p: p2p_url.clone(),
    }
}
fn listeners(n: u16) -> (Vec<TcpListener>, BTreeMap<PeerId, SocketAddr>) {
    let listeners: Vec<_> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses = listeners
        .iter()
        .enumerate()
        .map(|(p, l)| (PeerId(p as u16), l.local_addr().unwrap()))
        .collect();
    (listeners, addresses)
}
fn wait(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !ready() {
        assert!(Instant::now() < deadline, "generation deadline");
        thread::sleep(Duration::from_millis(5));
    }
}
fn close(ready: lifecycle::ReadyRuntime) {
    Arc::try_unwrap(ready.network)
        .ok()
        .expect("generation retained network reference")
        .shutdown()
        .unwrap();
}
struct NoTransport;
impl SetupTransport for NoTransport {
    fn wait_for_all(&mut self, _: &[PeerId]) -> Result<(), SetupError> {
        panic!("n1 transport")
    }
    fn send(&mut self, _: PeerId, _: Envelope) -> Result<(), SetupError> {
        panic!("n1 transport")
    }
    fn receive_from(&mut self, _: PeerId) -> Result<Envelope, SetupError> {
        panic!("n1 transport")
    }
}
#[test]
fn fresh_single_setup_is_durable_before_handoff_and_reopens_without_url_rewrite() {
    let (mut listeners, mut addresses) = listeners(1);
    let bound = listeners[0].local_addr().unwrap();
    addresses.insert(PeerId(0), "127.0.0.1:1".parse().unwrap()); // Advertised endpoint differs deliberately.
    let job = jobs(1, &addresses).remove(0);
    let expected = expected(&job);
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    assert!(lifecycle::load(&store, &expected).unwrap().is_none());
    let plan = SetupPlan::new(job, &expected).unwrap();
    assert!(plan.peer_urls().is_empty());
    let generation = plan
        .start(store.clone(), listeners.remove(0), BTreeMap::new(), 32)
        .unwrap();
    wait(|| generation.is_finished());
    let ready = generation.finish().unwrap();
    let public = ready.config.server_config().clone();
    assert_eq!(public.api_endpoints[&PeerId(0)].url, expected.api);
    assert!(setup::load_generated(&store).unwrap().is_some());
    close(ready);
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    let restored = lifecycle::load(&store, &expected).unwrap().unwrap();
    assert_eq!(restored.config().server_config(), &public);
    let rebound = TcpListener::bind(bound).unwrap();
    let ready = restored.connect(rebound, BTreeMap::new(), 32).unwrap();
    close(ready);
    let changed = AdvertisedEndpoints {
        api: url("ws://127.0.0.1:9998/"),
        p2p: expected.p2p,
    };
    assert!(matches!(
        lifecycle::load(&store, &changed),
        Err(LifecycleError::InvalidProfile)
    ));
}
#[test]
fn four_authenticated_generation_workers_finish_identical_public_config_and_persist_locals() {
    let (listeners, addresses) = listeners(4);
    let jobs = jobs(4, &addresses);
    let dirs: Vec<_> = (0..4).map(|_| fixture::TestDir::new()).collect();
    let stores: Vec<_> = dirs
        .iter()
        .map(|d| Store::open(d.path()).unwrap())
        .collect();
    let mut generations = vec![];
    for (p, (job, listener)) in jobs.into_iter().zip(listeners).enumerate() {
        let plan = SetupPlan::new(job, &expected_for(p, &addresses)).unwrap();
        let resolved = addresses
            .iter()
            .filter(|(id, _)| id.0 as usize != p)
            .map(|(p, a)| (*p, *a))
            .collect();
        generations.push(
            plan.start(stores[p].clone(), listener, resolved, 256)
                .unwrap(),
        );
    }
    wait(|| generations.iter().all(|g| g.is_finished()));
    let ready: Vec<_> = generations
        .into_iter()
        .map(|g| g.finish().unwrap())
        .collect();
    let public = ready[0].config.server_config().clone();
    for (p, r) in ready.iter().enumerate() {
        assert_eq!(r.config.server_config(), &public);
        assert_eq!(r.config.peer(), PeerId(p as u16));
        assert!(setup::load_generated(&stores[p]).unwrap().is_some());
        assert_eq!(
            r.config.session_config().unwrap().local_key.public_key(),
            public.broadcast_public_keys[&PeerId(p as u16)]
        );
    }
    for r in ready {
        close(r);
    }
}
fn expected_for(p: usize, addresses: &BTreeMap<PeerId, SocketAddr>) -> AdvertisedEndpoints {
    AdvertisedEndpoints {
        api: url(&format!("ws://127.0.0.1:{}/", 10000 + p)),
        p2p: url(&format!("fedimint://{}/", addresses[&PeerId(p as u16)])),
    }
}
#[test]
fn cancelling_missing_peer_setup_joins_and_leaves_no_partial_configuration() {
    let (mut listeners, addresses) = listeners(4);
    let job = jobs(4, &addresses).remove(0);
    let expected = expected(&job);
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let resolved = addresses
        .iter()
        .filter(|(p, _)| p.0 != 0)
        .map(|(p, a)| (*p, *a))
        .collect();
    let generation = SetupPlan::new(job, &expected)
        .unwrap()
        .start(store.clone(), listeners.remove(0), resolved, 32)
        .unwrap();
    thread::sleep(Duration::from_millis(30));
    assert!(!generation.is_finished());
    generation.shutdown().unwrap();
    assert!(setup::load_generated(&store).unwrap().is_none());
    // All listener/controller ownership was released, not detached.
    let _listener = TcpListener::bind(addresses[&PeerId(0)]).unwrap();
}
#[test]
fn resolved_membership_is_exact_and_profile_checks_precede_network_start() {
    let (mut listeners, addresses) = listeners(4);
    let job = jobs(4, &addresses).remove(0);
    let expected = expected(&job);
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let plan = SetupPlan::new(job, &expected).unwrap();
    assert_eq!(plan.peer_urls().len(), 3);
    assert!(matches!(
        plan.start(store, listeners.remove(0), BTreeMap::new(), 32),
        Err(LifecycleError::InvalidAddresses)
    ));
    let (mut listeners, addresses) = self::listeners(1);
    let job = jobs(1, &addresses).remove(0);
    let changed = AdvertisedEndpoints {
        api: url("ws://127.0.0.1:8888/"),
        p2p: self::expected(&job).p2p,
    };
    assert!(matches!(
        SetupPlan::new(job, &changed),
        Err(LifecycleError::InvalidProfile)
    ));
    let _listener = listeners.remove(0);
}
#[test]
fn fresh_and_restored_paths_both_reject_mainnet_and_secure_websocket_profiles() {
    for (network, scheme) in [
        (BitcoinNetwork::Mainnet, "ws"),
        (BitcoinNetwork::Regtest, "wss"),
    ] {
        let (_listeners, addresses) = listeners(1);
        let mut job = jobs(1, &addresses).remove(0);
        let record = job.inputs.records.get_mut(&PeerId(0)).unwrap();
        record.network = network;
        if let SetupEndpoints::Tcp { api_url, .. } = &mut record.endpoints {
            *api_url = url(&format!("{scheme}://127.0.0.1:10000/"));
        }
        let expected = expected(&job);
        let generated = setup::generate(
            job.inputs.peer,
            &job.inputs.records,
            &SetupDefaults::default(),
            &mut NoTransport,
        )
        .unwrap();
        let dir = fixture::TestDir::new();
        let store = Store::open(dir.path()).unwrap();
        setup::persist_generated(&store, &generated, &job.identity).unwrap();
        assert!(matches!(
            lifecycle::load(&store, &expected),
            Err(LifecycleError::InvalidProfile)
        ));
        assert!(matches!(
            SetupPlan::new(job, &expected),
            Err(LifecycleError::InvalidProfile)
        ));
    }
}
#[test]
fn setup_checksum_failure_joins_all_workers_without_persisting_any_identity() {
    let (listeners, addresses) = listeners(4);
    let mut jobs = jobs(4, &addresses);
    jobs[0]
        .inputs
        .records
        .get_mut(&PeerId(0))
        .unwrap()
        .federation_name = Some("Different federation".into());
    let dirs: Vec<_> = (0..4).map(|_| fixture::TestDir::new()).collect();
    let stores: Vec<_> = dirs
        .iter()
        .map(|d| Store::open(d.path()).unwrap())
        .collect();
    let mut generations = vec![];
    for (p, (job, listener)) in jobs.into_iter().zip(listeners).enumerate() {
        let expected = expected(&job);
        let plan = SetupPlan::new(job, &expected).unwrap();
        let resolved = addresses
            .iter()
            .filter(|(id, _)| id.0 as usize != p)
            .map(|(p, a)| (*p, *a))
            .collect();
        generations.push(
            plan.start(stores[p].clone(), listener, resolved, 256)
                .unwrap(),
        );
    }
    wait(|| generations.iter().all(|g| g.is_finished()));
    for (index, g) in generations.into_iter().enumerate() {
        g.request_shutdown(); // Cancellation must not mask an already failed checksum.
        let result = if index % 2 == 0 {
            g.finish().map(|_| ())
        } else {
            g.shutdown()
        };
        assert!(matches!(
            result,
            Err(LifecycleError::Setup(SetupError::ChecksumMismatch))
        ));
    }
    for store in stores {
        assert!(setup::load_generated(&store).unwrap().is_none());
    }
}

#[test]
fn resolved_addresses_cannot_silently_change_advertised_ports() {
    let (mut listeners, addresses) = listeners(4);
    let job = jobs(4, &addresses).remove(0);
    let plan = SetupPlan::new(job, &expected_for(0, &addresses)).unwrap();
    let mut resolved: BTreeMap<_, _> = addresses
        .iter()
        .filter(|(p, _)| p.0 != 0)
        .map(|(p, a)| (*p, *a))
        .collect();
    let address = resolved.get_mut(&PeerId(1)).unwrap();
    address.set_port(if address.port() == 1 { 2 } else { 1 });
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    assert!(matches!(
        plan.start(store, listeners.remove(0), resolved, 32),
        Err(LifecycleError::InvalidAddresses)
    ));
}
