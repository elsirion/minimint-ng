#[path = "fixtures/storage/mod.rs"]
mod fixture;
use futures::{StreamExt, executor::block_on};
use minimint_ng::{
    agreement::{EngineIo, EngineSession, FinalizedUnit, GuardianKeychain, ProposalQueue},
    crypto::secp::SecretKey,
    protocol::{ConsensusItem, DynamicValue, ModuleId, PeerId},
    storage::Store,
};
use std::{collections::BTreeMap, sync::mpsc, thread, time::Duration};
fn keychains() -> Vec<GuardianKeychain> {
    let secrets: Vec<_> = (1..=4)
        .map(|id| {
            let mut bytes = [0; 32];
            bytes[31] = id;
            SecretKey::from_bytes(&bytes).unwrap()
        })
        .collect();
    let keys: BTreeMap<_, _> = secrets
        .iter()
        .enumerate()
        .map(|(id, key)| (PeerId(id as u16), key.public_key()))
        .collect();
    secrets
        .into_iter()
        .enumerate()
        .map(|(id, key)| GuardianKeychain::new(PeerId(id as u16), key, keys.clone()).unwrap())
        .collect()
}
struct Federation {
    engines: Vec<EngineSession>,
    routers: Vec<thread::JoinHandle<()>>,
    finalized: Vec<mpsc::Receiver<FinalizedUnit>>,
}
impl Federation {
    fn start(stores: &[Store], phase: u8) -> Self {
        // Explicit shortened test profile; production defaults are R=3600,d=50ms.
        eprintln!("four-engine integration test profile: R=64, delay=20ms, phase={phase}");
        let mut engines = Vec::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut finalized = Vec::new();
        for (id, (keychain, store)) in keychains().into_iter().zip(stores).enumerate() {
            let (queue, provider) = ProposalQueue::new(32).unwrap();
            queue
                .push(ConsensusItem::Module(DynamicValue {
                    module_id: ModuleId(0),
                    payload: vec![id as u8, phase],
                }))
                .unwrap();
            let (
                engine,
                EngineIo {
                    inbound,
                    outbound,
                    finalized: events,
                },
            ) = EngineSession::start(keychain, store.clone(), 7, 64, 20, provider, 1024).unwrap();
            engines.push(engine);
            inputs.push(inbound);
            outputs.push(outbound);
            finalized.push(events);
        }
        let routers = outputs
            .into_iter()
            .enumerate()
            .map(|(source, mut output)| {
                let mut inputs = inputs.clone();
                thread::spawn(move || {
                    block_on(async move {
                        while let Some(message) = output.next().await {
                            match message.recipient {
                                Some(peer) => {
                                    let _ = inputs[usize::from(peer.0)].try_send(message.payload);
                                }
                                None => {
                                    for (target, input) in inputs.iter_mut().enumerate() {
                                        if target != source {
                                            let _ = input.try_send(message.payload.clone());
                                        }
                                    }
                                }
                            }
                        }
                    })
                })
            })
            .collect();
        Self {
            engines,
            routers,
            finalized,
        }
    }
    fn common_prefix(&self, length: usize) -> Vec<FinalizedUnit> {
        let histories: Vec<Vec<_>> = self
            .finalized
            .iter()
            .map(|receiver| {
                (0..length)
                    .map(|_| {
                        receiver
                            .recv_timeout(Duration::from_secs(25))
                            .expect("real engine failed to finalize in test deadline")
                    })
                    .collect()
            })
            .collect();
        for history in &histories[1..] {
            assert_eq!(history, &histories[0]);
        }
        histories.into_iter().next().unwrap()
    }
    fn shutdown(mut self) {
        for engine in self.engines.drain(..) {
            engine.shutdown().unwrap();
        }
        for router in self.routers.drain(..) {
            router.join().unwrap();
        }
    }
}
#[test]
fn four_real_engines_order_identically_and_restart_from_durable_backups() {
    let directories: Vec<_> = (0..4).map(|_| fixture::TestDir::new()).collect();
    let stores: Vec<_> = directories
        .iter()
        .map(|path| Store::open(path.path()).unwrap())
        .collect();
    let first = Federation::start(&stores, 0);
    let prefix = first.common_prefix(24);
    assert!(prefix.iter().any(|u| u.data.is_some()));
    assert!(prefix.iter().any(|u| u.data.is_none()));
    assert!(prefix.iter().all(|u| u.creator.0 < 4));
    first.shutdown();
    let backup_bytes: Vec<_> = stores
        .iter()
        .map(|s| s.read_agreement(7).unwrap())
        .collect();
    assert!(backup_bytes.iter().all(|bytes| !bytes.is_empty()));
    // After shutdown returns, every backup callback has completed. Reopening the
    // actual stores ensures the second native engine run loads persisted bytes.
    drop(stores);
    let stores: Vec<_> = directories
        .iter()
        .map(|path| Store::open(path.path()).unwrap())
        .collect();
    for (store, expected) in stores.iter().zip(&backup_bytes) {
        assert_eq!(&store.read_agreement(7).unwrap(), expected);
    }
    let second = Federation::start(&stores, 1);
    let replayed = second.common_prefix(24);
    assert_eq!(replayed, prefix);
    let continued = second.common_prefix(80);
    let mut new_proposers = std::collections::BTreeSet::new();
    for unit in &continued {
        if let Some(minimint_ng::agreement::Data::Batch(bytes)) = &unit.data {
            let items: Vec<ConsensusItem> = minimint_ng::codec::decode_whole(bytes).unwrap();
            for item in items {
                if let ConsensusItem::Module(value) = item
                    && value.payload.get(1) == Some(&1)
                {
                    new_proposers.insert(unit.creator);
                }
            }
        }
    }
    assert_eq!(
        new_proposers.len(),
        4,
        "fresh proposals from all restarted guardians must finalize"
    );
    second.shutdown();
    for (store, previous) in stores.iter().zip(backup_bytes) {
        let current = store.read_agreement(7).unwrap();
        assert!(current.starts_with(&previous));
        assert!(current.len() > previous.len());
    }
}

#[test]
fn losing_finalized_receiver_fails_session_and_awaits_components() {
    let directories: Vec<_> = (0..4).map(|_| fixture::TestDir::new()).collect();
    let stores: Vec<_> = directories
        .iter()
        .map(|path| Store::open(path.path()).unwrap())
        .collect();
    let mut federation = Federation::start(&stores, 2);
    drop(federation.finalized.remove(0));
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    while !federation.engines[0].is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "engine ignored loss of finalized consumer"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let failed = federation.engines.remove(0);
    assert!(failed.shutdown().is_err());
    federation.shutdown();
}

#[test]
fn invalid_persisted_native_backup_cannot_report_successful_completion() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    store.append_agreement(7, &[255, 255, 255]).unwrap();
    let (_, provider) = ProposalQueue::new(1).unwrap();
    let (engine, _io) =
        EngineSession::start(keychains().remove(0), store.clone(), 7, 64, 20, provider, 8).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(25);
    while !engine.is_finished() {
        assert!(
            std::time::Instant::now() < deadline,
            "native engine did not reject invalid backup"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(engine.shutdown().is_err());
    assert_eq!(store.read_agreement(7).unwrap(), [255, 255, 255]);
}
