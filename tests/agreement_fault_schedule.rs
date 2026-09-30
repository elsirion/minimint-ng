//! Opaque-message faults on one link and a separately bounded all-link window.
//! Packet ordinal fixes the fault action; native packet contents are opaque.
//! No native protocol inspection or process restart is part of this scenario.
#[path = "fixtures/storage/mod.rs"]
mod fixture;
use minimint_ng::{
    agreement::{Data, EngineIo, EngineSession, FinalizedUnit, GuardianKeychain, ProposalQueue},
    codec::decode_whole,
    crypto::secp::SecretKey,
    protocol::{ConsensusItem, DynamicValue, ModuleId, PeerId, Transaction, TransactionSignatures},
    storage::Store,
};
use std::{
    collections::BTreeMap,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Default)]
struct Link {
    seen: usize,
    held: Option<Vec<u8>>,
}
struct Federation {
    engines: Vec<EngineSession>,
    io: Vec<EngineIo>,
    queues: Vec<ProposalQueue>,
    links: BTreeMap<(usize, usize), Link>,
    histories: Vec<Vec<FinalizedUnit>>,
    reliable: bool,
    dropped: usize,
    reversed: usize,
    all_links: bool,
}
impl Federation {
    fn new(stores: &[Store], all_links: bool) -> Self {
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
            .map(|(id, secret)| (PeerId(id as u16), secret.public_key()))
            .collect();
        let mut federation = Self {
            engines: vec![],
            io: vec![],
            queues: vec![],
            links: BTreeMap::new(),
            histories: vec![vec![]; 4],
            reliable: false,
            dropped: 0,
            reversed: 0,
            all_links,
        };
        for (id, secret) in secrets.into_iter().enumerate() {
            let (queue, provider) = ProposalQueue::new(32).unwrap();
            let keychain = GuardianKeychain::new(PeerId(id as u16), secret, keys.clone()).unwrap();
            // Explicit test profile. No production R=3600/50ms claim.
            let (engine, io) =
                EngineSession::start(keychain, stores[id].clone(), 91, 128, 20, provider, 4096)
                    .unwrap();
            federation.engines.push(engine);
            federation.io.push(io);
            federation.queues.push(queue);
        }
        federation
    }
    fn deliver(&mut self, target: usize, payload: Vec<u8>) {
        // Incidental congestion is a test failure, never silently another fault.
        self.io[target]
            .inbound
            .try_send(payload)
            .expect("scheduled delivery queue unexpectedly unavailable");
    }
    fn route(&mut self, source: usize, target: usize, payload: Vec<u8>) {
        if self.reliable || (!self.all_links && (source, target) != (0, 1)) || source == target {
            self.deliver(target, payload);
            return;
        }
        let link = self.links.entry((source, target)).or_default();
        link.seen += 1;
        match link.seen {
            1 => self.dropped += 1,
            2 => link.held = Some(payload),
            3 => {
                let earlier = link.held.take().expect("second packet must be held");
                self.deliver(target, payload);
                self.deliver(target, earlier);
                self.reversed += 1;
            }
            _ => self.deliver(target, payload),
        }
    }
    fn tick(&mut self) {
        // Fixed source visitation; faults depend only on each directed link's
        // ordinal, not payload bytes, engine rounds, wall time or a random seed.
        for source in 0..4 {
            for _ in 0..128 {
                let Ok(message) = self.io[source].outbound.try_recv() else {
                    break;
                };
                if let Some(peer) = message.recipient {
                    self.route(source, usize::from(peer.0), message.payload);
                } else {
                    for target in 0..4 {
                        if target != source {
                            self.route(source, target, message.payload.clone());
                        }
                    }
                }
            }
        }
        for (io, history) in self.io.iter().zip(&mut self.histories) {
            history.extend(io.finalized.try_iter());
        }
        let length = self.histories.iter().map(Vec::len).min().unwrap();
        for history in &self.histories[1..] {
            assert_eq!(
                &history[..length],
                &self.histories[0][..length],
                "finalized prefixes disagree"
            );
        }
    }
    fn until(&mut self, deadline: Instant, done: impl Fn(&Self) -> bool) {
        while !done(self) {
            assert!(
                Instant::now() < deadline,
                "fault-schedule progress deadline"
            );
            assert!(
                self.engines.iter().all(|engine| !engine.is_finished()),
                "native engine stopped unexpectedly"
            );
            self.tick();
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn shutdown(mut self) {
        // Keep all EngineIo consumers alive while each engine awaits its workers.
        let results: Vec<_> = self
            .engines
            .drain(..)
            .map(EngineSession::shutdown)
            .collect();
        assert!(
            results.iter().all(Result::is_ok),
            "engine shutdown failed: {results:?}"
        );
    }
}
impl Drop for Federation {
    fn drop(&mut self) {
        for engine in self.engines.drain(..) {
            let _ = engine.shutdown();
        }
    }
}
fn transaction(peer: u8) -> ConsensusItem {
    ConsensusItem::Transaction(Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [peer; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    })
}
fn repeated(peer: u8) -> ConsensusItem {
    ConsensusItem::Module(DynamicValue {
        module_id: ModuleId(300),
        payload: vec![peer, 77],
    })
}
fn proposal_counts(history: &[FinalizedUnit]) -> ([usize; 4], [usize; 4]) {
    let (mut transactions, mut modules) = ([0; 4], [0; 4]);
    for unit in history {
        if let Some(Data::Batch(bytes)) = &unit.data {
            // Decode only public application data, never opaque engine messages.
            for item in decode_whole::<Vec<ConsensusItem>>(bytes).unwrap() {
                let peer = usize::from(unit.creator.0);
                if item == transaction(peer as u8) {
                    transactions[peer] += 1;
                } else if item == repeated(peer as u8) {
                    modules[peer] += 1;
                } else {
                    panic!("unexpected public proposal");
                }
            }
        }
    }
    (transactions, modules)
}
#[test]
fn fault_schedule_child() {
    let Ok(mode) = std::env::var("MINIMINT_ALEPH_FAULT_CHILD") else {
        return;
    };
    let all_links = mode == "all";
    let directories: Vec<_> = (0..4).map(|_| fixture::TestDir::new()).collect();
    let stores: Vec<_> = directories
        .iter()
        .map(|dir| Store::open(dir.path()).unwrap())
        .collect();
    let mut federation = Federation::new(&stores, all_links);
    let deadline = Instant::now() + Duration::from_secs(35);
    let mut flushed = 0;
    if all_links {
        // Unlike the original failed harness, release does not depend on
        // producing a third packet or making consensus progress. A fixed
        // transport outage ends and releases every held packet after two seconds.
        let restore = Instant::now() + Duration::from_secs(2);
        while Instant::now() < restore {
            federation.tick();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(federation.links.len(), 12);
        assert_eq!(federation.dropped, 12);
        let held: Vec<_> = federation
            .links
            .iter_mut()
            .filter_map(|((_, target), link)| link.held.take().map(|payload| (*target, payload)))
            .collect();
        flushed = held.len();
        // Count every scheduled second packet, whether reversed with packet3
        // or released at restoration. No missing held packet may be forgotten.
        assert_eq!(
            federation.reversed + flushed,
            federation
                .links
                .values()
                .filter(|link| link.seen >= 2)
                .count()
        );
        federation.reliable = true;
        for (target, payload) in held {
            federation.deliver(target, payload);
        }
        federation.until(deadline, |f| {
            f.histories.iter().all(|history| history.len() >= 16)
        });
    } else {
        federation.until(deadline, |f| {
            f.links.len() == 1
                && f.links.values().all(|link| link.seen >= 3)
                && f.histories.iter().all(|history| history.len() >= 16)
        });
        assert_eq!(federation.dropped, 1);
        assert_eq!(federation.reversed, 1);
    }
    assert!(federation.links.values().all(|link| link.held.is_none()));
    assert!(
        federation
            .histories
            .iter()
            .all(|history| history.iter().all(|unit| unit.data.is_none()))
    );
    federation.reliable = true;
    let before = federation.histories.iter().map(Vec::len).max().unwrap();
    for (peer, queue) in federation.queues.iter().enumerate() {
        for _ in 0..2 {
            queue.push(transaction(peer as u8)).unwrap();
            queue.push(repeated(peer as u8)).unwrap();
        }
    }
    federation.until(deadline, |f| {
        f.histories.iter().all(|history| {
            history.len() >= before + 48 && proposal_counts(history) == ([1; 4], [2; 4])
        })
    });
    // Requeue an already proposed transaction after it has finalized. It must
    // not reappear; repeated nontransaction module data intentionally did.
    for (peer, queue) in federation.queues.iter().enumerate() {
        queue.push(transaction(peer as u8)).unwrap();
        // FIFO marker proves this provider actually consumed the duplicate,
        // rather than merely finalizing unrelated already-created units.
        queue.push(repeated(peer as u8)).unwrap();
    }
    let after = federation.histories.iter().map(Vec::len).max().unwrap();
    federation.until(deadline, |f| {
        f.histories.iter().all(|history| {
            history.len() >= after + 32 && proposal_counts(history) == ([1; 4], [3; 4])
        })
    });
    for history in &federation.histories {
        assert_eq!(proposal_counts(history), ([1; 4], [3; 4]));
        assert!(history.iter().any(|unit| unit.data.is_none()));
    }
    let faults = (federation.dropped, federation.reversed, flushed);
    federation.shutdown();
    assert!(
        stores
            .iter()
            .all(|store| !store.read_agreement(91).unwrap().is_empty())
    );
    eprintln!(
        "schedule={mode}: drops={}, reversed_pairs={}, restoration_flushes={}; reliable progress and four joined engines",
        faults.0, faults.1, faults.2
    );
}
fn scenario(mode: &str) {
    // A process boundary bounds even a broken native shutdown. All workers are
    // threads in this owned child: timeout kills/reaps it, leaving no routers.
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fault_schedule_child", "--nocapture"])
            .env("MINIMINT_ALEPH_FAULT_CHILD", mode)
            .spawn()
            .unwrap(),
    );
    let end = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "fault-schedule subprocess failed: {status}"
            );
            break;
        }
        assert!(
            Instant::now() < end,
            "fault-schedule subprocess timeout; guard kills and reaps"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn four_engines_recover_from_deterministic_drop_and_reorder() {
    scenario("single");
}
#[test]
fn all_links_restore_on_deadline_independent_of_finalization() {
    scenario("all");
}
