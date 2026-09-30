//! Long guardian-only process evidence, with Bitcoin deliberately unavailable.
//! Run: cargo test --test four_daemon_process -- --ignored --nocapture
//! Ordinary generated R=3600 and default d=50ms are not overridden.
#![cfg(unix)]
use minimint_ng::{
    codec::{rpc, text::hex_encode},
    core::{
        history::{HistoryVerifier, SignaturePolicy, header},
        session::{persisted_status, session_count},
        transaction::transaction_id,
    },
    crypto::sha256,
    protocol::{
        ConsensusItem, PeerId, SessionStatusV2, SignedSessionOutcome, Transaction,
        TransactionError, TransactionSignatures,
    },
    setup,
    storage::Store,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};
use std::{
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/process/mod.rs"]
mod process_fixture;
use process_fixture::{Harness, Rpc};
fn signed(rpc: &mut Rpc, index: u64) -> SignedSessionOutcome {
    let encoded = rpc.call("await_signed_session_outcome", json!(index), false);
    let strings: Vec<_> = encoded
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    rpc::decode_hex(&strings).unwrap()
}
fn count(rpc: &mut Rpc) -> u64 {
    minimint_ng::json::unsigned(&rpc.call("session_count", json!(null), false)).unwrap()
}
fn transaction(n: u8) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [n; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    }
}
#[test]
#[ignore = "ordinary four-process session boundary takes several minutes; explicit 600-second integration run"]
fn four_fresh_daemons_complete_signed_history_and_restart_peer_catches_up() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(600);
    let mut harnesses: Vec<_> = (0..4).map(|_| Harness::new()).collect();
    let mut daemons: Vec<_> = harnesses.iter_mut().map(|h| Some(h.spawn())).collect();
    let mut rpcs: Vec<_> = daemons
        .iter_mut()
        .map(|d| Some(d.as_mut().unwrap().connect()))
        .collect();
    let mut codes = vec![];
    for (index, rpc) in rpcs.iter_mut().enumerate() {
        let params = if index == 0 {
            json!({"name":"Guardian 00","federation_name":"Four new process fixture","federation_size":4})
        } else {
            json!({"name":format!("Guardian {index:02}")})
        };
        codes.push(rpc.as_mut().unwrap().call("set_local_params", params, true));
    }
    for (index, rpc) in rpcs.iter_mut().enumerate() {
        for (peer, code) in codes.iter().enumerate() {
            if peer != index {
                rpc.as_mut()
                    .unwrap()
                    .call("add_peer_setup_code", code.clone(), true);
            }
        }
    }
    for rpc in &mut rpcs {
        rpc.as_mut().unwrap().call("start_dkg", json!(null), true);
    }
    for rpc in &mut rpcs {
        rpc.as_mut().unwrap().wait_running();
    }
    eprintln!(
        "four-daemon milestone: actual four-peer DKG and running handoff in {:?}",
        started.elapsed()
    );
    let mut ids = vec![];
    for (index, rpc) in rpcs.iter_mut().enumerate() {
        let tx = transaction(100 + index as u8);
        let id = transaction_id(&tx);
        ids.push(id);
        assert_eq!(
            rpc.as_mut()
                .unwrap()
                .call("submit_transaction", json!(rpc::hex(&tx)), false),
            json!(rpc::hex(&Ok::<_, TransactionError>(id)))
        );
    }
    for rpc in &mut rpcs {
        for id in &ids {
            assert_eq!(
                rpc.as_mut()
                    .unwrap()
                    .call("await_transaction", json!(hex_encode(id)), false),
                json!(hex_encode(id))
            );
        }
    }
    assert!(rpcs.iter_mut().all(|rpc| count(rpc.as_mut().unwrap()) == 0));
    // Guardian 3 has all four effects but has not completed session zero. Keep it
    // offline while the remaining quorum crosses the ordinary round boundary.
    daemons[3].as_mut().unwrap().terminate("-TERM");
    drop(rpcs[3].take());
    drop(daemons[3].take());
    let store = Store::open(harnesses[3].data()).unwrap();
    let generated = setup::load_generated(&store).unwrap().unwrap();
    assert_eq!(generated.generated.server.rounds_per_session, 3600);
    let verifier =
        HistoryVerifier::new(generated.generated.server.broadcast_public_keys.clone()).unwrap();
    assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 0);
    assert!(!store.read_agreement(0).unwrap().is_empty());
    let Some(SessionStatusV2::Pending(pending)) =
        persisted_status(&store.snapshot().unwrap(), 0).unwrap()
    else {
        panic!("stopped guardian lacks durable prefix")
    };
    assert_eq!(pending.len(), 4);
    drop(generated);
    drop(store);
    eprintln!(
        "four-daemon milestone: all four distinct transactions accepted; guardian 3 stopped with durable prefix/backup at {:?}",
        started.elapsed()
    );
    let mut last_report = Instant::now();
    loop {
        assert!(
            Instant::now() < deadline,
            "ordinary session completion exceeded 600-second test bound"
        );
        for daemon in daemons.iter_mut().take(3) {
            daemon.as_mut().unwrap().assert_running();
        }
        let counts: Vec<_> = rpcs
            .iter_mut()
            .take(3)
            .map(|r| count(r.as_mut().unwrap()))
            .collect();
        if counts.iter().all(|n| *n >= 1) {
            break;
        }
        if last_report.elapsed() >= Duration::from_secs(15) {
            eprintln!(
                "four-daemon progress: elapsed {:?}, surviving session counts {:?}",
                started.elapsed(),
                counts
            );
            last_report = Instant::now();
        }
        thread::sleep(Duration::from_millis(500));
    }
    let histories: Vec<_> = rpcs
        .iter_mut()
        .take(3)
        .map(|r| signed(r.as_mut().unwrap(), 0))
        .collect();
    for history in &histories {
        verifier
            .verify(0, history, SignaturePolicy::GuardianAdoption)
            .unwrap();
        assert_eq!(history.outcome.items, pending);
        assert_eq!(history.signatures.len(), 3);
        assert!(!history.signatures.contains_key(&PeerId(3)));
        for (index, item) in history.outcome.items.iter().enumerate() {
            assert_eq!(item.peer, PeerId(index as u16));
            let ConsensusItem::Transaction(tx) = &item.item else {
                panic!("unexpected module/monetary transition in empty transaction fixture")
            };
            assert_eq!(transaction_id(tx), ids[index]);
        }
    }
    let header_hash = hex_encode(&sha256(&header(0, &histories[0].outcome)));
    eprintln!(
        "four-daemon milestone: quorum completed ordinary session 0 at {:?}; SHA256(header)={header_hash}",
        started.elapsed()
    );
    daemons[3] = Some(harnesses[3].spawn());
    rpcs[3] = Some(daemons[3].as_mut().unwrap().connect());
    let catchup_started = Instant::now();
    loop {
        assert!(
            Instant::now() < deadline && catchup_started.elapsed() < Duration::from_secs(45),
            "restarted guardian failed history catch-up"
        );
        for daemon in &mut daemons {
            daemon.as_mut().unwrap().assert_running();
        }
        if count(rpcs[3].as_mut().unwrap()) >= 1 {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let recovered = signed(rpcs[3].as_mut().unwrap(), 0);
    verifier
        .verify(0, &recovered, SignaturePolicy::GuardianAdoption)
        .unwrap();
    assert_eq!(recovered.outcome, histories[0].outcome);
    eprintln!(
        "four-daemon milestone: restarted guardian caught up in {:?}; matching SHA256(header)={header_hash}",
        catchup_started.elapsed()
    );
    for daemon in &mut daemons {
        daemon.as_mut().unwrap().terminate("-TERM");
    }
    drop(rpcs);
    drop(daemons);
    for harness in &harnesses {
        let store = Store::open(harness.data()).unwrap();
        assert_eq!(session_count(&store.snapshot().unwrap()).unwrap(), 1);
        assert!(store.read_agreement(0).unwrap().is_empty());
    }
    eprintln!(
        "four-daemon evidence complete in {:?}; Bitcoin unavailable, empty transactions only",
        started.elapsed()
    );
}
