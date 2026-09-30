//! Replay public black-box evidence without a reference binary or secret keys.
use minimint_ng::{
    codec::{
        rpc,
        text::{hex_decode, hex_encode},
    },
    core::history::{HistoryVerifier, SignaturePolicy, header},
    crypto::sha256,
    protocol::{PeerId, SignedSessionOutcome},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::{fs, path::PathBuf};

fn root(capture: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop")
        .join(capture)
}
fn read(capture: &str, name: &str) -> Value {
    minimint_ng::json::parse(
        &fs::read(root(capture).join(name)).unwrap(),
        1024 * 1024,
        64,
    )
    .unwrap()
}

fn verify_manifest(capture: &str) {
    let manifest = read(capture, "manifest.json");
    for (name, digest) in manifest["sha256"].as_object().unwrap() {
        assert_eq!(
            hex_encode(&sha256(&fs::read(root(capture).join(name)).unwrap())),
            digest.as_str().unwrap()
        );
    }
}

fn verify_capture(capture: &str, expected_header: &str, survivors: Option<&[u16]>) {
    verify_manifest(capture);
    let config = read(capture, "peer0-client_config.json");
    let keys = config["broadcast_public_keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(peer, key)| {
            (
                PeerId(peer.parse().unwrap()),
                hex_decode(key.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    let verifier = HistoryVerifier::new(keys).unwrap();
    assert_eq!(verifier.quorum(), 3);
    let mut common = None;
    for peer in 0..4 {
        let value = read(capture, &format!("peer{peer}-signed-session0.json"));
        let wrapper: Vec<_> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let history = rpc::decode_hex::<SignedSessionOutcome>(&wrapper).unwrap();
        verifier
            .verify(0, &history, SignaturePolicy::GuardianAdoption)
            .unwrap();
        if let Some(survivors) = survivors {
            assert_eq!(
                history
                    .signatures
                    .keys()
                    .map(|peer| peer.0)
                    .collect::<Vec<_>>(),
                survivors
            );
        }
        assert_eq!(history.outcome.items.len(), 12);
        assert_eq!(
            hex_encode(&sha256(&header(0, &history.outcome))),
            expected_header
        );
        if let Some(expected) = &common {
            assert_eq!(&history.outcome, expected);
        } else {
            common = Some(history.outcome.clone());
        }
        assert!(
            verifier
                .verify(1, &history, SignaturePolicy::GuardianAdoption)
                .is_err()
        );
        let mut changed = history.clone();
        changed.outcome.items.swap(0, 1);
        assert!(
            verifier
                .verify(0, &changed, SignaturePolicy::GuardianAdoption)
                .is_err()
        );
        let mut missing = history;
        missing.outcome.items.pop();
        assert!(
            verifier
                .verify(0, &missing, SignaturePolicy::GuardianAdoption)
                .is_err()
        );
    }
}

#[test]
fn captured_mixed_history_authenticates_all_four_certificates_and_rejects_changes() {
    verify_capture(
        "mixed-session-2026-09-10",
        "96a31a12e07acd28b48794844905454b729a401b59c81712063bceae00264e4a",
        None,
    );
}

#[test]
fn captured_survivor_sets_exclude_the_stopped_signer_and_authenticate_restart_history() {
    verify_capture(
        "mixed-failure-2026-09-10",
        "96a31a12e07acd28b48794844905454b729a401b59c81712063bceae00264e4a",
        Some(&[0, 2, 3]),
    );
    for (peer, survivors) in [(0, [1, 2, 3]), (2, [0, 1, 3]), (3, [0, 1, 2])] {
        verify_capture(
            &format!("mixed-outage-{peer}-2026-09-10"),
            "7373a636a8e06d65ae1b6730aa35e20adf9d5714c77e58d6f48f9c176602021e",
            Some(&survivors),
        );
    }
}

// These retained certificates authenticate eventual acceptance. The separate
// process transcript supplies bounded noncompletion, not an offline safety proof.
fn verify_restored_work(capture: &str, expected_header: &str) {
    verify_manifest(capture);
    let config = read(capture, "peer0-client_config.json");
    let keys = config["broadcast_public_keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(peer, key)| {
            (
                PeerId(peer.parse().unwrap()),
                hex_decode(key.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    let verifier = HistoryVerifier::new(keys).unwrap();
    let barrier = read(capture, "two-peer-barrier.json");
    assert_eq!(barrier["general_quorum_proof"].as_bool(), Some(false));
    assert!(barrier["observed_noncompletion_ms"].as_u64().unwrap() > 0);
    let fresh = hex_decode(barrier["fresh_transaction_id"].as_str().unwrap()).unwrap();
    assert_eq!(fresh.len(), 32);
    let mut common = None;
    for peer in 0..4 {
        for session in 0..=1 {
            let value = read(capture, &format!("peer{peer}-signed-session{session}.json"));
            let wrapper: Vec<_> = value
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            let history = rpc::decode_hex::<SignedSessionOutcome>(&wrapper).unwrap();
            verifier
                .verify(session, &history, SignaturePolicy::GuardianAdoption)
                .unwrap();
            let matches = history
                .outcome
                .items
                .iter()
                .filter(|item| {
                    matches!(&item.item, minimint_ng::protocol::ConsensusItem::Transaction(tx)
                    if minimint_ng::core::transaction::transaction_id(tx).as_slice() == fresh)
                })
                .count();
            assert_eq!(matches, session as usize);
            if session == 1 {
                assert_eq!(
                    hex_encode(&sha256(&header(1, &history.outcome))),
                    expected_header
                );
                if let Some(expected) = &common {
                    assert_eq!(&history.outcome, expected);
                } else {
                    common = Some(history.outcome.clone());
                }
                assert!(
                    verifier
                        .verify(0, &history, SignaturePolicy::GuardianAdoption)
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn captured_restored_quorum_accepts_fresh_work_once_in_the_next_signed_session() {
    verify_restored_work(
        "mixed-failure-2026-09-10",
        "491dd6ff3c912e9bbed0d7f704ea1774ce9308947e925dee5b2cd2db2b3e5099",
    );
}

#[test]
fn captured_inverse_assignment_authenticates_survivors_and_restored_fresh_work() {
    let capture = "mixed-inverse-2026-09-10";
    let artifacts = read(capture, "artifacts.json");
    let roles: Vec<_> = artifacts["guardian_implementations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        roles,
        ["reference", "reference", "independent", "independent"]
    );
    let barrier = read(capture, "two-peer-barrier.json");
    assert_eq!(barrier["inspected_independent_peer"].as_u64(), Some(3));
    verify_capture(
        capture,
        "686e6f17af4ce4fdae74228bfc0e8a419a688f2c623d0adc877a7d0d278c62ba",
        Some(&[0, 1, 3]),
    );
    verify_restored_work(
        capture,
        "4b5cea21d660987e887a16220b70c375ce0b80d6eaaff0dca004fac672fc485b",
    );
}
