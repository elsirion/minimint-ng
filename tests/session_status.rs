use minimint_ng::{
    codec::{ConsensusEncode, decode_whole},
    protocol::{
        AcceptedItem, ConsensusItem, PeerId, SessionOutcome, SessionStatus, SessionStatusV2,
        SignedSessionOutcome,
    },
};
use std::collections::BTreeMap;
#[test]
fn independent_literal_status_envelopes_and_legacy_conversion() {
    assert_eq!(SessionStatus::Initial.consensus_encode(), [0, 0]);
    assert_eq!(SessionStatusV2::Initial.consensus_encode(), [0, 0]);
    assert_eq!(
        SessionStatusV2::Pending(vec![]).consensus_encode(),
        [1, 1, 0]
    );
    let item = AcceptedItem {
        item: ConsensusItem::Unknown {
            tag: 17,
            payload: vec![0xaa],
        },
        peer: PeerId(3),
    };
    // status tag1, body5bytes; list1; core tag17 body1 aa; peer3.
    let pending = SessionStatusV2::Pending(vec![item.clone()]);
    assert_eq!(pending.consensus_encode(), [1, 5, 1, 17, 1, 0xaa, 3]);
    assert_eq!(
        decode_whole::<SessionStatusV2>(&[1, 5, 1, 17, 1, 0xaa, 3]).unwrap(),
        pending
    );
    let outcome = SessionOutcome { items: vec![item] };
    let signed = SignedSessionOutcome {
        outcome: outcome.clone(),
        signatures: BTreeMap::from([(PeerId(0), [0x55; 64])]),
    };
    let v2 = SessionStatusV2::Complete(signed);
    let mut expected = vec![2, 71, 1, 17, 1, 0xaa, 3, 1, 0];
    expected.extend([0x55; 64]);
    assert_eq!(v2.consensus_encode(), expected);
    assert_eq!(
        SessionStatus::from(v2).consensus_encode(),
        [2, 5, 1, 17, 1, 0xaa, 3]
    );
    assert_eq!(
        SessionStatus::Complete(outcome).consensus_encode(),
        [2, 5, 1, 17, 1, 0xaa, 3]
    );
}
#[test]
fn status_unknown_tags_bad_lengths_and_trailing_data_are_rejected() {
    for bytes in [
        &[3, 0][..],
        &[0, 1, 0],
        &[0, 0, 0],
        &[1, 0],
        &[2, 0],
        &[1, 2, 0, 0],
    ] {
        assert!(decode_whole::<SessionStatus>(&bytes).is_err());
        assert!(decode_whole::<SessionStatusV2>(&bytes).is_err());
    }
    assert_eq!(
        decode_whole::<SessionStatus>(&[2, 1, 0]).unwrap(),
        SessionStatus::Complete(SessionOutcome { items: vec![] })
    );
    assert!(decode_whole::<SessionStatusV2>(&[2, 1, 0]).is_err());
    assert_eq!(
        SessionStatusV2::Complete(SignedSessionOutcome {
            outcome: SessionOutcome { items: vec![] },
            signatures: BTreeMap::new()
        })
        .consensus_encode(),
        [2, 2, 0, 0]
    );
}
#[test]
fn completed_status_contains_only_the_index_bound_outcome_certificate() {
    use minimint_ng::{
        core::history::{HistoryVerifier, SignaturePolicy},
        crypto::secp::SecretKey,
    };
    let mut bytes = [0; 32];
    bytes[31] = 1;
    let secret = SecretKey::from_bytes(&bytes).unwrap();
    let verifier =
        HistoryVerifier::new(BTreeMap::from([(PeerId(0), secret.public_key())])).unwrap();
    let outcome = SessionOutcome { items: vec![] };
    let signature = verifier.sign(7, &outcome, PeerId(0), &secret).unwrap();
    let status = SessionStatusV2::Complete(SignedSessionOutcome {
        outcome,
        signatures: BTreeMap::from([(PeerId(0), signature)]),
    });
    let decoded: SessionStatusV2 = decode_whole(&status.consensus_encode()).unwrap();
    let SessionStatusV2::Complete(signed) = decoded else {
        panic!("wrong status")
    };
    verifier
        .verify(7, &signed, SignaturePolicy::Generic)
        .unwrap();
    assert!(
        verifier
            .verify(8, &signed, SignaturePolicy::Generic)
            .is_err()
    );
    // Signing the status envelope is a different message and cannot replace CON003.
    let envelope_digest = minimint_ng::crypto::sha256(&status.consensus_encode());
    assert!(
        minimint_ng::crypto::secp::schnorr_verify(
            &minimint_ng::crypto::secp::x_only(&secret.public_key()).unwrap(),
            &envelope_digest,
            &signature
        )
        .is_err()
    );
}
