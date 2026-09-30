use minimint_ng::{
    codec::{
        ConsensusEncode,
        text::{hex_decode, hex_encode},
    },
    core::history::{HistoryError, HistoryVerifier, SignaturePolicy, header, merkle_root},
    crypto::secp::SecretKey,
    protocol::{AcceptedItem, ConsensusItem, PeerId, SessionOutcome, SignedSessionOutcome},
};
use std::collections::BTreeMap;

fn keys() -> (Vec<SecretKey>, HistoryVerifier) {
    let keys: Vec<_> = (1..=4)
        .map(|i| {
            let mut bytes = [0; 32];
            bytes[31] = i;
            SecretKey::from_bytes(&bytes).unwrap()
        })
        .collect();
    let public = keys
        .iter()
        .enumerate()
        .map(|(i, key)| (PeerId(i as u16), key.public_key()))
        .collect();
    (keys, HistoryVerifier::new(public).unwrap())
}
fn outcome() -> SessionOutcome {
    SessionOutcome {
        items: vec![AcceptedItem {
            item: ConsensusItem::Unknown {
                tag: 17,
                payload: vec![1, 2],
            },
            peer: PeerId(2),
        }],
    }
}
#[test]
fn published_opaque_merkle_fixture_and_header_endianness() {
    assert_eq!(header(0, &SessionOutcome { items: vec![] }), [0; 40]);
    let root = merkle_root([[0u8], [1], [2]]);
    assert_eq!(
        hex_encode(&root),
        "f2dcdd96791b6bac5d554f2d320e594b834f5da1981812c3707e7772234cb0ad"
    );
    let value = outcome();
    let h = header(0x0102030405060708, &value);
    assert_eq!(&h[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        &h[8..],
        minimint_ng::crypto::sha256(&value.items[0].consensus_encode())
    );
    let mut changed = value.clone();
    changed.items[0].peer = PeerId(1);
    assert_ne!(header(7, &value), header(7, &changed));
    assert_eq!(merkle_root(Vec::<Vec<u8>>::new()), [0; 32]);
    assert_ne!(
        merkle_root([[0u8], [1], [2]]),
        merkle_root([[2u8], [1], [0]])
    );
    assert_eq!(hex_decode("0000000000000007").unwrap(), 7u64.to_be_bytes());
}
#[test]
fn three_of_four_adoption_all_subsets_and_invalid_extra() {
    let (keys, verifier) = keys();
    let value = outcome();
    let all: BTreeMap<_, _> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let peer = PeerId(i as u16);
            (peer, verifier.sign(7, &value, peer, key).unwrap())
        })
        .collect();
    for omitted in 0..4 {
        let mut signed = SignedSessionOutcome {
            outcome: value.clone(),
            signatures: all.clone(),
        };
        signed.signatures.remove(&PeerId(omitted));
        verifier
            .verify(7, &signed, SignaturePolicy::GuardianAdoption)
            .unwrap();
        assert!(
            verifier
                .verify(8, &signed, SignaturePolicy::Generic)
                .is_err()
        );
        signed.signatures.pop_first();
        assert_eq!(
            verifier.verify(7, &signed, SignaturePolicy::Generic),
            Err(HistoryError::WrongSignatureCount)
        );
    }
    let mut signed = SignedSessionOutcome {
        outcome: value,
        signatures: all,
    };
    verifier
        .verify(7, &signed, SignaturePolicy::Generic)
        .unwrap();
    assert_eq!(
        verifier.verify(7, &signed, SignaturePolicy::GuardianAdoption),
        Err(HistoryError::WrongSignatureCount)
    );
    signed.signatures.get_mut(&PeerId(3)).unwrap()[0] ^= 1;
    assert_eq!(
        verifier.verify(7, &signed, SignaturePolicy::Generic),
        Err(HistoryError::InvalidSignature)
    );
    signed.signatures.remove(&PeerId(3));
    signed.signatures.insert(PeerId(99), [0; 64]);
    assert_eq!(
        verifier.verify(7, &signed, SignaturePolicy::Generic),
        Err(HistoryError::InvalidSigner)
    );
}
#[test]
fn key_set_and_local_identity_are_bound() {
    let (keys, verifier) = keys();
    let value = outcome();
    // Independently calculated with Python hashlib from literal E(key map),
    // E(accepted item)=1102010202 and the BE64 session index; not baseline output.
    let singleton =
        HistoryVerifier::new(BTreeMap::from([(PeerId(0), keys[0].public_key())])).unwrap();
    assert_eq!(
        hex_encode(&singleton.digest(7, &value)),
        "20f85a7a0e85058e81b0d17f216a45e09e954d00d7b6a9260045990ba7687978"
    );
    assert_eq!(
        verifier.sign(0, &value, PeerId(1), &keys[0]),
        Err(HistoryError::InvalidSigner)
    );
    let wrong = HistoryVerifier::new(BTreeMap::from([(PeerId(0), keys[1].public_key())])).unwrap();
    let signature = verifier.sign(0, &value, PeerId(0), &keys[0]).unwrap();
    assert!(
        wrong
            .verify_signature(0, &value, PeerId(0), &signature)
            .is_err()
    );
    assert!(HistoryVerifier::new(BTreeMap::new()).is_err());
    assert!(HistoryVerifier::new(BTreeMap::from([(PeerId(1), keys[0].public_key())])).is_err());
}
