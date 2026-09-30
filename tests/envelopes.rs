use minimint_ng::{
    crypto::bls::{G1, G2, Scalar},
    net::envelope::{DkgMessage, Envelope},
};
#[test]
fn literal_common_and_legacy_envelopes() {
    assert_eq!(
        Envelope::SessionIndex(7).encode_common().unwrap(),
        [2, 1, 7]
    );
    assert_eq!(
        Envelope::SessionIndex(7).encode_legacy().unwrap(),
        [2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        Envelope::Agreement(vec![0xaa, 0xbb])
            .encode_common()
            .unwrap(),
        [0, 3, 2, 0xaa, 0xbb]
    );
    assert_eq!(
        Envelope::SignedSessionOutcome(vec![0xaa, 0xbb])
            .encode_common()
            .unwrap(),
        [3, 3, 2, 0xaa, 0xbb]
    );
    let legacy = Envelope::SignedSessionOutcome(vec![0xaa, 0xbb])
        .encode_legacy()
        .unwrap();
    assert_eq!(&legacy[..12], &[3, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&legacy[12..], b"02aabb");
    let mut expected = vec![1, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0];
    expected.extend([5; 64]);
    assert_eq!(
        Envelope::SessionSignature([5; 64]).encode_legacy().unwrap(),
        expected
    );
}
#[test]
fn all_variants_roundtrip_and_legacy_suffix() {
    let values = [
        Envelope::Agreement(vec![1, 2]),
        Envelope::SessionSignature([3; 64]),
        Envelope::SessionIndex(65536),
        Envelope::SignedSessionOutcome(vec![4, 5]),
        Envelope::Checksum([6; 32]),
        Envelope::DkgG1(DkgMessage::Hash([7; 32])),
        Envelope::DkgG1(DkgMessage::Commitments(vec![
            G1::identity(),
            G1::generator(),
        ])),
        Envelope::DkgG2(DkgMessage::Commitments(vec![G2::generator()])),
        Envelope::DkgG2(DkgMessage::Share(Scalar::from_u64(5))),
        Envelope::SetupExchange(vec![8, 9]),
        Envelope::Unknown {
            tag: 42,
            payload: vec![10, 11],
        },
    ];
    for value in values {
        let common = value.encode_common().unwrap();
        assert_eq!(
            Envelope::decode(&common).unwrap().encode_common().unwrap(),
            common
        );
        let mut legacy = value.encode_legacy().unwrap();
        assert_eq!(
            Envelope::decode(&legacy).unwrap().encode_common().unwrap(),
            common
        );
        legacy.extend([0xff, 0xee]);
        assert_eq!(
            Envelope::decode(&legacy).unwrap().encode_common().unwrap(),
            common
        );
    }
}
#[test]
fn common_priority_and_malformed_inner_objects() {
    // Common unknown variant 8 wins outright, preserving its empty payload.
    assert_eq!(
        Envelope::decode(&[8, 0]).unwrap().encode_common().unwrap(),
        [8, 0]
    );
    assert!(Envelope::decode(&[1, 1, 0]).is_err());
    let mut short_signature = vec![1, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0];
    short_signature.extend([0; 63]);
    assert!(Envelope::decode(&short_signature).is_err());
    // Common outer G1 DKG, inner share scalar r (noncanonical).
    let mut scalar = vec![5, 34, 2, 32];
    scalar.extend([255; 32]);
    assert!(Envelope::decode(&scalar).is_err());
    let mut point = vec![5, 51, 1, 49, 1];
    point.extend([0; 48]);
    assert!(Envelope::decode(&point).is_err());
    let mut invalid_hex = vec![6, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
    invalid_hex.extend(b"zz");
    assert!(Envelope::decode(&invalid_hex).is_err());
    assert!(
        Envelope::Unknown {
            tag: 1,
            payload: vec![]
        }
        .encode_common()
        .is_err()
    );
}
