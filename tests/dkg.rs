use minimint_ng::{
    codec::ConsensusEncode,
    crypto::{
        bls::{G2, Scalar},
        sha256,
    },
    net::envelope::DkgMessage,
    protocol::PeerId,
    setup::{G2Dkg, SetupError},
};
fn coefficients() -> Vec<Scalar> {
    vec![
        Scalar::from_u64(1),
        Scalar::from_u64(2),
        Scalar::from_u64(3),
    ]
}
fn commitments() -> Vec<G2> {
    coefficients()
        .iter()
        .map(|s| G2::generator().mul(s))
        .collect()
}
fn hash(points: &[G2]) -> [u8; 32] {
    sha256(
        &points
            .iter()
            .map(G2::to_bytes)
            .collect::<Vec<_>>()
            .consensus_encode(),
    )
}
#[test]
fn prerequisites_duplicates_wrong_sender_and_aborted_state() {
    let (mut state, actions) = G2Dkg::from_coefficients(PeerId(0), 4, coefficients()).unwrap();
    assert_eq!(actions.len(), 3);
    assert!(matches!(
        state.receive(PeerId(1), DkgMessage::Commitments(commitments())),
        Err(SetupError::MissingPrerequisite)
    ));
    assert!(matches!(
        state.receive(PeerId(1), DkgMessage::Hash(hash(&commitments()))),
        Err(SetupError::Aborted)
    ));
    let (mut state, _) = G2Dkg::from_coefficients(PeerId(0), 4, coefficients()).unwrap();
    assert!(matches!(
        state.receive(PeerId(4), DkgMessage::Hash([0; 32])),
        Err(SetupError::UnknownPeer)
    ));
    let (mut state, _) = G2Dkg::from_coefficients(PeerId(0), 4, coefficients()).unwrap();
    state
        .receive(PeerId(1), DkgMessage::Hash(hash(&commitments())))
        .unwrap();
    assert!(matches!(
        state.receive(PeerId(1), DkgMessage::Hash([0; 32])),
        Err(SetupError::Duplicate)
    ));
}
#[test]
fn commitment_hash_count_and_share_checks_are_exact() {
    let (mut state, _) = G2Dkg::from_coefficients(PeerId(0), 4, coefficients()).unwrap();
    state.receive(PeerId(1), DkgMessage::Hash([0; 32])).unwrap();
    assert!(matches!(
        state.receive(PeerId(1), DkgMessage::Commitments(commitments())),
        Err(SetupError::CommitmentMismatch)
    ));
    let (mut state, _) = G2Dkg::from_coefficients(PeerId(0), 4, coefficients()).unwrap();
    let short = vec![G2::generator()];
    state
        .receive(PeerId(1), DkgMessage::Hash(hash(&short)))
        .unwrap();
    assert!(matches!(
        state.receive(PeerId(1), DkgMessage::Commitments(short)),
        Err(SetupError::WrongCoefficientCount)
    ));
    let (mut state, _) = G2Dkg::from_coefficients(PeerId(0), 4, coefficients()).unwrap();
    state
        .receive(PeerId(1), DkgMessage::Hash(hash(&commitments())))
        .unwrap();
    state
        .receive(PeerId(1), DkgMessage::Commitments(commitments()))
        .unwrap();
    assert!(matches!(
        state.receive(PeerId(1), DkgMessage::Share(Scalar::from_u64(99))),
        Err(SetupError::InvalidShare)
    ));
}

#[test]
fn all_four_required_and_coordinates_are_peer_plus_one() {
    let (mut state, _) = G2Dkg::from_coefficients(PeerId(2), 4, coefficients()).unwrap();
    for peer in [0, 1] {
        assert!(
            state
                .receive(PeerId(peer), DkgMessage::Hash(hash(&commitments())))
                .unwrap()
                .is_empty()
        );
    }
    assert!(!state.is_complete());
    let actions = state
        .receive(PeerId(3), DkgMessage::Hash(hash(&commitments())))
        .unwrap();
    assert_eq!(actions.len(), 3);
    assert!(
        actions
            .iter()
            .all(|a| matches!(a.message, DkgMessage::Commitments(_)))
    );
    for peer in [0, 1] {
        assert!(
            state
                .receive(PeerId(peer), DkgMessage::Commitments(commitments()))
                .unwrap()
                .is_empty()
        );
    }
    let actions = state
        .receive(PeerId(3), DkgMessage::Commitments(commitments()))
        .unwrap();
    assert_eq!(actions.len(), 3);
    for action in actions {
        let DkgMessage::Share(value) = action.message else {
            panic!()
        };
        let x = u64::from(action.recipient.0) + 1;
        assert_eq!(
            value.to_bytes(),
            Scalar::from_u64(1 + 2 * x + 3 * x * x).to_bytes()
        );
    }
    for peer in [0, 1] {
        state
            .receive(PeerId(peer), DkgMessage::Share(Scalar::from_u64(34)))
            .unwrap();
    }
    assert!(!state.is_complete());
    state
        .receive(PeerId(3), DkgMessage::Share(Scalar::from_u64(34)))
        .unwrap();
    assert!(state.is_complete());
    let result = state.finish().unwrap();
    assert_eq!(
        result.secret_share.to_bytes(),
        Scalar::from_u64(136).to_bytes()
    );
    assert_eq!(
        result
            .public_coefficients
            .iter()
            .map(G2::to_bytes)
            .collect::<Vec<_>>(),
        [4, 8, 12]
            .into_iter()
            .map(|value| G2::generator().mul(&Scalar::from_u64(value)).to_bytes())
            .collect::<Vec<_>>()
    );
}
#[test]
fn duplicate_commitment_and_duplicate_share_abort() {
    for duplicate_share in [false, true] {
        let (mut state, _) = G2Dkg::from_coefficients(PeerId(0), 4, coefficients()).unwrap();
        state
            .receive(PeerId(1), DkgMessage::Hash(hash(&commitments())))
            .unwrap();
        state
            .receive(PeerId(1), DkgMessage::Commitments(commitments()))
            .unwrap();
        let message = if duplicate_share {
            state
                .receive(PeerId(1), DkgMessage::Share(Scalar::from_u64(6)))
                .unwrap();
            DkgMessage::Share(Scalar::from_u64(6))
        } else {
            DkgMessage::Commitments(commitments())
        };
        assert!(matches!(
            state.receive(PeerId(1), message),
            Err(SetupError::Duplicate)
        ));
        assert!(matches!(state.finish(), Err(SetupError::Aborted)));
    }
}
