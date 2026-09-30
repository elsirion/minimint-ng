use minimint_ng::{
    codec::{ConsensusEncode, decode_whole, text::hex_encode},
    config::{Fee, RawMintConfig},
    crypto::{
        bls::{self, G1, G2, Scalar},
        secp::SecretKey,
    },
    modules::mint::*,
    protocol::{ModuleId, OutPoint, PeerId},
    storage::Store,
};
use std::collections::BTreeMap;
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn mint(instance: u16) -> Mint {
    let shares = (0..42)
        .map(|d| (d, Scalar::from_u64(u64::from(d) + 1)))
        .collect::<BTreeMap<_, _>>();
    let keys = shares
        .iter()
        .map(|(d, s)| (*d, G2::generator().mul(s).to_bytes()))
        .collect::<BTreeMap<_, _>>();
    Mint::new(
        ModuleId(instance),
        PeerId(0),
        RawMintConfig {
            aggregate_keys: keys.clone(),
            public_shares: keys
                .iter()
                .map(|(d, k)| (*d, BTreeMap::from([(PeerId(0), *k)])))
                .collect(),
            fee: Fee::mint(100, 0).unwrap(),
            amount_unit: 0,
        },
        shares,
    )
    .unwrap()
}
fn point(index: u64) -> OutPoint {
    OutPoint {
        txid: [3; 32],
        out_idx: index,
    }
}
#[test]
fn issued_blinded_share_unblinds_and_spends_atomically() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mint = mint(42);
    let secret = SecretKey::from_bytes(&[1; 32]).unwrap();
    let nonce = Nonce::from_bytes(secret.public_key()).unwrap();
    let message = bls::message_sha256(&nonce.to_bytes()).unwrap();
    let blind = Scalar::from_u64(9);
    let output = Output::V0(OutputV0 {
        denomination: 10,
        blinded_message: G1Bytes::from_bytes(message.mul(&blind).to_bytes()).unwrap(),
        tweak: [7; 16],
    });
    let mut tx = store.transaction().unwrap();
    let meta = mint.output(&mut tx, &output, point(0)).unwrap();
    assert_eq!((meta.amount_msat, meta.fee_msat), (1024, 100));
    assert_eq!(mint.audit(&tx).unwrap(), -1024);
    tx.commit().unwrap();
    let share = mint
        .signature_shares(&store.snapshot().unwrap(), [3; 32], 0..1)
        .unwrap()[0];
    let unblinded = G1::from_bytes(&share.to_bytes())
        .unwrap()
        .mul(&blind.inverse().unwrap());
    let input = Input::V0(Note {
        denomination: 10,
        nonce,
        signature: G1Bytes::from_bytes(unblinded.to_bytes()).unwrap(),
    });
    let mut tx = store.transaction().unwrap();
    let meta = mint.input(&mut tx, &input, point(0)).unwrap();
    assert_eq!((meta.amount_msat, meta.fee_msat), (1024, 100));
    assert_eq!(meta.public_key, secret.public_key());
    assert_eq!(mint.audit(&tx).unwrap(), 0);
    tx.commit().unwrap();
    assert_eq!(mint.recovery_count(&store.snapshot().unwrap()).unwrap(), 2);
    let mut tx = store.transaction().unwrap();
    assert!(
        matches!(mint.input(&mut tx,&input,point(0)),Err(minimint_ng::core::transaction::TransitionError::Module(bytes)) if bytes==[1,0])
    );
}
#[test]
fn independent_error_and_empty_recovery_hash_fixtures() {
    assert_eq!(InputError::InvalidSignature.consensus_encode(), [3, 0]);
    assert_eq!(
        InputError::UnknownInputVariant(7).consensus_encode(),
        [0, 1, 7]
    );
    assert_eq!(
        decode_whole::<InputError>(&[3, 0]),
        Ok(InputError::InvalidSignature)
    );
    assert!(decode_whole::<InputError>(&[4, 0]).is_err());
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        hex_encode(
            &mint(0)
                .recovery_slice_hash(&store.snapshot().unwrap(), 0..100)
                .unwrap()
        ),
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    );
}

fn issue(store: &Store, mint: &Mint, denomination: u8, secret: &SecretKey, index: u64) -> Input {
    let nonce = Nonce::from_bytes(secret.public_key()).unwrap();
    let blind = Scalar::from_u64(7);
    let message = bls::message_sha256(&nonce.to_bytes()).unwrap();
    let output = Output::V0(OutputV0 {
        denomination,
        blinded_message: G1Bytes::from_bytes(message.mul(&blind).to_bytes()).unwrap(),
        tweak: [0; 16],
    });
    let mut tx = store.transaction().unwrap();
    mint.output(&mut tx, &output, point(index)).unwrap();
    tx.commit().unwrap();
    let share = mint
        .signature_shares(&store.snapshot().unwrap(), [3; 32], index..index + 1)
        .unwrap()[0];
    Input::V0(Note {
        denomination,
        nonce,
        signature: G1Bytes::from_bytes(
            G1::from_bytes(&share.to_bytes())
                .unwrap()
                .mul(&blind.inverse().unwrap())
                .to_bytes(),
        )
        .unwrap(),
    })
}

#[test]
fn nonce_spent_is_global_per_instance_and_signature_precedes_spent() {
    use minimint_ng::core::transaction::TransitionError;
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mint = mint(7);
    let secret = SecretKey::from_bytes(&[2; 32]).unwrap();
    let input = issue(&store, &mint, 0, &secret, 0);
    let second = issue(&store, &mint, 1, &secret, 1);
    let mut tx = store.transaction().unwrap();
    assert_eq!(
        mint.input(&mut tx, &input, point(0)).unwrap().amount_msat,
        1
    );
    tx.commit().unwrap();
    let mut tx = store.transaction().unwrap();
    assert!(
        matches!(mint.input(&mut tx,&second,point(0)),Err(TransitionError::Module(bytes)) if bytes==[1,0])
    );
    drop(tx);
    let Input::V0(mut bad) = second else { panic!() };
    bad.signature = G1Bytes::from_bytes(G1::identity().to_bytes()).unwrap();
    let mut tx = store.transaction().unwrap();
    assert!(
        matches!(mint.input(&mut tx,&Input::V0(bad),point(0)),Err(TransitionError::Module(bytes)) if bytes==[3,0])
    );
}
#[test]
fn repeated_blinded_lookup_overwrites_and_missing_locations_are_omitted() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mint = mint(42);
    let other = mint_for_other_instance();
    let message = G1Bytes::from_bytes(G1::generator().to_bytes()).unwrap();
    let mut tx = store.transaction().unwrap();
    for (index, d) in [(0, 1), (2, 2)] {
        mint.output(
            &mut tx,
            &Output::V0(OutputV0 {
                denomination: d,
                blinded_message: message,
                tweak: [index as u8; 16],
            }),
            point(index),
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let snapshot = store.snapshot().unwrap();
    let shares = mint.signature_shares(&snapshot, [3; 32], 0..3).unwrap();
    assert_eq!(shares.len(), 2);
    assert_ne!(shares[0], shares[1]);
    assert_eq!(
        mint.recovery_signature_shares(&snapshot, &[message, message])
            .unwrap(),
        [shares[1], shares[1]]
    );
    assert!(matches!(
        other.recovery_signature_shares(&snapshot, &[message]),
        Err(ReadError::MissingShare)
    ));
    assert_eq!(other.recovery_count(&snapshot).unwrap(), 0);
    assert!(
        mint.signature_shares(&snapshot, [3; 32], 1..2)
            .unwrap()
            .is_empty()
    );
    let missing = G1Bytes::from_bytes(G1::identity().to_bytes()).unwrap();
    assert!(matches!(
        mint.recovery_signature_shares(&snapshot, &[message, missing]),
        Err(ReadError::MissingShare)
    ));
    assert!(
        mint.recovery_signature_shares(&snapshot, &[])
            .unwrap()
            .is_empty()
    );
    let records = mint.recovery_slice(&snapshot, 0..u64::MAX).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        mint.recovery_slice_hash(&snapshot, 0..2).unwrap(),
        minimint_ng::crypto::sha256(&records.consensus_encode())
    );
}
fn mint_for_other_instance() -> Mint {
    mint(43)
}
#[test]
fn unknown_versions_are_inspectable_then_rejected_and_infinity_is_signed() {
    use minimint_ng::core::transaction::TransitionError;
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mint = mint(0);
    let mut tx = store.transaction().unwrap();
    let input = decode_whole::<Input>(&[7, 2, 1, 2]).unwrap();
    assert_eq!(input.consensus_encode(), [7, 2, 1, 2]);
    assert!(
        matches!(mint.input(&mut tx,&input,point(0)),Err(TransitionError::Module(bytes)) if bytes==[0,1,7])
    );
    let output = decode_whole::<Output>(&[9, 0]).unwrap();
    assert!(
        matches!(mint.output(&mut tx,&output,point(0)),Err(TransitionError::Module(bytes)) if bytes==[0,1,9])
    );
    let identity = G1Bytes::from_bytes(G1::identity().to_bytes()).unwrap();
    mint.output(
        &mut tx,
        &Output::V0(OutputV0 {
            denomination: 0,
            blinded_message: identity,
            tweak: [255; 16],
        }),
        point(0),
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        mint.recovery_signature_shares(&store.snapshot().unwrap(), &[identity])
            .unwrap(),
        [identity]
    );
    assert!(decode_whole::<Output>(&[0, 0]).is_err());
    assert!(G1Bytes::from_bytes([0; 48]).is_err());
}
#[test]
fn fee_saturation_rounding_and_counter_underflow_are_not_rejections() {
    use minimint_ng::core::transaction::TransitionError;
    assert_eq!(fee(u64::MAX, 100, 1000).unwrap(), 18_446_744_073_809);
    assert_eq!(fee(999, 100, 1000).unwrap(), 100);
    assert_eq!(fee(1000, 100, 1000).unwrap(), 101);
    assert!(matches!(
        fee(u64::MAX, u64::MAX, 1),
        Err(TransitionError::FatalInvariant(_))
    ));
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mint = mint(0);
    let nonce = Nonce::from_bytes(SecretKey::from_bytes(&[3; 32]).unwrap().public_key()).unwrap();
    let signature = bls::message_sha256(&nonce.to_bytes())
        .unwrap()
        .mul(&Scalar::from_u64(1));
    let input = Input::V0(Note {
        denomination: 0,
        nonce,
        signature: G1Bytes::from_bytes(signature.to_bytes()).unwrap(),
    });
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        mint.input(&mut tx, &input, point(0)),
        Err(TransitionError::FatalInvariant(_))
    ));
    drop(tx);
    assert_eq!(mint.recovery_count(&store.snapshot().unwrap()).unwrap(), 0);
}
#[test]
fn real_mint_transaction_rollback_and_note_error_precedes_witness_count() {
    use minimint_ng::{
        config::CORE_CONSENSUS,
        core::transaction::{ExecutionError, check_submission},
        protocol::{DynamicValue, Transaction, TransactionError, TransactionSignatures},
    };
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mint = mint(0);
    let secret = SecretKey::from_bytes(&[4; 32]).unwrap();
    let input = issue(&store, &mint, 10, &secret, 0);
    let output = Output::V0(OutputV0 {
        denomination: 9,
        blinded_message: G1Bytes::from_bytes(G1::generator().to_bytes()).unwrap(),
        tweak: [4; 16],
    });
    let mut transaction = Transaction {
        inputs: vec![DynamicValue {
            module_id: ModuleId(0),
            payload: input.consensus_encode(),
        }],
        outputs: vec![
            DynamicValue {
                module_id: ModuleId(0),
                payload: output.consensus_encode(),
            },
            DynamicValue {
                module_id: ModuleId(0),
                payload: Output::Unknown {
                    version: 7,
                    payload: vec![],
                }
                .consensus_encode(),
            },
        ],
        nonce: [5; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    let id = minimint_ng::core::transaction::transaction_id(&transaction);
    transaction.signatures =
        TransactionSignatures::Schnorr(vec![secret.schnorr_sign(&id).unwrap()]);
    assert!(matches!(
        check_submission(&store, &transaction, &mint, CORE_CONSENSUS),
        Err(ExecutionError::Rejected(TransactionError::Output(_)))
    ));
    let snapshot = store.snapshot().unwrap();
    assert_eq!(mint.recovery_count(&snapshot).unwrap(), 1);
    assert!(
        mint.signature_shares(&snapshot, id, 0..2)
            .unwrap()
            .is_empty()
    );
    let mut tx = store.transaction().unwrap();
    assert!(mint.input(&mut tx, &input, point(0)).is_ok());
    drop(tx);
    let Input::V0(mut invalid) = input else {
        panic!()
    };
    invalid.signature = G1Bytes::from_bytes(G1::identity().to_bytes()).unwrap();
    transaction.inputs[0].payload = Input::V0(invalid).consensus_encode();
    transaction.signatures = TransactionSignatures::Schnorr(vec![]);
    let error = check_submission(&store, &transaction, &mint, CORE_CONSENSUS);
    assert!(
        matches!(error,Err(ExecutionError::Rejected(TransactionError::Input(value))) if value.payload==[3,0])
    );
    // No-op hooks don't perform pairing, state mutations or version rejection.
    let mut tx = store.transaction().unwrap();
    assert!(
        mint.stateless_input(&decode_whole::<Input>(&[7, 0]).unwrap())
            .is_ok()
    );
    assert!(
        mint.submission_output(
            &mut tx,
            &Output::Unknown {
                version: 7,
                payload: vec![]
            },
            point(0)
        )
        .is_ok()
    );
}

#[test]
fn constructor_checks_local_shares_but_not_map_equality() {
    let shares = (0..42)
        .map(|d| (d, Scalar::from_u64(1)))
        .collect::<BTreeMap<_, _>>();
    let key = G2::generator().to_bytes();
    let config = RawMintConfig {
        aggregate_keys: (0..42).map(|d| (d, key)).collect(),
        public_shares: (0..42)
            .map(|d| (d, BTreeMap::from([(PeerId(0), key)])))
            .collect(),
        fee: Fee {
            base: 0,
            parts_per_million: 1001,
        },
        amount_unit: 0,
    };
    let mut missing = shares.clone();
    missing.remove(&3);
    assert!(Mint::new(ModuleId(0), PeerId(0), config.clone(), missing).is_err());
    let mut wrong = shares.clone();
    wrong.insert(3, Scalar::from_u64(2));
    assert!(Mint::new(ModuleId(0), PeerId(0), config.clone(), wrong).is_err());
    let mut extras = shares;
    extras.insert(42, Scalar::from_u64(2));
    // Extra private denomination and raw rate above constructor limit impose no
    // invented input/output predicate or denomination-map equality requirement.
    let mint = Mint::new(ModuleId(0), PeerId(0), config, extras).unwrap();
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut tx = store.transaction().unwrap();
    let output = Output::V0(OutputV0 {
        denomination: 42,
        blinded_message: G1Bytes::from_bytes(G1::identity().to_bytes()).unwrap(),
        tweak: [0; 16],
    });
    assert_eq!(
        mint.output(&mut tx, &output, point(0)).unwrap().amount_msat,
        1 << 42
    );
}
#[test]
fn counter_overflow_and_unsupported_audit_domain_are_fatal() {
    use minimint_ng::{core::transaction::TransitionError, storage::Namespace};
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mint = mint(42);
    // Fault injection into the private DB schema, not a network encoding.
    let counter_key = [b"mint/v1/".as_slice(), &42u16.to_be_bytes(), &[1, 0]].concat();
    let mut tx = store.transaction().unwrap();
    tx.put(Namespace::Replicated, &counter_key, &u64::MAX.to_be_bytes())
        .unwrap();
    tx.commit().unwrap();
    let output = Output::V0(OutputV0 {
        denomination: 0,
        blinded_message: G1Bytes::from_bytes(G1::identity().to_bytes()).unwrap(),
        tweak: [0; 16],
    });
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        mint.output(&mut tx, &output, point(0)),
        Err(TransitionError::FatalInvariant(_))
    ));
    drop(tx);
    assert!(
        mint.signature_shares(&store.snapshot().unwrap(), [3; 32], 0..1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(mint.recovery_count(&store.snapshot().unwrap()).unwrap(), 0);
    let tx = store.transaction().unwrap();
    assert!(matches!(
        mint.audit(&tx),
        Err(TransitionError::FatalInvariant(_))
    ));
}
#[test]
fn successful_core_reissuance_and_reopen_preserve_recovery() {
    use minimint_ng::{
        config::CORE_CONSENSUS,
        core::transaction::{apply_consensus, check_submission, transaction_id},
        protocol::{DynamicValue, Transaction, TransactionSignatures},
    };
    let dir = fixture::TestDir::new();
    let mint = mint(0);
    let secret = SecretKey::from_bytes(&[5; 32]).unwrap();
    let stored_hash;
    {
        let store = Store::open(dir.path()).unwrap();
        let input = issue(&store, &mint, 10, &secret, 0);
        let output = Output::V0(OutputV0 {
            denomination: 9,
            blinded_message: G1Bytes::from_bytes(G1::generator().to_bytes()).unwrap(),
            tweak: [9; 16],
        });
        let mut transaction = Transaction {
            inputs: vec![DynamicValue {
                module_id: ModuleId(0),
                payload: input.consensus_encode(),
            }],
            outputs: vec![DynamicValue {
                module_id: ModuleId(0),
                payload: output.consensus_encode(),
            }],
            nonce: [8; 8],
            signatures: TransactionSignatures::Schnorr(vec![]),
        };
        let id = transaction_id(&transaction);
        transaction.signatures =
            TransactionSignatures::Schnorr(vec![secret.schnorr_sign(&id).unwrap()]);
        assert_eq!(
            check_submission(&store, &transaction, &mint, CORE_CONSENSUS).unwrap(),
            id
        );
        assert_eq!(mint.recovery_count(&store.snapshot().unwrap()).unwrap(), 1);
        let mut tx = store.transaction().unwrap();
        assert_eq!(
            apply_consensus(&mut tx, &transaction, &mint, CORE_CONSENSUS).unwrap(),
            id
        );
        assert_eq!(mint.audit(&tx).unwrap(), -512);
        tx.commit().unwrap();
        assert_eq!(mint.recovery_count(&store.snapshot().unwrap()).unwrap(), 3);
        stored_hash = mint
            .recovery_slice_hash(&store.snapshot().unwrap(), 0..3)
            .unwrap();
    }
    let reopened = Store::open(dir.path()).unwrap();
    assert_eq!(
        mint.recovery_count(&reopened.snapshot().unwrap()).unwrap(),
        3
    );
    assert_eq!(
        mint.recovery_slice_hash(&reopened.snapshot().unwrap(), 0..3)
            .unwrap(),
        stored_hash
    );
}

#[test]
fn all_three_of_four_share_subsets_issue_same_spendable_note_and_recovery() {
    let polynomials = (0..42u8)
        .map(|d| {
            (
                d,
                vec![
                    Scalar::from_u64(u64::from(d) + 1),
                    Scalar::from_u64(2),
                    Scalar::from_u64(3),
                ],
            )
        })
        .collect::<BTreeMap<_, _>>();
    let config = RawMintConfig {
        aggregate_keys: polynomials
            .iter()
            .map(|(d, p)| (*d, G2::generator().mul(&p[0]).to_bytes()))
            .collect(),
        public_shares: polynomials
            .iter()
            .map(|(d, p)| {
                (
                    *d,
                    (0..4)
                        .map(|peer| {
                            (
                                PeerId(peer),
                                G2::generator()
                                    .mul(&bls::evaluate_polynomial(p, peer).unwrap())
                                    .to_bytes(),
                            )
                        })
                        .collect(),
                )
            })
            .collect(),
        fee: Fee::mint(100, 0).unwrap(),
        amount_unit: 0,
    };
    let dirs = (0..4).map(|_| fixture::TestDir::new()).collect::<Vec<_>>();
    let stores = dirs
        .iter()
        .map(|dir| Store::open(dir.path()).unwrap())
        .collect::<Vec<_>>();
    let mints = (0..4)
        .map(|peer| {
            Mint::new(
                ModuleId(42),
                PeerId(peer),
                config.clone(),
                polynomials
                    .iter()
                    .map(|(d, p)| (*d, bls::evaluate_polynomial(p, peer).unwrap()))
                    .collect(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let nonce = Nonce::from_bytes(SecretKey::from_bytes(&[6; 32]).unwrap().public_key()).unwrap();
    let blind = Scalar::from_u64(13);
    let message = bls::message_sha256(&nonce.to_bytes()).unwrap();
    let blinded = message.mul(&blind);
    let output = Output::V0(OutputV0 {
        denomination: 10,
        blinded_message: G1Bytes::from_bytes(blinded.to_bytes()).unwrap(),
        tweak: [23; 16],
    });
    let shares = mints
        .iter()
        .zip(&stores)
        .enumerate()
        .map(|(peer, (mint, store))| {
            let mut tx = store.transaction().unwrap();
            mint.output(&mut tx, &output, point(0)).unwrap();
            tx.commit().unwrap();
            let share = mint
                .signature_shares(&store.snapshot().unwrap(), [3; 32], 0..1)
                .unwrap()[0];
            let share = G1::from_bytes(&share.to_bytes()).unwrap();
            bls::verify_share(
                &blinded,
                &G2::from_bytes(&config.public_shares[&10][&PeerId(peer as u16)]).unwrap(),
                &share,
            )
            .unwrap();
            (peer as u16, share)
        })
        .collect::<Vec<_>>();
    let mut expected = None;
    for excluded in 0..4 {
        let subset = shares
            .iter()
            .filter(|(peer, _)| usize::from(*peer) != excluded)
            .map(|(peer, share)| (*peer, share.clone()))
            .collect::<Vec<_>>();
        let signature = bls::interpolate_g1(&subset, 3)
            .unwrap()
            .mul(&blind.inverse().unwrap());
        bls::verify_share(
            &message,
            &G2::from_bytes(&config.aggregate_keys[&10]).unwrap(),
            &signature,
        )
        .unwrap();
        if let Some(previous) = expected {
            assert_eq!(previous, signature.to_bytes());
        }
        expected = Some(signature.to_bytes());
    }
    let input = Input::V0(Note {
        denomination: 10,
        nonce,
        signature: G1Bytes::from_bytes(expected.unwrap()).unwrap(),
    });
    let mut hashes = Vec::new();
    for (mint, store) in mints.iter().zip(&stores) {
        let mut tx = store.transaction().unwrap();
        mint.input(&mut tx, &input, point(0)).unwrap();
        assert_eq!(mint.audit(&tx).unwrap(), 0);
        tx.commit().unwrap();
        hashes.push(
            mint.recovery_slice_hash(&store.snapshot().unwrap(), 0..2)
                .unwrap(),
        );
    }
    assert!(hashes.windows(2).all(|w| w[0] == w[1]));
}
#[test]
fn exact_output_and_recovery_frames_and_whole_module_consumption() {
    use minimint_ng::protocol::{DynamicValue, ModuleValueKind};
    let identity = G1Bytes::from_bytes(G1::identity().to_bytes()).unwrap();
    let output = Output::V0(OutputV0 {
        denomination: 7,
        blinded_message: identity,
        tweak: [1; 16],
    });
    let expected = [vec![0, 65, 7, 0xc0], vec![0; 47], vec![1; 16]].concat();
    assert_eq!(output.consensus_encode(), expected);
    assert_eq!(decode_whole::<Output>(&expected).unwrap(), output);
    let recovery = RecoveryItem::Output {
        denomination: 7,
        nonce_hash: [0; 20],
        tweak: [1; 16],
    };
    assert_eq!(
        recovery.consensus_encode(),
        [vec![0, 37, 7], vec![0; 20], vec![1; 16]].concat()
    );
    let mint = mint(42);
    let mut dynamic = DynamicValue {
        module_id: ModuleId(42),
        payload: expected,
    };
    assert!(dynamic.validate(&mint, ModuleValueKind::Output).is_ok());
    dynamic.payload.push(0);
    assert!(dynamic.validate(&mint, ModuleValueKind::Output).is_err());
    dynamic.module_id = ModuleId(43);
    assert!(dynamic.validate(&mint, ModuleValueKind::Output).is_err());
}
