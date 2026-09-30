use minimint_ng::codec::text::hex_decode;
use minimint_ng::codec::{ConsensusEncode, DecodeError, decode_whole};
use minimint_ng::protocol::*;

#[test]
fn independent_empty_transaction_and_witness_exclusion() {
    let bytes = hex_decode("00000000000000000000000100").unwrap();
    let mut tx: Transaction = decode_whole(&bytes).unwrap();
    assert_eq!(
        tx.commitment_bytes(),
        hex_decode("00000000000000000000").unwrap()
    );
    assert_eq!(tx.consensus_encode(), bytes);
    tx.signatures = TransactionSignatures::Unknown {
        tag: 9,
        payload: vec![1, 2],
    };
    assert_eq!(tx.commitment_bytes(), vec![0; 10]);
}
#[test]
fn error_fixture_and_exact_enum_consumption() {
    let error = TransactionError::Input(DynamicValue {
        module_id: ModuleId(0),
        payload: vec![3, 0],
    });
    assert_eq!(
        error.consensus_encode(),
        hex_decode("040400020300").unwrap()
    );
    assert_eq!(
        Result::<[u8; 32], _>::Err(error.clone()).consensus_encode(),
        hex_decode("00040400020300").unwrap()
    );
    assert_eq!(
        decode_whole::<TransactionError>(&error.consensus_encode()),
        Ok(error)
    );
    assert_eq!(
        decode_whole::<TransactionError>(&[3, 1, 0]),
        Err(DecodeError::TrailingBytes)
    );
    assert!(decode_whole::<TransactionError>(&[6, 0]).is_err());
}
#[test]
fn known_signature_payload_is_exact_unknown_is_preserved() {
    assert_eq!(
        decode_whole::<TransactionSignatures>(&[0, 2, 0, 0]),
        Err(DecodeError::TrailingBytes)
    );
    let raw = [99, 2, 1, 2];
    assert_eq!(
        decode_whole::<TransactionSignatures>(&raw)
            .unwrap()
            .consensus_encode(),
        raw
    );
}
#[test]
fn accepted_item_order_and_opaque_consensus() {
    let bytes = [42, 2, 8, 9, 253, 0, 253];
    let item: AcceptedItem = decode_whole(&bytes).unwrap();
    assert_eq!(item.peer, PeerId(253));
    assert_eq!(item.consensus_encode(), bytes);
}

struct Registry;
impl ModuleRegistry for Registry {
    fn decode_payload(
        &self,
        id: ModuleId,
        _: ModuleValueKind,
        r: &mut minimint_ng::codec::Reader<'_>,
    ) -> Result<(), DecodeError> {
        if id != ModuleId(42) {
            return Err(DecodeError::UnknownModule);
        }
        let (tag, body) = r.variant()?;
        if tag != 0 {
            return Err(DecodeError::UnknownVariant);
        }
        body.finish()
    }
}
#[test]
fn inspection_and_strict_registry_are_distinct() {
    use minimint_ng::codec::Reader;
    let mut tx = Transaction {
        inputs: vec![DynamicValue {
            module_id: ModuleId(42),
            payload: vec![0, 0],
        }],
        outputs: vec![],
        nonce: [0; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    assert!(
        Transaction::decode_for_execution(&mut Reader::new(&tx.consensus_encode()), &Registry)
            .is_ok()
    );
    tx.inputs[0].payload.push(0);
    assert_eq!(
        tx.validate_modules(&Registry),
        Err(DecodeError::TrailingBytes)
    );
    tx.inputs[0].module_id = ModuleId(7);
    let bytes = tx.consensus_encode();
    assert_eq!(decode_whole::<Transaction>(&bytes), Ok(tx));
    assert_eq!(
        Transaction::decode_for_execution(&mut Reader::new(&bytes), &Registry),
        Err(DecodeError::UnknownModule)
    );
}
#[test]
fn rpc_double_envelope_and_exact_unsigned_values() {
    use minimint_ng::codec::rpc;
    let value = Result::<[u8; 32], TransactionError>::Err(TransactionError::Input(DynamicValue {
        module_id: ModuleId(0),
        payload: vec![3, 0],
    }));
    let wrapper = rpc::hex(&value);
    assert_eq!(wrapper, ["0700040400020300"]);
    assert_eq!(
        rpc::decode_hex::<Result<[u8; 32], TransactionError>>(&wrapper),
        Ok(value)
    );
    assert_eq!(rpc::hex(&u64::MAX), ["09ffffffffffffffffff"]);
    assert_eq!(
        rpc::decode_base64::<u64>(&rpc::base64(&u64::MAX)),
        Ok(u64::MAX)
    );
    assert!(rpc::decode_hex::<u8>(&["010000".into()]).is_err());
    assert!(rpc::decode_hex::<u8>(&["020000".into()]).is_err());
    assert!(rpc::decode_hex::<u8>(&[]).is_err());
}

#[test]
fn batch_and_history_registry_gate_preserves_unknown_core_items() {
    let batch = [2, 42, 0, 1, 4, 42, 2, 0, 0];
    let items = decode_batch(&batch, &Registry).unwrap();
    assert!(matches!(items[0], ConsensusItem::Unknown { tag: 42, .. }));
    let mut trailing = batch.to_vec();
    trailing.push(0);
    assert_eq!(
        decode_batch(&trailing, &Registry),
        Err(DecodeError::TrailingBytes)
    );
    assert_eq!(
        decode_batch(&[1, 1, 4, 7, 2, 0, 0], &Registry),
        Err(DecodeError::UnknownModule)
    );
    let history = SignedSessionOutcome {
        outcome: SessionOutcome {
            items: vec![AcceptedItem {
                item: items[1].clone(),
                peer: PeerId(3),
            }],
        },
        signatures: std::collections::BTreeMap::new(),
    };
    assert_eq!(history.consensus_encode(), [1, 1, 4, 42, 2, 0, 0, 3, 0]);
    assert_eq!(
        SignedSessionOutcome::decode_with_registry(&history.consensus_encode(), &Registry),
        Ok(history)
    );
}
