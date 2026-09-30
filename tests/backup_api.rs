use minimint_ng::{
    api::backup::{self, BackupError, BackupTimestamp, SignedBackup},
    codec::text::{hex_decode, hex_encode},
    crypto::secp::SecretKey,
    storage::{Namespace, Store},
};
use sonic_rs::{Value, json};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn secret() -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = 1;
    SecretKey::from_bytes(&bytes).unwrap()
}
fn time(secs: u64, nanos: u32) -> BackupTimestamp {
    BackupTimestamp {
        secs_since_epoch: secs,
        nanos_since_epoch: nanos,
    }
}
fn signed(timestamp: BackupTimestamp, payload: Vec<u8>) -> SignedBackup {
    let key = secret();
    let mut request = SignedBackup {
        id: key.public_key(),
        payload,
        timestamp,
        signature: [0; 64],
    };
    request.signature = key.schnorr_sign(&request.digest()).unwrap();
    request
}
fn native(request: &SignedBackup) -> Value {
    json!({"id":hex_encode(&request.id),"payload":hex_encode(&request.payload),"timestamp":request.timestamp.json(),"signature":hex_encode(&request.signature)})
}
#[test]
fn fixed_signing_preimage_and_digest_have_only_legacy_consensus_fields() {
    let request = signed(time(65536, 999999999), vec![0, 255, 66]);
    // Independent literal assembled from REC007 + ENC BigSize, hashed with
    // Python hashlib. Neither a timestamp type tag nor a signature is included.
    assert_eq!(
        hex_encode(&request.commitment_bytes()),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817980300ff42fe00010000fe3b9ac9ff"
    );
    assert_eq!(
        hex_encode(&request.digest()),
        "38c30be7ef579e5774e52efad3aa4899bfe913cbb21907f26edc0b48494fd5a0"
    );
    request.verify().unwrap();
    let request = signed(time(0, 0), vec![42; 253]);
    assert_eq!(&request.commitment_bytes()[33..36], &[0xfd, 0, 0xfd]);
}
#[test]
fn native_upload_and_public_recovery_are_opaque_and_survive_reopen() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let request = signed(time(9007199254740993, 123456789), vec![0, 255, 42]);
    let id = json!(hex_encode(&request.id));
    assert_eq!(
        backup::dispatch(&store, "recover", &id).unwrap(),
        json!(null)
    );
    assert_eq!(
        backup::dispatch(&store, "backup", &native(&request)).unwrap(),
        json!(null)
    );
    let result = backup::dispatch(&store, "recover", &id).unwrap();
    assert_eq!(
        result,
        json!({"timestamp":{"secs_since_epoch":9007199254740993u64,"nanos_since_epoch":123456789},"data":"00ff2a"})
    );
    assert!(
        String::from_utf8(minimint_ng::json::encode(&result).unwrap())
            .unwrap()
            .contains("9007199254740993")
    );
    assert!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Replicated, b"")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::ClientBackup, b"")
            .unwrap()
            .len(),
        1
    );
    drop(store);
    let reopened = Store::open(directory.path()).unwrap();
    assert_eq!(backup::dispatch(&reopened, "recover", &id).unwrap(), result);
    let unknown = SecretKey::from_bytes(&[3; 32]).unwrap().public_key();
    assert!(
        backup::recover(&reopened.snapshot().unwrap(), &unknown)
            .unwrap()
            .is_none()
    );
}
#[test]
fn payload_limit_is_inclusive_and_ciphertext_structure_is_not_checked() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    backup::upload(&store, &signed(time(0, 0), vec![])).unwrap();
    let boundary = signed(time(1, 0), vec![0x37; backup::MAX_PAYLOAD_BYTES]);
    backup::upload(&store, &boundary).unwrap();
    let too_large = signed(time(2, 0), vec![0x38; backup::MAX_PAYLOAD_BYTES + 1]);
    assert!(matches!(
        backup::upload(&store, &too_large),
        Err(BackupError::PayloadTooLarge)
    ));
    assert!(matches!(
        backup::dispatch(&store, "backup", &native(&too_large)),
        Err(BackupError::PayloadTooLarge)
    ));
    assert!(
        backup::recover(&store.snapshot().unwrap(), &boundary.id)
            .unwrap()
            .unwrap()
            .data
            == boundary.payload
    );
}
#[test]
fn every_signed_field_and_signature_are_bound_before_any_replacement() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let initial = signed(time(1, 0), vec![1]);
    backup::upload(&store, &initial).unwrap();
    for mutation in 0..5 {
        let mut request = signed(time(2, 0), vec![2]);
        match mutation {
            0 => request.payload.push(3),
            1 => request.timestamp.secs_since_epoch += 1,
            2 => request.timestamp.nanos_since_epoch += 1,
            3 => request.id[0] ^= 1,
            _ => request.signature[0] ^= 1,
        }
        assert!(matches!(
            backup::upload(&store, &request),
            Err(BackupError::InvalidSignature)
        ));
    }
    let saved = backup::recover(&store.snapshot().unwrap(), &initial.id)
        .unwrap()
        .unwrap();
    assert_eq!(saved.timestamp, initial.timestamp);
    assert_eq!(saved.data, initial.payload);
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::ClientBackup, b"")
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn timestamps_strictly_increase_without_wall_clock_or_float_limits() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let initial = signed(time(10, 999999999), vec![1]);
    backup::upload(&store, &initial).unwrap();
    for timestamp in [time(9, 999999999), time(10, 0), initial.timestamp] {
        assert!(matches!(
            backup::upload(&store, &signed(timestamp, vec![2])),
            Err(BackupError::TimestampNotIncreasing)
        ));
    }
    backup::upload(&store, &signed(time(11, 0), vec![3])).unwrap();
    let latest = signed(time(u64::MAX, 999999999), vec![4]);
    backup::upload(&store, &latest).unwrap();
    assert!(matches!(
        backup::upload(&store, &latest),
        Err(BackupError::TimestampNotIncreasing)
    ));
    let snapshot = backup::recover(&store.snapshot().unwrap(), &latest.id)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.timestamp, latest.timestamp);
    assert_eq!(snapshot.data, latest.payload);
}
#[test]
fn simultaneous_identical_requests_cannot_both_replace_the_snapshot() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let request = signed(time(2, 0), vec![2]);
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            backup::upload(&store, &request)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            backup::upload(&store, &request)
        });
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(BackupError::TimestampNotIncreasing)))
            .count(),
        1
    );
    assert_eq!(
        backup::recover(&store.snapshot().unwrap(), &request.id)
            .unwrap()
            .unwrap()
            .timestamp,
        request.timestamp
    );
}
#[test]
fn malformed_json_shapes_and_integer_domains_fail_without_storage_changes() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let request = signed(time(1, 0), vec![42]);
    for timestamp in [
        json!({"secs_since_epoch":-1,"nanos_since_epoch":0}),
        json!({"secs_since_epoch":1.5,"nanos_since_epoch":0}),
        json!({"secs_since_epoch":"1","nanos_since_epoch":0}),
        json!({"secs_since_epoch":1,"nanos_since_epoch":4294967296u64}),
        json!({"secs_since_epoch":1}),
    ] {
        let params = json!({"id":hex_encode(&request.id),"payload":"2a","timestamp":timestamp,"signature":hex_encode(&request.signature)});
        assert!(matches!(
            backup::dispatch(&store, "backup", &params),
            Err(BackupError::InvalidParams)
        ));
    }
    for params in [
        json!(null),
        json!([native(&request)]),
        json!({"id":"00".repeat(33)}),
        json!("00"),
    ] {
        assert!(backup::dispatch(&store, "backup", &params).is_err());
    }
    for params in [
        json!([hex_encode(&request.id)]),
        json!(null),
        json!("00".repeat(33)),
        json!("00"),
    ] {
        assert!(backup::dispatch(&store, "recover", &params).is_err());
    }
    assert!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::ClientBackup, b"")
            .unwrap()
            .is_empty()
    );
}
#[test]
fn corrupt_private_snapshot_is_not_silently_overwritten() {
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let request = signed(time(1, 0), vec![1]);
    let key = [b"backup/v1/".as_slice(), &request.id].concat();
    let mut writer = store.transaction().unwrap();
    writer.put(Namespace::ClientBackup, &key, &[0xff]).unwrap();
    writer.commit().unwrap();
    assert!(matches!(
        backup::upload(&store, &request),
        Err(BackupError::CorruptState)
    ));
    assert!(matches!(
        backup::recover(&store.snapshot().unwrap(), &request.id),
        Err(BackupError::CorruptState)
    ));
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .get(Namespace::ClientBackup, &key)
            .unwrap()
            .unwrap(),
        vec![0xff]
    );
}
#[test]
fn nonnormalized_timestamp_interpretation_preserves_signed_pair() {
    // Explicit local interpretation only; writer question Q15 tracks upstream
    // JSON normalization before signing and ordering for this producer-excluded corner.
    let directory = fixture::TestDir::new();
    let store = Store::open(directory.path()).unwrap();
    let request = signed(time(1, 1000000000), vec![1]);
    assert!(
        request
            .commitment_bytes()
            .ends_with(&hex_decode("01fe3b9aca00").unwrap())
    );
    backup::upload(&store, &request).unwrap();
    assert!(matches!(
        backup::upload(&store, &signed(time(2, 0), vec![2])),
        Err(BackupError::TimestampNotIncreasing)
    ));
    assert_eq!(
        backup::recover(&store.snapshot().unwrap(), &request.id)
            .unwrap()
            .unwrap()
            .timestamp,
        request.timestamp
    );
}
