//! Independently captured baseline replies for synthetic opaque backup data.
use minimint_ng::{
    api::backup::{self, SignedBackup},
    codec::text::hex_encode,
    crypto::sha256,
    storage::Store,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};
use std::{fs, path::PathBuf};
#[path = "fixtures/storage/mod.rs"]
mod fixture;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop/mixed-recovery-2026-09-10")
}
fn read(name: &str) -> Value {
    minimint_ng::json::parse(&fs::read(root().join(name)).unwrap(), 1024 * 1024, 64).unwrap()
}

#[test]
fn captured_backup_requests_match_all_guardians_and_local_durable_recovery() {
    for (name, digest) in read("manifest.json")["sha256"].as_object().unwrap() {
        assert_eq!(
            hex_encode(&sha256(&fs::read(root().join(name)).unwrap())),
            digest.as_str().unwrap()
        );
    }
    let requests = read("synthetic-backup-requests.json");
    let initial = SignedBackup::from_json(&requests["initial"]).unwrap();
    let replacement = SignedBackup::from_json(&requests["replacement"]).unwrap();
    initial.verify().unwrap();
    replacement.verify().unwrap();
    assert_eq!(initial.id, replacement.id);
    assert_eq!(
        initial.timestamp.secs_since_epoch,
        replacement.timestamp.secs_since_epoch
    );
    assert_eq!(
        initial.timestamp.nanos_since_epoch + 1,
        replacement.timestamp.nanos_since_epoch
    );
    assert!(replacement.timestamp.nanos_since_epoch < 1_000_000_000);
    assert_ne!(initial.payload, replacement.payload);
    let expected = json!({"timestamp": replacement.timestamp.json(), "data": hex_encode(&replacement.payload)});
    for peer in 0..4 {
        for phase in ["before-restart", "after-restart"] {
            assert_eq!(read(&format!("backup-peer{peer}-{phase}.json")), expected);
            for (method, result) in [
                ("recovery_count", json!(0)),
                ("recovery_signature_shares", json!([])),
                ("recovery_slice", json!([])),
                ("signature_shares", json!([])),
                (
                    "recovery_slice_hash",
                    json!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
                ),
            ] {
                assert_eq!(
                    read(&format!(
                        "recovery-{phase}-peer{peer}-module_0_{method}.json"
                    ))["response"],
                    result
                );
            }
        }
        for kind in ["older", "repeated"] {
            let error = read(&format!("backup-peer{peer}-{kind}-error.json"));
            assert_eq!(error["error"]["code"].as_u64(), Some(400));
            assert!(error["error"]["message"].as_str().is_some());
            assert!(error.get("result").is_none());
        }
    }
    // Replay the captured signed requests through our public native handler.
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let id = json!(hex_encode(&initial.id));
    assert_eq!(
        backup::dispatch(&store, "recover", &id).unwrap(),
        json!(null)
    );
    assert_eq!(
        backup::dispatch(&store, "backup", &requests["initial"]).unwrap(),
        json!(null)
    );
    assert!(matches!(
        backup::dispatch(&store, "backup", &requests["initial"]).unwrap_err(),
        backup::BackupError::TimestampNotIncreasing
    ));
    assert_eq!(
        backup::dispatch(&store, "backup", &requests["replacement"]).unwrap(),
        json!(null)
    );
    assert!(matches!(
        backup::dispatch(&store, "backup", &requests["initial"]).unwrap_err(),
        backup::BackupError::TimestampNotIncreasing
    ));
    drop(store);
    let reopened = Store::open(dir.path()).unwrap();
    assert_eq!(
        backup::dispatch(&reopened, "recover", &id).unwrap(),
        expected
    );
}
