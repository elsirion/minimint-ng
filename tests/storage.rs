use minimint_ng::storage::{Namespace::*, Store, StoreError};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
use fixture::TestDir;

#[test]
fn snapshots_rollback_and_all_namespaces() {
    let dir = TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let old = store.snapshot().unwrap();
    let mut tx = store.transaction().unwrap();
    for ns in [Replicated, Local, Agreement, Outbox, ClientBackup] {
        tx.put(ns, b"k", &[ns as u8]).unwrap();
        assert_eq!(tx.get(ns, b"k").unwrap(), Some(vec![ns as u8]));
        assert_eq!(old.get(ns, b"k").unwrap(), None);
    }
    tx.commit().unwrap();
    let committed = store.snapshot().unwrap();
    let mut tx = store.transaction().unwrap();
    tx.delete(Replicated, b"k").unwrap();
    tx.put(Local, b"k", b"rollback").unwrap();
    assert_eq!(tx.get(Replicated, b"k").unwrap(), None);
    drop(tx);
    assert_eq!(
        store.snapshot().unwrap().get(Replicated, b"k").unwrap(),
        Some(vec![0])
    );
    assert_eq!(committed.get(Local, b"k").unwrap(), Some(vec![1]));
    assert_eq!(old.get(Replicated, b"k").unwrap(), None);
}
#[test]
fn scan_order_prefix_boundaries_and_own_writes() {
    let dir = TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut tx = store.transaction().unwrap();
    for key in [b"a\xff".as_slice(), b"b", b"a", b"a\0", b"", b"\xff"] {
        tx.put(Replicated, key, key).unwrap();
    }
    tx.put(Local, b"a", b"private").unwrap();
    tx.commit().unwrap();
    let mut tx = store.transaction().unwrap();
    tx.delete(Replicated, b"a\0").unwrap();
    tx.put(Replicated, b"aa", b"replacement").unwrap();
    assert_eq!(
        tx.scan_prefix(Replicated, b"a").unwrap(),
        vec![
            (b"a".to_vec(), b"a".to_vec()),
            (b"aa".to_vec(), b"replacement".to_vec()),
            (b"a\xff".to_vec(), b"a\xff".to_vec())
        ]
    );
    assert_eq!(tx.scan_prefix(Replicated, b"\xff").unwrap().len(), 1);
    assert_eq!(tx.scan_prefix(Replicated, b"").unwrap().len(), 6);
    tx.commit().unwrap();
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Local, b"")
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn exact_agreement_bytes_atomic_clear_and_reopen() {
    let dir = TestDir::new();
    {
        let store = Store::open(dir.path()).unwrap();
        store.append_agreement(7, b"\0\xffopaque").unwrap();
        store.append_agreement(7, b"").unwrap();
        store.append_agreement(7, b"\r\n").unwrap();
        store.append_agreement(8, b"other").unwrap();
        assert_eq!(store.read_agreement(7).unwrap(), b"\0\xffopaque\r\n");
        let mut tx = store.transaction().unwrap();
        tx.clear_agreement(7).unwrap();
        tx.put(Replicated, b"done", b"yes").unwrap();
        drop(tx);
        assert_eq!(store.read_agreement(7).unwrap(), b"\0\xffopaque\r\n");
        let mut tx = store.transaction().unwrap();
        tx.clear_agreement(7).unwrap();
        tx.put(Agreement, b"\0\0\0\0\0\0\0\x07", b"user").unwrap();
        tx.put(Replicated, b"done", b"yes").unwrap();
        tx.commit().unwrap();
    }
    let store = Store::open(dir.path()).unwrap();
    assert!(store.read_agreement(7).unwrap().is_empty());
    assert_eq!(store.read_agreement(8).unwrap(), b"other");
    assert_eq!(
        store.snapshot().unwrap().get(Replicated, b"done").unwrap(),
        Some(b"yes".to_vec())
    );
    store.append_agreement(7, b"restart").unwrap();
    assert_eq!(store.read_agreement(7).unwrap(), b"restart");
}
#[test]
fn clones_serialize_read_modify_write_and_path_is_locked() {
    let dir = TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    assert!(matches!(
        Store::open(dir.path()),
        Err(StoreError::Database(fjall::Error::Locked))
    ));
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let clone = store.clone();
            scope.spawn(move || {
                for _ in 0..20 {
                    let mut tx = clone.transaction().unwrap();
                    let n = tx
                        .get(Local, b"count")
                        .unwrap()
                        .map(|v| u64::from_be_bytes(v.try_into().unwrap()))
                        .unwrap_or(0);
                    tx.put(Local, b"count", &(n + 1).to_be_bytes()).unwrap();
                    tx.commit().unwrap();
                }
            });
        }
    });
    assert_eq!(
        store.snapshot().unwrap().get(Local, b"count").unwrap(),
        Some(80_u64.to_be_bytes().to_vec())
    );
}
#[test]
fn invalid_keys_return_error_and_private_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        tx.put(Local, &vec![0; 65534], b""),
        Err(StoreError::KeyTooLong)
    ));
    tx.put(Local, &vec![0; 65533], b"long").unwrap();
    tx.commit().unwrap();
}

#[test]
fn snapshot_keeps_database_locked_and_nested_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TestDir::new();
    let path = dir.path().join("new-parent").join("database");
    let store = Store::open(&path).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(Local, b"secret", b"private").unwrap();
    tx.commit().unwrap();
    let snapshot = store.snapshot().unwrap();
    drop(store);
    assert_eq!(
        snapshot.get(Local, b"secret").unwrap(),
        Some(b"private".to_vec())
    );
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::Database(fjall::Error::Locked))
    ));
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    drop(snapshot);
    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened.snapshot().unwrap().get(Local, b"secret").unwrap(),
        Some(b"private".to_vec())
    );
}

#[test]
fn error_debug_never_exposes_underlying_private_diagnostics() {
    let sensitive = "/private/guardian/key-file with secret diagnostic";
    let errors = [
        StoreError::Io(std::io::Error::other(sensitive)),
        StoreError::Database(fjall::Error::from(std::io::Error::other(sensitive))),
    ];
    for error in errors {
        let debug = format!("{error:?}");
        assert_eq!(debug, error.to_string());
        assert!(!debug.contains(sensitive));
        assert!(!format!("{error:#?}").contains(sensitive));
    }
}
