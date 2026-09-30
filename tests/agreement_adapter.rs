#[path = "fixtures/storage/mod.rs"]
mod fixture;
use fedimint_aleph_bft::{BackupReader, BackupWriter, SpawnHandle};
use futures::{FutureExt, channel::oneshot, executor::block_on};
use minimint_ng::{
    agreement::{backup::SessionBackup, runtime::ThreadSpawner},
    storage::{Namespace, Store},
};

#[test]
fn engine_backup_callbacks_preserve_exact_bytes_and_session_isolation() {
    let path = fixture::TestDir::new();
    {
        let store = Store::open(path.path()).unwrap();
        let mut backup = SessionBackup::new(store.clone(), 7);
        block_on(backup.append(&[0, 255, 1])).unwrap();
        block_on(backup.append(&[])).unwrap();
        block_on(backup.append(&[2, 0])).unwrap();
        assert_eq!(block_on(backup.read()).unwrap(), [0, 255, 1, 2, 0]);
        let mut next = SessionBackup::new(store, 8);
        assert!(block_on(next.read()).unwrap().is_empty());
        block_on(next.append(b"next")).unwrap();
    }
    let store = Store::open(path.path()).unwrap();
    let mut backup = SessionBackup::new(store.clone(), 7);
    assert_eq!(block_on(backup.read()).unwrap(), [0, 255, 1, 2, 0]);
    let mut tx = store.transaction().unwrap();
    tx.put(
        Namespace::Replicated,
        b"test/completed/7",
        b"signed history",
    )
    .unwrap();
    tx.clear_agreement(7).unwrap();
    tx.commit().unwrap();
    assert!(block_on(backup.read()).unwrap().is_empty());
    assert_eq!(store.read_agreement(8).unwrap(), b"next");
}

#[test]
fn essential_completion_waits_and_reports_panics() {
    let spawner = ThreadSpawner;
    let (release, wait) = oneshot::channel();
    let mut handle = spawner.spawn_essential("test-wait", async move {
        wait.await.unwrap();
    });
    assert!(handle.as_mut().now_or_never().is_none());
    release.send(()).unwrap();
    assert_eq!(block_on(handle), Ok(()));
    let failed = spawner.spawn_essential("test-failure", async {
        panic!("test task failure");
    });
    assert_eq!(block_on(failed), Err(()));
}

#[test]
fn attached_scale_and_tagged_signatures() {
    use fedimint_aleph_bft::{Hasher, Keychain, MultiKeychain, NodeIndex, PartialMultisignature};
    use minimint_ng::{
        agreement::{Data, GuardianKeychain, ProtocolHasher},
        codec::ConsensusEncode,
        crypto::{secp::SecretKey, sha256},
        protocol::PeerId,
    };
    use parity_scale_codec::{Decode, Encode};
    use std::collections::BTreeMap;
    assert_eq!(Data::Batch(vec![1, 2, 3]).encode(), [0, 12, 1, 2, 3]);
    let mut sig = vec![1];
    sig.extend([5; 64]);
    assert_eq!(Data::Signature([5; 64]).encode(), sig);
    assert_eq!(
        Data::decode(&mut &[0, 12, 1, 2, 3][..]).unwrap(),
        Data::Batch(vec![1, 2, 3])
    );
    assert!(Data::decode(&mut &[2][..]).is_err());
    assert_eq!(
        ProtocolHasher::hash(b"abc"),
        sha256(&b"abc".as_slice().consensus_encode())
    );
    assert_ne!(ProtocolHasher::hash(b"abc"), sha256(b"abc"));
    let secrets: Vec<_> = (1..=4)
        .map(|n| {
            let mut b = [0; 32];
            b[31] = n;
            SecretKey::from_bytes(&b).unwrap()
        })
        .collect();
    let keys: BTreeMap<_, _> = secrets
        .iter()
        .enumerate()
        .map(|(i, k)| (PeerId(i as u16), k.public_key()))
        .collect();
    let keychains: Vec<_> = secrets
        .into_iter()
        .enumerate()
        .map(|(i, s)| GuardianKeychain::new(PeerId(i as u16), s, keys.clone()).unwrap())
        .collect();
    let message = b"tagged agreement message";
    let signature = keychains[0].sign(message);
    assert!(keychains[1].verify(message, &signature, NodeIndex(0)));
    assert!(!keychains[1].verify(message, &signature, NodeIndex(65536)));
    let digest = sha256(&[sha256(&keys.consensus_encode()).to_vec(), message.to_vec()].concat());
    minimint_ng::crypto::secp::schnorr_verify(
        &minimint_ng::crypto::secp::x_only(&keys[&PeerId(0)]).unwrap(),
        &digest,
        &signature,
    )
    .unwrap();
    let mut multi = keychains[0].bootstrap_multi(&signature, NodeIndex(0));
    assert!(!keychains[0].is_complete(message, &multi));
    for i in 1..3 {
        multi = multi.add_signature(&keychains[i].sign(message), NodeIndex(i));
    }
    assert!(keychains[0].is_complete(message, &multi));
    multi = multi.add_signature(&[0; 64], NodeIndex(3));
    assert!(!keychains[0].is_complete(message, &multi));
}
#[test]
fn ordinary_delays_and_batch_reservation_dedup() {
    use fedimint_aleph_bft::DataProvider;
    use minimint_ng::{
        agreement::{Data, ProposalQueue, ordinary_delays},
        codec::{ConsensusEncode, decode_whole},
        protocol::{ConsensusItem, DynamicValue, ModuleId, Transaction, TransactionSignatures},
    };
    use std::time::Duration;
    let delays = ordinary_delays(3600, 50);
    assert_eq!((delays.unit_creation_delay)(0), Duration::ZERO);
    assert_eq!(
        (delays.unit_creation_delay)(3600),
        Duration::from_millis(50)
    );
    assert_eq!(
        (delays.unit_creation_delay)(3601),
        Duration::from_millis(51)
    );
    assert_eq!((delays.coord_request_delay)(0), Duration::ZERO);
    assert_eq!((delays.coord_request_delay)(1), Duration::from_millis(50));
    assert_eq!((delays.coord_request_delay)(2), Duration::from_millis(1000));
    assert_eq!((delays.coord_request_delay)(3), Duration::from_millis(3000));
    let (queue, mut provider) = ProposalQueue::new(8).unwrap();
    assert!(block_on(provider.get_data()).is_none());
    let transaction = ConsensusItem::Transaction(Transaction {
        inputs: vec![],
        outputs: vec![],
        nonce: [0; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    });
    queue.push(transaction.clone()).unwrap();
    queue.push(transaction).unwrap();
    let module = ConsensusItem::Module(DynamicValue {
        module_id: ModuleId(0),
        payload: vec![1; 49_950],
    });
    queue.push(module.clone()).unwrap();
    queue.push(module).unwrap();
    let Some(Data::Batch(first)) = block_on(provider.get_data()) else {
        panic!("batch expected")
    };
    let decoded: Vec<ConsensusItem> = decode_whole(&first).unwrap();
    assert_eq!(decoded.len(), 2);
    assert!(first.len() <= 50_000);
    assert_eq!(first, decoded.consensus_encode());
    let Some(Data::Batch(_)) = block_on(provider.get_data()) else {
        panic!("second batch expected")
    };
    queue.set_signature([7; 64]).unwrap();
    assert_eq!(
        block_on(provider.get_data()),
        Some(Data::Signature([7; 64]))
    );
}

fn one_test_keychain() -> minimint_ng::agreement::GuardianKeychain {
    use minimint_ng::{agreement::GuardianKeychain, crypto::secp::SecretKey, protocol::PeerId};
    let mut keys = std::collections::BTreeMap::new();
    for id in 0..4 {
        let mut bytes = [0; 32];
        bytes[31] = id + 1;
        keys.insert(
            PeerId(id as u16),
            SecretKey::from_bytes(&bytes).unwrap().public_key(),
        );
    }
    let mut secret = [0; 32];
    secret[31] = 1;
    GuardianKeychain::new(PeerId(0), SecretKey::from_bytes(&secret).unwrap(), keys).unwrap()
}
fn signed_unit(data: minimint_ng::agreement::Data) -> Vec<u8> {
    use fedimint_aleph_bft::{Hasher, Keychain};
    use minimint_ng::agreement::ProtocolHasher;
    use parity_scale_codec::Encode;
    // Independent NET006 round-0 full-unit schema with four absent parents.
    let mut bytes = 0u16.to_le_bytes().to_vec();
    bytes.extend(0u64.to_le_bytes());
    bytes.extend(4u32.to_le_bytes());
    bytes.extend([4, 0]);
    bytes.extend(ProtocolHasher::hash(&[16, 0, 0, 0, 0]));
    bytes.push(1);
    bytes.extend(data.encode());
    bytes.extend(7u64.to_le_bytes());
    let signature = one_test_keychain().sign(&ProtocolHasher::hash(&bytes));
    bytes.extend(signature);
    bytes
}
#[test]
fn opaque_network_checks_native_included_data_and_allows_scale_suffix() {
    use fedimint_aleph_bft::{Hasher, Keychain};
    use minimint_ng::agreement::{AgreementError, Data, ProtocolHasher, decode_payload};
    let mut valid = vec![0, 0];
    valid.extend(signed_unit(Data::Batch(vec![0; 50_000])));
    assert!(decode_payload(&valid).is_ok());
    valid.extend([255, 254]);
    assert!(decode_payload(&valid).is_ok());
    let oversized = signed_unit(Data::Batch(vec![0; 50_001]));
    let mut new_unit = vec![0, 0];
    new_unit.extend(&oversized);
    assert!(matches!(
        decode_payload(&new_unit),
        Err(AgreementError::OversizedData)
    ));
    // NET005: proof units are omitted by the public native included_data traversal.
    // The application may not impose its batch cap on those two proof units.
    let mut alert = 0u64.to_le_bytes().to_vec();
    alert.extend(&oversized);
    alert.extend(signed_unit(Data::Batch(vec![1; 50_001])));
    alert.push(0);
    let mut proof = vec![1, 0];
    proof.extend(&alert);
    proof.extend(one_test_keychain().sign(&ProtocolHasher::hash(&alert)));
    assert!(decode_payload(&proof).is_ok());
    // The same oversized unit in the legitimized-unit list must be rejected.
    alert.pop();
    alert.push(4);
    alert.extend(&oversized);
    let mut legitimate = vec![1, 0];
    legitimate.extend(&alert);
    legitimate.extend(one_test_keychain().sign(&ProtocolHasher::hash(&alert)));
    assert!(matches!(
        decode_payload(&legitimate),
        Err(AgreementError::OversizedData)
    ));
    assert!(decode_payload(&[255]).is_err());
}
#[test]
fn native_signature_map_scale_and_config_edges() {
    use fedimint_aleph_bft::{Keychain, MultiKeychain, NodeIndex, NodeMap};
    use minimint_ng::{
        agreement::{GuardianKeychain, session_config},
        crypto::secp::SecretKey,
        protocol::PeerId,
    };
    use parity_scale_codec::{Decode, Encode};
    let key = one_test_keychain();
    let signature = key.sign(b"map");
    let map = key.bootstrap_multi(&signature, NodeIndex(0));
    let mut expected = vec![16, 1];
    expected.extend(signature);
    expected.extend([0, 0, 0]);
    assert_eq!(map.encode(), expected);
    assert_eq!(
        NodeMap::<[u8; 64]>::decode(&mut expected.as_slice())
            .unwrap()
            .encode(),
        expected
    );
    assert!(session_config(4, PeerId(0), 7, 3600, 50).is_ok());
    assert!(session_config(4, PeerId(0), 7, u16::MAX, 50).is_err());
    assert!(session_config(3, PeerId(0), 7, 3600, 50).is_err());
    assert!(session_config(4, PeerId(4), 7, 3600, 50).is_err());
    let mut bytes = [0; 32];
    bytes[31] = 1;
    let secret = SecretKey::from_bytes(&bytes).unwrap();
    let keys = std::collections::BTreeMap::from([(PeerId(1), secret.public_key())]);
    assert!(GuardianKeychain::new(PeerId(1), secret, keys).is_err());
}
