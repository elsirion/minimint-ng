//! WAL-013 precedence through public Wallet transitions and real discovery scans.
//! Synthetic backend blocks are fixtures, not evidence of Bitcoin admission.
use minimint_ng::{
    bitcoin::{self, BackendError, BitcoinBackend},
    config::{BitcoinNetwork, DescriptorKind, Fee, RawWalletConfig},
    core::transaction::TransitionError,
    crypto::secp::SecretKey,
    modules::wallet::{ConsensusItem, Destination, Input, Output, Wallet, prepare_scan},
    protocol::{ModuleId, OutPoint, PeerId},
    storage::{Namespace, Store, WriteTransaction},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn key(n: u64) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_bytes(&bytes).unwrap()
}
fn wallet() -> Wallet {
    Wallet::new(
        ModuleId(42),
        PeerId(0),
        RawWalletConfig {
            bitcoin_pks: (0..4)
                .map(|p| (PeerId(p), key(u64::from(p) + 1).public_key()))
                .collect(),
            descriptor: DescriptorKind::Wsh,
            send_tx_vbytes: 228,
            receive_tx_vbytes: 316,
            feerate_base: 250,
            dust_limit: 10_000,
            fee_consensus: Fee {
                base: 100_000,
                parts_per_million: 0,
            },
            network: BitcoinNetwork::Regtest,
        },
        key(1),
    )
    .unwrap()
}
struct Backend(bitcoin::Block);
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        Ok(7)
    }
    fn wait_for_count(&self, n: u64) -> Result<(), BackendError> {
        assert!(n <= 7);
        Ok(())
    }
    fn block_hash(&self, h: u64) -> Result<[u8; 32], BackendError> {
        assert_eq!(h, 0);
        Ok(self.0.hash())
    }
    fn block(&self, h: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        assert_eq!(h, self.0.hash());
        Ok(self.0.clone())
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        panic!("explicit consensus votes only")
    }
    fn broadcast(&self, _: &bitcoin::Transaction) -> Result<(), BackendError> {
        panic!("offline test must not broadcast")
    }
}
fn discover(s: &Store, w: &Wallet, values: &[u64]) {
    let script = w.deposit_script(&key(53843).public_key()).unwrap();
    assert!(w.matches_filter(&script));
    let backend = Backend(bitcoin::Block {
        header: [0; 80],
        transactions: vec![bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            inputs: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid([7; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: u32::MAX,
                witness: vec![],
            }],
            outputs: values
                .iter()
                .map(|&value_sat| bitcoin::TxOut {
                    value_sat,
                    script_pubkey: script.clone(),
                })
                .collect(),
        }],
    });
    for p in 0..3 {
        let item = ConsensusItem::BlockCount(1);
        let batch = w
            .required_scan(&s.snapshot().unwrap(), PeerId(p), &item)
            .unwrap()
            .map(|request| prepare_scan(&backend, request).unwrap());
        let mut tx = s.transaction().unwrap();
        w.process_consensus(&mut tx, PeerId(p), &item, batch.as_ref())
            .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        w.snapshot(&s.snapshot().unwrap())
            .unwrap()
            .output_info_slice(0, u64::MAX)
            .len(),
        values.len()
    );
}
fn fees(s: &Store, w: &Wallet, rate: Option<u64>) {
    for p in 0..3 {
        let mut tx = s.transaction().unwrap();
        w.process_consensus(&mut tx, PeerId(p), &ConsensusItem::FeeRate(rate), None)
            .unwrap();
        tx.commit().unwrap();
    }
}
fn point() -> OutPoint {
    OutPoint {
        txid: [9; 32],
        out_idx: 0,
    }
}
fn input(index: u64, claimant: u64, fee: u64) -> Input {
    Input::V0 {
        output_index: index,
        claimant: key(claimant).public_key(),
        mining_fee_sat: fee,
    }
}
fn output(value: u64, fee: u64, unknown: bool) -> Output {
    Output::V0 {
        destination: if unknown {
            Destination::Unknown {
                tag: 9,
                payload: vec![],
            }
        } else {
            Destination::P2wpkh([8; 20])
        },
        value_sat: value,
        mining_fee_sat: fee,
    }
}
fn rows(s: &Store) -> Vec<minimint_ng::storage::KeyValueRows> {
    let snap = s.snapshot().unwrap();
    [
        Namespace::Replicated,
        Namespace::Local,
        Namespace::Agreement,
        Namespace::Outbox,
        Namespace::ClientBackup,
    ]
    .into_iter()
    .map(|n| snap.scan_prefix(n, &[]).unwrap())
    .collect()
}
fn rejects(
    s: &Store,
    tag: u8,
    call: impl FnOnce(&mut WriteTransaction<'_>) -> Result<(), TransitionError>,
) {
    let before = rows(s);
    let mut tx = s.transaction().unwrap();
    match call(&mut tx).unwrap_err() {
        TransitionError::Module(bytes) => assert_eq!(bytes, [tag, 0]),
        e => panic!("unexpected rejection: {e:?}"),
    }
    drop(tx);
    assert_eq!(rows(s), before);
}
fn claim(s: &Store, w: &Wallet, index: u64, fee: u64) {
    let mut tx = s.transaction().unwrap();
    w.input(&mut tx, &input(index, 53843, fee), point())
        .unwrap();
    tx.commit().unwrap();
}

#[test]
fn input_precedence_and_changed_quote_preserve_unclaimed_discoveries() {
    let dir = fixture::TestDir::new();
    let s = Store::open(dir.path()).unwrap();
    let w = wallet();
    discover(&s, &w, &[100_000, 100_000]);
    // Unknown index precedes claimant and rate; wrong claimant precedes missing rate.
    rejects(&s, 2, |t| {
        w.input(t, &input(99, 123, 0), point()).map(|_| ())
    });
    rejects(&s, 3, |t| {
        w.input(t, &input(0, 123, 0), point()).map(|_| ())
    });
    rejects(&s, 4, |t| {
        w.input(t, &input(0, 53843, 0), point()).map(|_| ())
    });
    fees(&s, &w, Some(1000));
    rejects(&s, 5, |t| {
        w.input(t, &input(0, 53843, 315), point()).map(|_| ())
    });
    // Adequate quote but fee greater than deposit reaches checked subtraction.
    rejects(&s, 6, |t| {
        w.input(t, &input(0, 53843, 100_001), point()).map(|_| ())
    });
    claim(&s, &w, 0, 316);
    fees(&s, &w, None);
    rejects(&s, 1, |t| {
        w.input(t, &input(0, 123, 0), point()).map(|_| ())
    });
    fees(&s, &w, Some(2000));
    rejects(&s, 5, |t| {
        w.input(t, &input(1, 53843, 316), point()).map(|_| ())
    });
    assert_eq!(w.receive_fee(&s.snapshot().unwrap()).unwrap(), Some(632));
    // No quote identity/age check: an older, higher quote remains valid.
    fees(&s, &w, Some(1000));
    claim(&s, &w, 1, 632);
    let view = w.snapshot(&s.snapshot().unwrap()).unwrap();
    assert!(view.output_info_slice(0, 2).iter().all(|d| d.spent));
    assert_eq!(view.wallet.as_ref().unwrap().value_sat, 199_368);
    assert_eq!(view.chain.len(), 1);
    assert_eq!(view.chain[0].fee_sat, 632);
}

#[test]
fn output_precedence_and_exact_dust_change_boundaries() {
    let dir = fixture::TestDir::new();
    let s = Store::open(dir.path()).unwrap();
    let w = wallet();
    // Destination dust beats absent wallet/rate/unknown script.
    rejects(&s, 1, |t| {
        w.output(t, &output(9_999, 0, true), point()).map(|_| ())
    });
    rejects(&s, 2, |t| {
        w.output(t, &output(10_000, 0, true), point()).map(|_| ())
    });
    discover(&s, &w, &[100_000]);
    fees(&s, &w, Some(1000));
    claim(&s, &w, 0, 316);
    fees(&s, &w, None);
    rejects(&s, 3, |t| {
        w.output(t, &output(10_000, 0, true), point()).map(|_| ())
    });
    fees(&s, &w, Some(1000));
    rejects(&s, 4, |t| {
        w.output(t, &output(u64::MAX, 227, true), point())
            .map(|_| ())
    });
    // Distinct addition and subtraction failures precede unknown destination.
    rejects(&s, 6, |t| {
        w.output(t, &output(u64::MAX, 228, true), point())
            .map(|_| ())
    });
    rejects(&s, 6, |t| {
        w.output(t, &output(100_000, 228, true), point())
            .map(|_| ())
    });
    rejects(&s, 5, |t| {
        w.output(t, &output(89_773, 228, true), point()).map(|_| ())
    });
    rejects(&s, 7, |t| {
        w.output(t, &output(89_772, 228, true), point()).map(|_| ())
    });
    // Exactly dust-sized change succeeds and persists a pending transaction.
    let mut tx = s.transaction().unwrap();
    let meta = w
        .output(&mut tx, &output(89_772, 228, false), point())
        .unwrap();
    assert_eq!(meta.amount_msat, 90_000_000);
    tx.commit().unwrap();
    let view = w.snapshot(&s.snapshot().unwrap()).unwrap();
    assert_eq!(view.wallet.as_ref().unwrap().value_sat, 10_000);
    assert_eq!(view.chain.len(), 1);
    assert!(view.transaction_id(point()).is_some());
    // Separate control: destination exactly dust succeeds when change has room.
    let other = fixture::TestDir::new();
    let s = Store::open(other.path()).unwrap();
    discover(&s, &w, &[100_000]);
    fees(&s, &w, Some(1000));
    claim(&s, &w, 0, 316);
    let mut tx = s.transaction().unwrap();
    w.output(&mut tx, &output(10_000, 228, false), point())
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        w.snapshot(&s.snapshot().unwrap())
            .unwrap()
            .wallet
            .unwrap()
            .value_sat,
        89_772
    );
}
