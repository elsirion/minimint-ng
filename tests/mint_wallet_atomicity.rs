//! Real consolidation + Mint transitions in the executor's caller-owned writer.
//! The backend supplies a deterministic block; no Core/network interop is claimed.
use minimint_ng::{
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::{ConsensusEncode, decode_whole, text::hex_decode},
    config::{BitcoinNetwork, DescriptorKind, Fee, RawMintConfig, RawWalletConfig},
    core::transaction::{
        ExecutionError, accepted_output_modules, apply_consensus, check_submission, transaction_id,
    },
    crypto::{
        bls::{G1, G2, Scalar},
        secp::SecretKey,
    },
    modules::{Modules, mint, wallet},
    protocol::{
        DynamicValue, ModuleId, PeerId, Transaction, TransactionError, TransactionSignatures,
        Version,
    },
    storage::{KeyValueRows, Namespace, Store},
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};
#[path = "fixtures/storage/mod.rs"]
mod fixture;

const MINT: ModuleId = ModuleId(42);
const WALLET: ModuleId = ModuleId(99);
const VERSION: Version = Version { major: 2, minor: 1 };
const CLAIMANT: u64 = 53843;
const SCRIPT: &str = "00206760a3fc7b8c1d4f7266aa80773672cd98bc5f3e4e9d6eb2edf300156bef0a06";

fn secret(n: u64) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_bytes(&bytes).unwrap()
}

fn wallet(peer: u16) -> wallet::Wallet {
    wallet::Wallet::new(
        WALLET,
        PeerId(peer),
        RawWalletConfig {
            bitcoin_pks: (0..4)
                .map(|p| (PeerId(p), secret(u64::from(p) + 1).public_key()))
                .collect(),
            descriptor: DescriptorKind::Wsh,
            send_tx_vbytes: 228,
            receive_tx_vbytes: 316,
            feerate_base: 250,
            dust_limit: 10000,
            fee_consensus: Fee::wallet(100000, 0).unwrap(),
            network: BitcoinNetwork::Regtest,
        },
        secret(u64::from(peer) + 1),
    )
    .unwrap()
}

fn modules() -> Modules {
    let public = G2::generator().mul(&Scalar::from_u64(5)).to_bytes();
    let mint = mint::Mint::new(
        MINT,
        PeerId(0),
        RawMintConfig {
            aggregate_keys: (0..42).map(|d| (d, public)).collect(),
            public_shares: (0..42)
                .map(|d| (d, (0..4).map(|p| (PeerId(p), public)).collect()))
                .collect(),
            fee: Fee::mint(100, 0).unwrap(),
            amount_unit: 0,
        },
        (0..42).map(|d| (d, Scalar::from_u64(5))).collect(),
    )
    .unwrap();
    Modules::new(mint, wallet(0)).unwrap()
}

struct Backend(bitcoin::Block);
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        Ok(7)
    }
    fn wait_for_count(&self, count: u64) -> Result<(), BackendError> {
        if count <= 7 {
            Ok(())
        } else {
            Err(BackendError)
        }
    }
    fn block_hash(&self, height: u64) -> Result<[u8; 32], BackendError> {
        if height == 0 {
            Ok(self.0.hash())
        } else {
            Err(BackendError)
        }
    }
    fn block(&self, hash: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        if hash == self.0.hash() {
            Ok(self.0.clone())
        } else {
            Err(BackendError)
        }
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Ok(Some(1000))
    }
    fn broadcast(&self, _: &bitcoin::Transaction) -> Result<(), BackendError> {
        panic!("ordered transitions must not broadcast")
    }
}

fn observe_three_deposits(store: &Store, modules: &Modules) {
    let script = hex_decode(SCRIPT).unwrap();
    // Existing independent OpenSSL/filter fixture, with three distinct outpoints.
    assert_eq!(
        modules
            .wallet()
            .deposit_script(&secret(CLAIMANT).public_key())
            .unwrap(),
        script
    );
    assert!(modules.wallet().matches_filter(&script));
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
            outputs: (0..3)
                .map(|_| bitcoin::TxOut {
                    value_sat: 100000,
                    script_pubkey: script.clone(),
                })
                .collect(),
        }],
    });
    for item in [
        wallet::ConsensusItem::BlockCount(1),
        wallet::ConsensusItem::FeeRate(Some(1000)),
    ] {
        for peer in 0..3 {
            let request = modules
                .wallet()
                .required_scan(&store.snapshot().unwrap(), PeerId(peer), &item)
                .unwrap();
            let prepared = request.map(|r| wallet::prepare_scan(&backend, r).unwrap());
            let mut writer = store.transaction().unwrap();
            modules
                .wallet()
                .process_consensus(&mut writer, PeerId(peer), &item, prepared.as_ref())
                .unwrap();
            writer.commit().unwrap();
        }
    }
}

fn dynamic(id: ModuleId, value: impl ConsensusEncode) -> DynamicValue {
    DynamicValue {
        module_id: id,
        payload: value.consensus_encode(),
    }
}

fn mint_output(denomination: u8, marker: u8) -> mint::Output {
    mint::Output::V0(mint::OutputV0 {
        denomination,
        blinded_message: mint::G1Bytes::from_bytes(
            G1::generator()
                .mul(&Scalar::from_u64(u64::from(marker) + 1))
                .to_bytes(),
        )
        .unwrap(),
        tweak: [marker; 16],
    })
}

fn claim(index: u64, nonce: u8, outputs: Vec<mint::Output>) -> Transaction {
    let mut transaction = Transaction {
        inputs: vec![dynamic(
            WALLET,
            wallet::Input::V0 {
                output_index: index,
                claimant: secret(CLAIMANT).public_key(),
                mining_fee_sat: 316,
            },
        )],
        outputs: outputs.into_iter().map(|o| dynamic(MINT, o)).collect(),
        nonce: [nonce; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    transaction.signatures = TransactionSignatures::Schnorr(vec![
        secret(CLAIMANT)
            .schnorr_sign(&transaction_id(&transaction))
            .unwrap(),
    ]);
    transaction
}

fn accept(store: &Store, modules: &Modules, transaction: &Transaction) {
    transaction.validate_modules(modules).unwrap();
    let mut writer = store.transaction().unwrap();
    apply_consensus(&mut writer, transaction, modules, VERSION).unwrap();
    modules.audit(&writer).unwrap();
    writer.commit().unwrap();
}

fn state(store: &Store) -> BTreeMap<u8, KeyValueRows> {
    let snapshot = store.snapshot().unwrap();
    [
        Namespace::Replicated,
        Namespace::Local,
        Namespace::Agreement,
        Namespace::Outbox,
        Namespace::ClientBackup,
    ]
    .into_iter()
    .map(|ns| (ns as u8, snapshot.scan_prefix(ns, b"").unwrap()))
    .collect()
}

fn seed_signed_consolidation(store: &Store, modules: &Modules) {
    observe_three_deposits(store, modules);
    accept(store, modules, &claim(0, 1, vec![mint_output(19, 1)]));
    accept(store, modules, &claim(1, 2, vec![mint_output(19, 2)]));
    for peer in 0..3 {
        let signatures = wallet(peer)
            .local_signatures(&store.snapshot().unwrap())
            .unwrap();
        assert_eq!(signatures.len(), 1);
        let mut writer = store.transaction().unwrap();
        modules
            .wallet()
            .process_consensus(&mut writer, PeerId(peer), &signatures[0], None)
            .unwrap();
        writer.commit().unwrap();
    }
    let snapshot = store.snapshot().unwrap();
    let outbox = snapshot.scan_prefix(Namespace::Outbox, b"").unwrap();
    assert_eq!(
        outbox.len(),
        1,
        "baseline contains a real threshold-signed broadcast job"
    );
    let signed = bitcoin::Transaction::decode(&outbox[0].1).unwrap();
    assert_eq!(signed.inputs.len(), 2);
    assert!(signed.inputs.iter().all(|input| input.witness.len() == 5));
    assert_eq!(
        modules
            .wallet()
            .snapshot(&snapshot)
            .unwrap()
            .wallet
            .unwrap()
            .value_sat,
        199684
    );
    assert_eq!(modules.mint().recovery_count(&snapshot).unwrap(), 2);
}

#[test]
fn failed_consolidation_rolls_back_populated_wallet_mint_and_outbox_state() {
    for funding_failure in [false, true] {
        let dir = fixture::TestDir::new();
        let store = Store::open(dir.path()).unwrap();
        let modules = modules();
        seed_signed_consolidation(&store, &modules);
        let baseline = state(&store);
        let first = mint_output(20, 10);
        let mint::Output::V0(first_v0) = &first else {
            unreachable!()
        };
        let late = mint_output(if funding_failure { 30 } else { 255 }, 11);
        let failing = claim(2, 3, vec![first.clone(), late]);
        failing.validate_modules(&modules).unwrap();
        let id = transaction_id(&failing);

        let reject = |error: ExecutionError| {
            if funding_failure {
                assert!(matches!(
                    error,
                    ExecutionError::Rejected(TransactionError::UnbalancedTransaction {
                        inputs: 99684000,
                        outputs: 1074790400,
                        fee: 100200,
                    })
                ));
            } else {
                let ExecutionError::Rejected(TransactionError::Output(value)) = error else {
                    panic!("expected late Mint rejection")
                };
                assert_eq!(value.module_id, MINT);
                assert_eq!(
                    value.payload,
                    mint::OutputError::InvalidDenomination.consensus_encode()
                );
            }
        };
        reject(check_submission(&store, &failing, &modules, VERSION).unwrap_err());
        assert!(
            state(&store) == baseline,
            "submission must discard every tentative namespace change"
        );
        {
            let mut writer = store.transaction().unwrap();
            reject(apply_consensus(&mut writer, &failing, &modules, VERSION).unwrap_err());
            // These changed audits prove the valid Wallet consolidation and first
            // real Mint share/counter writes occurred before the later rejection.
            assert_eq!(modules.wallet().audit(&writer).unwrap(), 299368000);
            assert_eq!(
                modules.mint().audit(&writer).unwrap(),
                -((2_i64 << 19) + (1_i64 << 20) + if funding_failure { 1_i64 << 30 } else { 0 })
            );
            assert!(
                writer.scan_prefix(Namespace::Replicated, b"").unwrap()
                    != baseline[&(Namespace::Replicated as u8)]
            );
            assert!(
                writer.scan_prefix(Namespace::Outbox, b"").unwrap()
                    == baseline[&(Namespace::Outbox as u8)]
            );
            // Executor contract: the caller discards the whole writer on error.
        }
        assert!(
            state(&store) == baseline,
            "failed consensus transition must preserve the full populated store"
        );
        let snapshot = store.snapshot().unwrap();
        let view = modules.wallet().snapshot(&snapshot).unwrap();
        assert!(!view.output_info_slice(2, 3)[0].spent);
        assert_eq!(view.wallet.unwrap().value_sat, 199684);
        assert_eq!((view.chain.len(), view.pending_chain.len()), (1, 1));
        assert_eq!(modules.mint().recovery_count(&snapshot).unwrap(), 2);
        assert!(
            modules
                .mint()
                .signature_shares(&snapshot, id, 0..2)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            modules
                .mint()
                .recovery_signature_shares(&snapshot, &[first_v0.blinded_message]),
            Err(mint::ReadError::MissingShare)
        ));
        assert_eq!(accepted_output_modules(&snapshot, &id).unwrap(), None);

        let control = claim(2, 4, vec![first, mint_output(21, 12)]);
        accept(&store, &modules, &control);
        let snapshot = store.snapshot().unwrap();
        let view = modules.wallet().snapshot(&snapshot).unwrap();
        assert!(view.output_info_slice(2, 3)[0].spent);
        assert_eq!((view.chain.len(), view.pending_chain.len()), (2, 2));
        let current = view.wallet.unwrap();
        assert_eq!(current.value_sat, 299368);
        assert_eq!(
            current.outpoint,
            bitcoin::OutPoint {
                txid: view.chain[1].txid,
                vout: 0
            }
        );
        assert_eq!(
            (
                view.chain[1].input_sat,
                view.chain[1].output_sat,
                view.chain[1].fee_sat
            ),
            (199684, 299368, 316)
        );
        assert_eq!(
            modules.wallet().local_signatures(&snapshot).unwrap().len(),
            1
        );
        assert_eq!(modules.mint().recovery_count(&snapshot).unwrap(), 4);
        assert_eq!(
            modules
                .mint()
                .signature_shares(&snapshot, transaction_id(&control), 0..2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            accepted_output_modules(&snapshot, &transaction_id(&control)).unwrap(),
            Some(vec![MINT, MINT])
        );
        assert!(
            snapshot.scan_prefix(Namespace::Outbox, b"").unwrap()
                == baseline[&(Namespace::Outbox as u8)],
            "the older signed broadcast job survives; the new consolidation is still unsigned"
        );
    }
}

struct CrashChild(Child);
impl Drop for CrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn publish(path: &Path, bytes: &[u8]) {
    let temporary = path.with_extension("pending");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::rename(temporary, path).unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

struct DeliveryBackend {
    stop_before_ack: Option<PathBuf>,
    delivered: RefCell<Vec<Vec<u8>>>,
}
impl BitcoinBackend for DeliveryBackend {
    fn block_count(&self) -> Result<u64, BackendError> {
        Err(BackendError)
    }
    fn wait_for_count(&self, _: u64) -> Result<(), BackendError> {
        Err(BackendError)
    }
    fn block_hash(&self, _: u64) -> Result<[u8; 32], BackendError> {
        Err(BackendError)
    }
    fn block(&self, _: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        Err(BackendError)
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Err(BackendError)
    }
    fn broadcast(&self, transaction: &bitcoin::Transaction) -> Result<(), BackendError> {
        let bytes = transaction.encode();
        if let Some(root) = &self.stop_before_ack {
            // Controlled remote-delivery observation, deliberately before the
            // backend returns acknowledgement to Wallet::broadcast_pending.
            publish(&root.join("delivered.bin"), &bytes);
            publish(&root.join("ready"), b"delivered-before-ack");
            loop {
                thread::park();
            }
        }
        self.delivered.borrow_mut().push(bytes);
        Ok(())
    }
}

#[test]
fn wallet_outbox_crash_child() {
    let Ok(mode) = std::env::var("MINIMINT_WALLET_OUTBOX_CRASH") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("MINIMINT_WALLET_OUTBOX_DIRECTORY").unwrap());
    let store = Store::open(root.join("store")).unwrap();
    let modules = modules();
    seed_signed_consolidation(&store, &modules);
    let checkpoint = state(&store);
    let outbox = &checkpoint[&(Namespace::Outbox as u8)];
    assert_eq!(outbox.len(), 1);
    let encoded: BTreeMap<u8, BTreeMap<Vec<u8>, Vec<u8>>> = checkpoint
        .iter()
        .map(|(namespace, rows)| (*namespace, rows.iter().cloned().collect()))
        .collect();
    publish(&root.join("checkpoint.bin"), &encoded.consensus_encode());
    publish(&root.join("signed-transaction.bin"), &outbox[0].1);
    if mode == "before-broadcast" {
        publish(&root.join("ready"), b"before-broadcast");
        loop {
            thread::park();
        }
    }
    assert_eq!(mode, "delivered-before-ack");
    let backend = DeliveryBackend {
        stop_before_ack: Some(root),
        delivered: RefCell::new(vec![]),
    };
    modules
        .wallet()
        .broadcast_pending(&store, &backend)
        .unwrap();
    panic!("controlled backend unexpectedly acknowledged before process kill");
}

#[cfg(target_os = "linux")]
#[test]
fn committed_wallet_outbox_retries_identical_bytes_across_sigkill_boundaries() {
    use std::os::unix::process::ExitStatusExt;
    // SIGKILL tests daemon-process crashes, not host power loss or Core mempool
    // admission. The parent owns/reaps each child even on assertion failure.
    for mode in ["before-broadcast", "delivered-before-ack"] {
        let directory = fixture::TestDir::new();
        let mut child = CrashChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "wallet_outbox_crash_child", "--nocapture"])
                .env("MINIMINT_WALLET_OUTBOX_CRASH", mode)
                .env("MINIMINT_WALLET_OUTBOX_DIRECTORY", directory.path())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !directory.path().join("ready").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child stopped before the durable boundary"
            );
            assert!(
                Instant::now() < deadline,
                "outbox boundary deadline; guard kills/reaps child"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            fs::read(directory.path().join("ready")).unwrap(),
            mode.as_bytes()
        );
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(9),
            "must exercise SIGKILL without destructors"
        );
        let encoded: BTreeMap<u8, BTreeMap<Vec<u8>, Vec<u8>>> =
            decode_whole(&fs::read(directory.path().join("checkpoint.bin")).unwrap()).unwrap();
        let expected: BTreeMap<u8, KeyValueRows> = encoded
            .into_iter()
            .map(|(namespace, rows)| (namespace, rows.into_iter().collect()))
            .collect();
        let signed = fs::read(directory.path().join("signed-transaction.bin")).unwrap();
        if mode == "delivered-before-ack" {
            assert!(fs::read(directory.path().join("delivered.bin")).unwrap() == signed);
        } else {
            assert!(!directory.path().join("delivered.bin").exists());
        }
        // An acknowledged retry also leaves the job until block observation.
        // Reopen once more and prove the next attempt remains byte-identical.
        for _ in 0..2 {
            let store = Store::open(directory.path().join("store")).unwrap();
            let modules = modules();
            assert!(
                state(&store) == expected,
                "committed namespaces changed across process crash/reopen"
            );
            let snapshot = store.snapshot().unwrap();
            let view = modules.wallet().snapshot(&snapshot).unwrap();
            assert_eq!((view.chain.len(), view.pending_chain.len()), (1, 1));
            assert_eq!(view.wallet.as_ref().unwrap().value_sat, 199684);
            let transaction = bitcoin::Transaction::decode(&signed).unwrap();
            assert_eq!(
                view.wallet.as_ref().unwrap().outpoint,
                bitcoin::OutPoint {
                    txid: transaction.txid(),
                    vout: 0
                }
            );
            assert_eq!(view.chain[0].txid, transaction.txid());
            assert!(
                view.output_info_slice(0, 2)
                    .iter()
                    .all(|output| output.spent)
            );
            assert!(!view.output_info_slice(2, 3)[0].spent);
            assert_eq!(modules.mint().recovery_count(&snapshot).unwrap(), 2);
            assert!(
                modules
                    .wallet()
                    .local_signatures(&snapshot)
                    .unwrap()
                    .is_empty(),
                "retry must use the committed signed witness"
            );
            {
                let writer = store.transaction().unwrap();
                assert_eq!(modules.wallet().audit(&writer).unwrap(), 199684000);
                assert_eq!(modules.mint().audit(&writer).unwrap(), -(2_i64 << 19));
                assert_eq!(modules.audit(&writer).unwrap(), 198635424);
            }
            let backend = DeliveryBackend {
                stop_before_ack: None,
                delivered: RefCell::new(vec![]),
            };
            modules
                .wallet()
                .broadcast_pending(&store, &backend)
                .unwrap();
            assert!(backend.delivered.borrow().as_slice() == [signed.clone()]);
            assert!(
                state(&store) == expected,
                "broadcast acknowledgement must not mutate accounting or remove the outbox job"
            );
        }
    }
}
