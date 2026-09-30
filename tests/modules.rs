//! Real cross-module state transitions; fixtures supply an observed regtest block.
use minimint_ng::{
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::{ConsensusEncode, text::hex_decode},
    config::{BitcoinNetwork, DescriptorKind, Fee, RawMintConfig, RawWalletConfig},
    core::transaction::{ExecutionError, apply_consensus, transaction_id},
    crypto::{
        bls::{self, G1, G2, Scalar},
        secp::SecretKey,
    },
    modules::{Modules, mint, wallet},
    protocol::{
        DynamicValue, ModuleId, PeerId, Transaction, TransactionError, TransactionSignatures,
        Version,
    },
    storage::{Namespace, Store},
};
use std::collections::BTreeMap;
#[path = "fixtures/storage/mod.rs"]
mod fixture;
const MINT: ModuleId = ModuleId(42);
const WALLET: ModuleId = ModuleId(99);
fn secret(n: u64) -> SecretKey {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_bytes(&b).unwrap()
}
fn modules() -> Modules {
    let public = G2::generator().mul(&Scalar::from_u64(5)).to_bytes();
    let mint = mint::Mint::new(
        MINT,
        PeerId(0),
        RawMintConfig {
            aggregate_keys: (0..42).map(|d| (d, public)).collect(),
            public_shares: (0..42)
                .map(|d| (d, (0..4).map(|i| (PeerId(i), public)).collect()))
                .collect(),
            fee: Fee {
                base: 100,
                parts_per_million: 0,
            },
            amount_unit: 0,
        },
        (0..42).map(|d| (d, Scalar::from_u64(5))).collect(),
    )
    .unwrap();
    let wallet = wallet::Wallet::new(
        WALLET,
        PeerId(0),
        RawWalletConfig {
            bitcoin_pks: (0..4)
                .map(|i| (PeerId(i), secret(u64::from(i) + 1).public_key()))
                .collect(),
            descriptor: DescriptorKind::Wsh,
            send_tx_vbytes: 228,
            receive_tx_vbytes: 316,
            feerate_base: 250,
            dust_limit: 10000,
            fee_consensus: Fee {
                base: 100000,
                parts_per_million: 0,
            },
            network: BitcoinNetwork::Regtest,
        },
        secret(1),
    )
    .unwrap();
    Modules::new(mint, wallet).unwrap()
}
struct Backend(bitcoin::Block);
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        Ok(7)
    }
    fn wait_for_count(&self, n: u64) -> Result<(), BackendError> {
        if n <= 7 { Ok(()) } else { Err(BackendError) }
    }
    fn block_hash(&self, h: u64) -> Result<[u8; 32], BackendError> {
        if h == 0 {
            Ok(self.0.hash())
        } else {
            Err(BackendError)
        }
    }
    fn block(&self, h: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        if h == self.0.hash() {
            Ok(self.0.clone())
        } else {
            Err(BackendError)
        }
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Ok(Some(1000))
    }
    fn broadcast(&self, _: &bitcoin::Transaction) -> Result<(), BackendError> {
        Err(BackendError)
    }
}
fn observe_deposit(store: &Store, modules: &Modules) {
    let script =
        hex_decode("00206760a3fc7b8c1d4f7266aa80773672cd98bc5f3e4e9d6eb2edf300156bef0a06").unwrap();
    assert_eq!(
        modules
            .wallet()
            .deposit_script(&secret(53843).public_key())
            .unwrap(),
        script
    );
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
            outputs: vec![bitcoin::TxOut {
                value_sat: 50000,
                script_pubkey: script,
            }],
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
            let mut tx = store.transaction().unwrap();
            modules
                .wallet()
                .process_consensus(&mut tx, PeerId(peer), &item, prepared.as_ref())
                .unwrap();
            modules.audit(&tx).unwrap();
            tx.commit().unwrap();
        }
    }
}
fn dynamic(id: ModuleId, value: impl ConsensusEncode) -> DynamicValue {
    DynamicValue {
        module_id: id,
        payload: value.consensus_encode(),
    }
}
fn sign(mut tx: Transaction, key: &SecretKey) -> Transaction {
    tx.signatures =
        TransactionSignatures::Schnorr(vec![key.schnorr_sign(&transaction_id(&tx)).unwrap()]);
    tx
}
fn state(store: &Store) -> BTreeMap<u8, Vec<(Vec<u8>, Vec<u8>)>> {
    let snapshot = store.snapshot().unwrap();
    [
        Namespace::Replicated,
        Namespace::Outbox,
        Namespace::Agreement,
        Namespace::Local,
        Namespace::ClientBackup,
    ]
    .into_iter()
    .map(|n| (n as u8, snapshot.scan_prefix(n, b"").unwrap()))
    .collect()
}
#[test]
fn deposit_issuance_reissuance_and_bidirectional_rollback() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = modules();
    observe_deposit(&store, &modules);
    let nonce = secret(9);
    let message = bls::message_sha256(&nonce.public_key()).unwrap();
    let blind = Scalar::from_u64(7);
    let output = mint::Output::V0(mint::OutputV0 {
        denomination: 25,
        blinded_message: mint::G1Bytes::from_bytes(message.mul(&blind).to_bytes()).unwrap(),
        tweak: [0; 16],
    });
    let unsigned = Transaction {
        inputs: vec![dynamic(
            WALLET,
            wallet::Input::V0 {
                output_index: 0,
                claimant: secret(53843).public_key(),
                mining_fee_sat: 316,
            },
        )],
        outputs: vec![dynamic(MINT, output)],
        nonce: [1; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    let before = state(&store);
    let mut failing = unsigned.clone();
    failing.outputs.push(dynamic(
        WALLET,
        wallet::Output::Unknown {
            version: 7,
            payload: vec![],
        },
    ));
    let failing = sign(failing, &secret(53843));
    failing.validate_modules(&modules).unwrap();
    {
        let mut tentative = store.transaction().unwrap();
        assert!(matches!(
            apply_consensus(
                &mut tentative,
                &failing,
                &modules,
                Version { major: 2, minor: 1 }
            ),
            Err(ExecutionError::Rejected(TransactionError::Output(_)))
        ));
    }
    assert_eq!(
        state(&store),
        before,
        "wallet claim and Mint counters/indexes/recovery must all roll back"
    );
    let issued = sign(unsigned, &secret(53843));
    let id = transaction_id(&issued);
    {
        let mut tx = store.transaction().unwrap();
        apply_consensus(&mut tx, &issued, &modules, Version { major: 2, minor: 1 }).unwrap();
        assert_eq!(modules.audit(&tx).unwrap(), 50_000_000 - (1i64 << 25));
        tx.put(
            Namespace::Replicated,
            b"test/history/0",
            &issued.consensus_encode(),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let shares = modules
        .mint()
        .signature_shares(&store.snapshot().unwrap(), id, 0..1)
        .unwrap();
    let signature = G1::from_bytes(&shares[0].to_bytes())
        .unwrap()
        .mul(&blind.inverse().unwrap());
    let note = mint::Note {
        denomination: 25,
        nonce: mint::Nonce::from_bytes(nonce.public_key()).unwrap(),
        signature: mint::G1Bytes::from_bytes(signature.to_bytes()).unwrap(),
    };
    let replacement = mint::Output::V0(mint::OutputV0 {
        denomination: 24,
        blinded_message: mint::G1Bytes::from_bytes(G1::generator().to_bytes()).unwrap(),
        tweak: [3; 16],
    });
    let reissue = Transaction {
        inputs: vec![dynamic(MINT, mint::Input::V0(note))],
        outputs: vec![dynamic(MINT, replacement)],
        nonce: [2; 8],
        signatures: TransactionSignatures::Schnorr(vec![]),
    };
    let before = state(&store);
    let mut bad = reissue.clone();
    bad.outputs.push(dynamic(
        WALLET,
        wallet::Output::Unknown {
            version: 7,
            payload: vec![],
        },
    ));
    let bad = sign(bad, &nonce);
    {
        let mut tx = store.transaction().unwrap();
        assert!(apply_consensus(&mut tx, &bad, &modules, Version { major: 2, minor: 1 }).is_err());
    }
    assert_eq!(
        state(&store),
        before,
        "spent nonce, issuance, recovery and accepted IDs must roll back"
    );
    let reissue = sign(reissue, &nonce);
    {
        let mut tx = store.transaction().unwrap();
        apply_consensus(&mut tx, &reissue, &modules, Version { major: 2, minor: 1 }).unwrap();
        assert_eq!(modules.audit(&tx).unwrap(), 50_000_000 - (1i64 << 24));
        tx.commit().unwrap();
    }
    assert_eq!(
        modules
            .mint()
            .recovery_count(&store.snapshot().unwrap())
            .unwrap(),
        3
    );
}
