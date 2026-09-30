use minimint_ng::{
    bitcoin::{self, BackendError, BitcoinBackend},
    codec::{
        ConsensusEncode, decode_whole,
        text::{hex_decode, hex_encode},
    },
    config::{BitcoinNetwork, DescriptorKind, Fee, RawWalletConfig},
    core::transaction::TransitionError,
    crypto::{
        secp::{self, SecretKey},
        sha256,
    },
    modules::wallet::*,
    protocol::{ModuleId, OutPoint, PeerId},
    storage::{Namespace, Store},
};
use std::cell::{Cell, RefCell};
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn secret(n: u64) -> SecretKey {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_bytes(&b).unwrap()
}
fn config() -> RawWalletConfig {
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
    }
}
fn wallet(peer: u16) -> Wallet {
    Wallet::new(
        ModuleId(42),
        PeerId(peer),
        config(),
        secret(u64::from(peer) + 1),
    )
    .unwrap()
}
#[derive(Default)]
struct Backend {
    blocks: RefCell<Vec<bitcoin::Block>>,
    waits: RefCell<Vec<u64>>,
    sent: RefCell<Vec<bitcoin::Transaction>>,
    fail: Cell<bool>,
    reject_parent: Cell<bool>,
    attempted: RefCell<Vec<bitcoin::Txid>>,
    wrong_hash: Cell<bool>,
}
impl BitcoinBackend for Backend {
    fn block_count(&self) -> Result<u64, BackendError> {
        Ok(self.blocks.borrow().len() as u64 + 6)
    }
    fn wait_for_count(&self, n: u64) -> Result<(), BackendError> {
        self.waits.borrow_mut().push(n);
        Ok(())
    }
    fn block_hash(&self, h: u64) -> Result<[u8; 32], BackendError> {
        self.blocks
            .borrow()
            .get(h as usize)
            .map(bitcoin::Block::hash)
            .ok_or(BackendError)
    }
    fn block(&self, h: [u8; 32]) -> Result<bitcoin::Block, BackendError> {
        let mut b = self
            .blocks
            .borrow()
            .iter()
            .find(|b| b.hash() == h)
            .cloned()
            .ok_or(BackendError)?;
        if self.wrong_hash.get() {
            b.header[0] ^= 1;
        }
        Ok(b)
    }
    fn fee_rate(&self) -> Result<Option<u64>, BackendError> {
        Ok(Some(1000))
    }
    fn broadcast(&self, t: &bitcoin::Transaction) -> Result<(), BackendError> {
        self.attempted.borrow_mut().push(t.txid());
        if self.fail.get() || self.reject_parent.get() && t.inputs.len() == 2 {
            return Err(BackendError);
        }
        self.sent.borrow_mut().push(t.clone());
        Ok(())
    }
}
fn consensus(
    store: &Store,
    wallet: &Wallet,
    peer: u16,
    item: ConsensusItem,
    backend: &Backend,
) -> Result<(), WalletError> {
    let request = wallet.required_scan(&store.snapshot()?, PeerId(peer), &item)?;
    let batch = request.map(|r| prepare_scan(backend, r)).transpose()?;
    let mut tx = store.transaction()?;
    wallet.process_consensus(&mut tx, PeerId(peer), &item, batch.as_ref())?;
    tx.commit()?;
    Ok(())
}
fn fees(store: &Store, w: &Wallet, backend: &Backend) {
    for peer in 0..3 {
        consensus(store, w, peer, ConsensusItem::FeeRate(Some(1000)), backend).unwrap();
    }
}
fn point(index: u64) -> OutPoint {
    OutPoint {
        txid: [9; 32],
        out_idx: index,
    }
}
fn rejection(error: TransitionError) -> Vec<u8> {
    match error {
        TransitionError::Module(bytes) => bytes,
        _ => panic!("expected module rejection"),
    }
}
fn deposit_transaction(script: Vec<u8>, value: u64) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        inputs: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid([7; 32]),
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        outputs: vec![bitcoin::TxOut {
            value_sat: value,
            script_pubkey: script,
        }],
    }
}
fn advance(store: &Store, w: &Wallet, backend: &Backend, value: u64) {
    for peer in 0..3 {
        consensus(store, w, peer, ConsensusItem::BlockCount(value), backend).unwrap();
    }
}

#[test]
fn empty_state_fee_order_statistics_and_no_proposer_floor_on_admission() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let w = wallet(0);
    let backend = Backend::default();
    let view = w.snapshot(&store.snapshot().unwrap()).unwrap();
    assert_eq!(view.block_count, 0);
    assert_eq!(w.send_fee(&store.snapshot().unwrap()).unwrap(), None);
    assert_eq!(w.receive_fee(&store.snapshot().unwrap()).unwrap(), None);
    assert!(view.wallet.is_none());
    assert!(view.chain.is_empty());
    assert!(view.output_info_slice(0, 10).is_empty());
    for (peer, rate) in [(0, 900), (1, 500), (2, 100)] {
        consensus(
            &store,
            &w,
            peer,
            ConsensusItem::FeeRate(Some(rate)),
            &backend,
        )
        .unwrap();
    }
    assert_eq!(
        w.snapshot(&store.snapshot().unwrap())
            .unwrap()
            .consensus_fee_rate,
        Some(900)
    );
    consensus(&store, &w, 3, ConsensusItem::FeeRate(Some(600)), &backend).unwrap();
    assert_eq!(
        w.snapshot(&store.snapshot().unwrap())
            .unwrap()
            .consensus_fee_rate,
        Some(600)
    );
    assert!(consensus(&store, &w, 3, ConsensusItem::FeeRate(Some(600)), &backend).is_err());
    consensus(&store, &w, 0, ConsensusItem::FeeRate(None), &backend).unwrap();
    consensus(&store, &w, 1, ConsensusItem::FeeRate(None), &backend).unwrap();
    assert_eq!(
        w.snapshot(&store.snapshot().unwrap())
            .unwrap()
            .consensus_fee_rate,
        None
    );
    assert_eq!(
        Wallet::fee_proposal(Some(1)),
        ConsensusItem::FeeRate(Some(1000))
    );
    assert_eq!(Wallet::fee_proposal(None), ConsensusItem::FeeRate(None));
    assert_eq!(
        w.block_proposal(&store.snapshot().unwrap(), 5).unwrap(),
        ConsensusItem::BlockCount(0)
    );
}
#[test]
fn block_scan_boundaries_hash_validation_and_stale_preparation() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let w = wallet(0);
    let backend = Backend::default();
    backend.blocks.borrow_mut().push(bitcoin::Block {
        header: [0; 80],
        transactions: vec![],
    });
    for peer in 0..2 {
        consensus(&store, &w, peer, ConsensusItem::BlockCount(1), &backend).unwrap();
    }
    let item = ConsensusItem::BlockCount(1);
    let request = w
        .required_scan(&store.snapshot().unwrap(), PeerId(2), &item)
        .unwrap()
        .unwrap();
    assert_eq!(
        request,
        ScanRequest {
            from: 0,
            to: 1,
            skip_scan: false
        }
    );
    backend.wrong_hash.set(true);
    assert!(matches!(
        prepare_scan(&backend, request.clone()),
        Err(WalletError::Backend(_))
    ));
    backend.wrong_hash.set(false);
    let batch = prepare_scan(&backend, request).unwrap();
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        w.process_consensus(&mut tx, PeerId(2), &item, None),
        Err(WalletError::StaleScan)
    ));
    drop(tx);
    consensus(&store, &w, 3, item.clone(), &backend).unwrap();
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        w.process_consensus(&mut tx, PeerId(2), &item, Some(&batch)),
        Err(WalletError::StaleScan)
    ));
    drop(tx);
    consensus(&store, &w, 2, item.clone(), &backend).unwrap();
    assert_eq!(
        w.snapshot(&store.snapshot().unwrap()).unwrap().block_count,
        1
    );
    assert!(backend.waits.borrow().iter().all(|n| *n == 7));
    assert_eq!(
        w.block_proposal(&store.snapshot().unwrap(), 100).unwrap(),
        ConsensusItem::BlockCount(6)
    );
    assert!(consensus(&store, &w, 2, item, &backend).is_err());
}
#[test]
fn nonregtest_first_advance_skips_blocks_but_waits_for_burial() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut cfg = config();
    cfg.network = BitcoinNetwork::Mainnet;
    let w = Wallet::new(ModuleId(42), PeerId(0), cfg, secret(1)).unwrap();
    let backend = Backend::default();
    advance(&store, &w, &backend, 100);
    assert_eq!(*backend.waits.borrow(), vec![106]);
    assert_eq!(
        w.snapshot(&store.snapshot().unwrap()).unwrap().block_count,
        100
    );
}
#[test]
fn wire_variants_exact_lengths_and_unsupported_version_errors() {
    let input = Input::V0 {
        output_index: 253,
        claimant: secret(1).public_key(),
        mining_fee_sat: 316,
    };
    assert_eq!(
        decode_whole::<Input>(&input.consensus_encode()).unwrap(),
        input
    );
    let mut trailing = input.consensus_encode();
    trailing.push(0);
    assert!(decode_whole::<Input>(&trailing).is_err());
    for destination in [
        Destination::P2pkh([1; 20]),
        Destination::P2sh([2; 20]),
        Destination::P2wpkh([3; 20]),
        Destination::P2wsh([4; 32]),
        Destination::P2tr([5; 32]),
    ] {
        assert_eq!(
            decode_whole::<Destination>(&destination.consensus_encode()).unwrap(),
            destination
        );
        assert!(destination.script_pubkey().is_some());
    }
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let w = wallet(0);
    let mut tx = store.transaction().unwrap();
    assert_eq!(
        rejection(
            w.input(
                &mut tx,
                &Input::Unknown {
                    version: 9,
                    payload: vec![]
                },
                point(0)
            )
            .err()
            .unwrap()
        ),
        [0, 1, 9]
    );
    assert_eq!(
        rejection(
            w.output(
                &mut tx,
                &Output::Unknown {
                    version: 9,
                    payload: vec![]
                },
                point(0)
            )
            .err()
            .unwrap()
        ),
        [0, 1, 9]
    );
    assert_eq!(
        rejection(
            w.output(
                &mut tx,
                &Output::V0 {
                    destination: Destination::Unknown {
                        tag: 9,
                        payload: vec![]
                    },
                    value_sat: 1,
                    mining_fee_sat: 0
                },
                point(0)
            )
            .err()
            .unwrap()
        ),
        [1, 0]
    );
}

const CLAIMANT: u64 = 53843;
const DEPOSIT_SCRIPT: &str = "00206760a3fc7b8c1d4f7266aa80773672cd98bc5f3e4e9d6eb2edf300156bef0a06";
fn prepare_deposits(store: &Store, w: &Wallet, backend: &Backend, value: u64) -> bitcoin::Txid {
    let gap = (0_u32..1_000_000)
        .map(|n| [vec![0x6a, 4], n.to_le_bytes().to_vec()].concat())
        .find(|s| w.matches_filter(s))
        .unwrap();
    let mut deposits = deposit_transaction(hex_decode(DEPOSIT_SCRIPT).unwrap(), value);
    deposits.outputs.push(deposits.outputs[0].clone());
    let id = deposits.txid();
    backend.blocks.borrow_mut().push(bitcoin::Block {
        header: [0; 80],
        transactions: vec![deposit_transaction(gap, 1), deposits],
    });
    advance(store, w, backend, 1);
    fees(store, w, backend);
    id
}
fn claim(store: &Store, w: &Wallet, index: u64, fee: u64) {
    let mut tx = store.transaction().unwrap();
    w.input(
        &mut tx,
        &Input::V0 {
            output_index: index,
            claimant: secret(CLAIMANT).public_key(),
            mining_fee_sat: fee,
        },
        point(index),
    )
    .unwrap();
    tx.commit().unwrap();
}
#[test]
fn independent_openssl_tweaked_multisig_and_filter_fixture() {
    // fixtures/wallet/filter.json was generated independently using OpenSSL EC + Python hashlib.
    let w = wallet(0);
    let public = secret(CLAIMANT).public_key();
    assert_eq!(
        hex_encode(&public),
        "0312b6469842c193875931f55525b96f168f64465487ae5a5128b7fce5f12c42d8"
    );
    assert_eq!(
        hex_encode(&w.deposit_script(&public).unwrap()),
        DEPOSIT_SCRIPT
    );
    assert_eq!(
        hex_encode(&w.witness_script(&sha256(&public)).unwrap()),
        "5321024743f3fb3b21bc88abff980bd6b6325a4c75f43328444dd0cab816decc1aeb39210260e173879b4a6c4269eed33debbf971fde46ebf08facffed54afd35364585b2121035208161ba089e850675cc60a01fd0f701fe8e031dbd4835f5f4c08a46d2e1aff2103f9804236278cedbdefbb992ccc7693abdaff0adde7d7fecb7b33cf29c989aa0b54ae"
    );
    assert!(w.matches_filter(&hex_decode(DEPOSIT_SCRIPT).unwrap()));
    assert_eq!(w.witness_script(&[0; 32]).unwrap().len(), 139);
    assert!(w.witness_script(&[255; 32]).is_err());
    assert!(Wallet::new(ModuleId(42), PeerId(0), config(), secret(2)).is_err());
}
#[test]
fn deposits_pending_change_signer_order_outbox_and_multi_confirmation() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let w = wallet(0);
    let backend = Backend::default();
    let deposit_id = prepare_deposits(&store, &w, &backend, 1_000_000);
    let view = w.snapshot(&store.snapshot().unwrap()).unwrap();
    assert_eq!(
        view.output_info_slice(0, 3)
            .iter()
            .map(|d| d.index)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        w.receive_fee(&store.snapshot().unwrap()).unwrap(),
        Some(316)
    );
    assert_eq!(w.send_fee(&store.snapshot().unwrap()).unwrap(), Some(228));
    let mut tx = store.transaction().unwrap();
    let input = Input::V0 {
        output_index: 1,
        claimant: secret(CLAIMANT).public_key(),
        mining_fee_sat: 316,
    };
    let meta = w.input(&mut tx, &input, point(0)).unwrap();
    assert_eq!(meta.amount_msat, 999_684_000);
    assert_eq!(meta.fee_msat, 100000);
    assert_eq!(w.audit(&tx).unwrap(), 1_000_000_000);
    drop(tx);
    assert!(
        w.snapshot(&store.snapshot().unwrap())
            .unwrap()
            .wallet
            .is_none()
    );
    assert!(
        !w.snapshot(&store.snapshot().unwrap())
            .unwrap()
            .output_info_slice(1, 2)[0]
            .spent
    );
    claim(&store, &w, 1, 316);
    let view = w.snapshot(&store.snapshot().unwrap()).unwrap();
    assert!(view.chain.is_empty());
    assert_eq!(view.wallet.as_ref().unwrap().value_sat, 1_000_000);
    assert_eq!(
        view.wallet.unwrap().outpoint,
        bitcoin::OutPoint {
            txid: deposit_id,
            vout: 0
        }
    );
    let mut tx = store.transaction().unwrap();
    assert_eq!(
        rejection(w.input(&mut tx, &input, point(0)).err().unwrap()),
        [1, 0]
    );
    drop(tx);
    claim(&store, &w, 2, 316);
    let view = w.snapshot(&store.snapshot().unwrap()).unwrap();
    assert_eq!(view.chain.len(), 1);
    assert_eq!(view.chain[0].input_sat, 1_000_000);
    assert_eq!(view.chain[0].output_sat, 1_999_684);
    assert_eq!(view.chain[0].vbytes, 316);
    let mut tx = store.transaction().unwrap();
    let output = Output::V0 {
        destination: Destination::P2wpkh([8; 20]),
        value_sat: 100000,
        mining_fee_sat: 228,
    };
    let meta = w.output(&mut tx, &output, point(9)).unwrap();
    assert_eq!(meta.amount_msat, 100_228_000);
    tx.commit().unwrap();
    let view = w.snapshot(&store.snapshot().unwrap()).unwrap();
    assert_eq!(view.wallet.as_ref().unwrap().value_sat, 1_899_456);
    assert_eq!(view.chain.len(), 2);
    assert_eq!(view.chain[1].vbytes, 228);
    assert_eq!(view.transaction_id(point(9)), Some(view.chain[1].txid));
    assert_eq!(
        view.pending_chain
            .iter()
            .map(|r| r.index)
            .collect::<Vec<_>>(),
        vec![1, 0]
    );
    let proposals: Vec<_> = (0..4)
        .map(|peer| {
            wallet(peer)
                .local_signatures(&store.snapshot().unwrap())
                .unwrap()
        })
        .collect();
    // Verify invalid signatures precede duplicate-list rejection.
    consensus(&store, &w, 3, proposals[3][0].clone(), &backend).unwrap();
    let mut invalid = proposals[3][0].clone();
    if let ConsensusItem::Signatures { signatures, .. } = &mut invalid {
        signatures[0] = [0; 64];
    }
    assert!(matches!(
        consensus(&store, &w, 3, invalid, &backend),
        Err(WalletError::Rejected("invalid-signature"))
    ));
    assert!(matches!(
        consensus(&store, &w, 3, proposals[3][0].clone(), &backend),
        Err(WalletError::Rejected("duplicate-signature-list"))
    ));
    for (index, _) in view.chain.iter().enumerate() {
        for peer in [3, 0, 2] {
            if index == 0 && peer == 3 {
                continue;
            }
            if index == 0 && peer == 2 {
                let mut tentative = store.transaction().unwrap();
                w.process_consensus(
                    &mut tentative,
                    PeerId(peer),
                    &proposals[peer as usize][index],
                    None,
                )
                .unwrap();
                assert_eq!(
                    tentative.scan_prefix(Namespace::Outbox, b"").unwrap().len(),
                    1
                );
                drop(tentative);
                assert!(
                    store
                        .snapshot()
                        .unwrap()
                        .scan_prefix(Namespace::Outbox, b"")
                        .unwrap()
                        .is_empty()
                );
            }
            consensus(
                &store,
                &w,
                peer,
                proposals[peer as usize][index].clone(),
                &backend,
            )
            .unwrap();
        }
    }
    assert!(matches!(
        consensus(&store, &w, 1, proposals[1][0].clone(), &backend),
        Err(WalletError::Rejected("missing-unsigned-transaction"))
    ));
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Outbox, b"")
            .unwrap()
            .len(),
        2
    );
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    backend.fail.set(true);
    assert!(w.broadcast_pending(&store, &backend).is_err());
    assert_eq!(
        w.snapshot(&store.snapshot().unwrap())
            .unwrap()
            .pending_chain
            .len(),
        2
    );
    assert_eq!(backend.attempted.borrow().len(), 2);
    backend.fail.set(false);
    backend.reject_parent.set(true);
    assert!(w.broadcast_pending(&store, &backend).is_err());
    assert_eq!(backend.attempted.borrow().len(), 4);
    // The child succeeds even when the already-confirmed ancestor is rejected.
    assert_eq!(backend.sent.borrow().len(), 1);
    assert_eq!(backend.sent.borrow()[0].inputs.len(), 1);
    assert_eq!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Outbox, b"")
            .unwrap()
            .len(),
        2
    );
    backend.sent.borrow_mut().clear();
    backend.reject_parent.set(false);
    w.broadcast_pending(&store, &backend).unwrap();
    let signed = backend.sent.borrow().clone();
    assert_eq!(signed.len(), 2);
    assert_eq!(signed[0].inputs.len(), 2);
    assert_eq!(signed[1].inputs.len(), 1);
    for transaction in &signed {
        for input in &transaction.inputs {
            assert_eq!(input.sequence, 0xffff_fffd);
            assert!(input.script_sig.is_empty());
            assert_eq!(input.witness.len(), 5);
            assert!(input.witness[0].is_empty());
            assert_eq!(input.witness.last().unwrap().len(), 139);
            for der in &input.witness[1..4] {
                assert_eq!(der.last(), Some(&1));
                assert!(secp::ecdsa_der_to_compact(&der[..der.len() - 1]).is_ok());
            }
        }
    }
    let consolidation = signed.iter().find(|t| t.inputs.len() == 2).unwrap();
    let withdrawal = signed.iter().find(|t| t.inputs.len() == 1).unwrap();
    assert_eq!(
        hex_encode(&consolidation.encode_without_witness()),
        include_str!("../fixtures/wallet/consolidation.hex").trim()
    );
    assert_eq!(
        hex_encode(&withdrawal.encode_without_witness()),
        include_str!("../fixtures/wallet/withdrawal.hex").trim()
    );
    assert_eq!(
        hex_encode(&consolidation.txid().0),
        "bdac852bf822054a4e028fb255a163b252bd16eab3d7c15ff46f0d33dcf75f73"
    );
    assert_eq!(
        hex_encode(&withdrawal.txid().0),
        "d3d2b91ed9aafe1dc8de2b8ab9188aa6c2957d1134e53ba05e2e1432ed46d288"
    );
    assert_eq!(
        hex_encode(
            &withdrawal
                .sighash_all(0, withdrawal.inputs[0].witness.last().unwrap(), 1_999_684)
                .unwrap()
        ),
        "b6ebfc40aaec0391b3b84d3fc7341cec2183405b6905db3c57bbc53a869c5704"
    );
    assert_eq!(
        withdrawal.inputs[0].previous_output.txid,
        consolidation.txid()
    );
    // All selected signature lists verify in the tweaked script-key order.
    let tweak = sha256(&secret(CLAIMANT).public_key());
    let hash = consolidation
        .sighash_all(
            0,
            consolidation.inputs[0].witness.last().unwrap(),
            1_000_000,
        )
        .unwrap();
    assert_eq!(
        hex_encode(&hash),
        "1692cb3c4b012489a221dd8af407883ff326a241f7a9dda8fac992369c7b242c"
    );
    let mut selected: Vec<_> = [3, 0, 2]
        .into_iter()
        .map(|peer| secp::add_tweak(&secret(peer + 1).public_key(), &tweak).unwrap())
        .collect();
    selected.sort();
    for (key, der) in selected.iter().zip(&consolidation.inputs[0].witness[1..4]) {
        secp::ecdsa_verify(
            key,
            &hash,
            &secp::ecdsa_der_to_compact(&der[..der.len() - 1]).unwrap(),
        )
        .unwrap();
    }
    backend.blocks.borrow_mut().push(bitcoin::Block {
        header: [1; 80],
        transactions: vec![consolidation.clone(), withdrawal.clone()],
    });
    advance(&store, &w, &backend, 2);
    let view = w.snapshot(&store.snapshot().unwrap()).unwrap();
    assert!(view.pending_chain.is_empty());
    assert_eq!(view.chain.len(), 2);
    assert_eq!(view.chain[0].vbytes, 316);
    assert_eq!(view.chain[1].vbytes, 228);
    assert!(
        store
            .snapshot()
            .unwrap()
            .scan_prefix(Namespace::Outbox, b"")
            .unwrap()
            .is_empty()
    );
    assert!(backend.waits.borrow().contains(&8));
}
#[test]
fn fee_at_32_allows_33rd_then_quote_has_fatal_invariant() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let w = wallet(0);
    let backend = Backend::default();
    prepare_deposits(&store, &w, &backend, 1_000_000_000_000_000);
    claim(&store, &w, 1, 316);
    for index in 0..33 {
        let fee = w.send_fee(&store.snapshot().unwrap()).unwrap().unwrap();
        let mut tx = store.transaction().unwrap();
        w.output(
            &mut tx,
            &Output::V0 {
                destination: Destination::P2wpkh([8; 20]),
                value_sat: 10000,
                mining_fee_sat: fee,
            },
            point(index),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let view = w.snapshot(&store.snapshot().unwrap()).unwrap();
    assert_eq!(view.block_count, 1);
    assert_eq!(view.chain.len(), 33);
    assert!(view.wallet.is_some());
    assert!(matches!(
        w.send_fee(&store.snapshot().unwrap()),
        Err(WalletError::Invariant("wallet-pending-count-exceeds-32"))
    ));
    let mut tx = store.transaction().unwrap();
    assert!(matches!(
        w.output(
            &mut tx,
            &Output::V0 {
                destination: Destination::P2wpkh([8; 20]),
                value_sat: 10000,
                mining_fee_sat: 0
            },
            point(33)
        ),
        Err(TransitionError::FatalInvariant(
            "wallet-pending-count-exceeds-32"
        ))
    ));
}

#[test]
fn long_bitcoin_scripts_use_compactsize_for_filter_and_consume_indices() {
    // Independent Python hashlib fixture in fixtures/wallet/long-script-filter.json.
    let mut script = vec![0; 249];
    script.extend(16165_u32.to_le_bytes());
    let w = wallet(0);
    assert!(w.matches_filter(&script));
    let key_hash = sha256(&config().bitcoin_pks.consensus_encode());
    let compact = sha256(&[vec![253, 253, 0], script.clone(), key_hash.to_vec()].concat());
    assert_eq!(
        hex_encode(&compact),
        "0000d4bfcc25d0fce6d46d311eb4253f3612606cd8dc50c9b227191576d397f9"
    );
    assert_eq!(
        hex_encode(&sha256(
            &[script.consensus_encode(), key_hash.to_vec()].concat()
        )),
        "80502eb3983f9b478bc4d251af4778aeb393067878786fc14e1828de0b8a6819"
    );
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let backend = Backend::default();
    backend.blocks.borrow_mut().push(bitcoin::Block {
        header: [0; 80],
        transactions: vec![
            deposit_transaction(script, 1),
            deposit_transaction(hex_decode(DEPOSIT_SCRIPT).unwrap(), 1_000_000),
        ],
    });
    advance(&store, &w, &backend, 1);
    let records = w
        .snapshot(&store.snapshot().unwrap())
        .unwrap()
        .output_info_slice(0, 10);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].index, 1);
}
#[test]
fn error_registry_known_frames_are_exact_and_outcomes_absent() {
    use minimint_ng::{
        core::transaction::ModuleTransitions,
        protocol::{DynamicValue, ModuleValueKind},
    };
    let w = wallet(0);
    for tag in 1..=6 {
        assert!(decode_whole::<InputError>(&[tag, 0]).is_ok());
        assert!(decode_whole::<InputError>(&[tag, 1, 0]).is_err());
    }
    for tag in 1..=7 {
        assert!(decode_whole::<OutputError>(&[tag, 0]).is_ok());
        assert!(decode_whole::<OutputError>(&[tag, 1, 0]).is_err());
    }
    assert!(decode_whole::<InputError>(&[7, 0]).is_err());
    assert!(decode_whole::<OutputError>(&[8, 0]).is_err());
    assert!(decode_whole::<OutputError>(&[0, 0]).is_err());
    assert_eq!(
        decode_whole::<InputError>(&[0, 1, 9]).unwrap(),
        InputError::UnknownVersion(9)
    );
    assert!(decode_whole::<ConsensusItem>(&[3, 0]).is_err());
    let value = DynamicValue {
        module_id: ModuleId(42),
        payload: vec![4, 0],
    };
    assert!(value.validate(&w, ModuleValueKind::InputError).is_ok());
    assert!(value.validate(&w, ModuleValueKind::Outcome).is_err());
    let input = DynamicValue {
        module_id: ModuleId(42),
        payload: Input::Unknown {
            version: 9,
            payload: vec![],
        }
        .consensus_encode(),
    };
    assert!(ModuleTransitions::stateless_input(&w, &input).is_ok());
    let malformed = DynamicValue {
        module_id: ModuleId(42),
        payload: vec![0, 0],
    };
    assert!(matches!(
        ModuleTransitions::stateless_input(&w, &malformed),
        Err(TransitionError::FatalInvariant(_))
    ));
    let wrong_id = DynamicValue {
        module_id: ModuleId(43),
        payload: input.payload,
    };
    assert!(wrong_id.validate(&w, ModuleValueKind::Input).is_err());
}

#[test]
fn first_absent_fee_vote_is_persisted_and_only_identical_repeats_reject() {
    let directory = fixture::TestDir::new();
    let w = wallet(0);
    let backend = Backend::default();
    {
        let store = Store::open(directory.path()).unwrap();
        consensus(&store, &w, 0, ConsensusItem::FeeRate(None), &backend).unwrap();
    }
    let store = Store::open(directory.path()).unwrap();
    assert!(matches!(
        consensus(&store, &w, 0, ConsensusItem::FeeRate(None), &backend),
        Err(WalletError::Rejected("unchanged-fee-vote"))
    ));
    consensus(&store, &w, 0, ConsensusItem::FeeRate(Some(1000)), &backend).unwrap();
    assert!(matches!(
        consensus(&store, &w, 0, ConsensusItem::FeeRate(Some(1000)), &backend),
        Err(WalletError::Rejected("unchanged-fee-vote"))
    ));
    consensus(&store, &w, 0, ConsensusItem::FeeRate(None), &backend).unwrap();
    assert!(matches!(
        consensus(&store, &w, 0, ConsensusItem::FeeRate(None), &backend),
        Err(WalletError::Rejected("unchanged-fee-vote"))
    ));
    // Missing state belongs to each guardian independently; another guardian's
    // persisted None does not make this first None an identical repeat.
    consensus(&store, &w, 1, ConsensusItem::FeeRate(None), &backend).unwrap();
    assert_eq!(
        w.snapshot(&store.snapshot().unwrap())
            .unwrap()
            .consensus_fee_rate,
        None
    );
}
