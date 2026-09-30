use minimint_ng::{
    api::modules::{ModuleApiError, dispatch},
    bitcoin,
    codec::{
        ConsensusEncode,
        text::{hex_decode, hex_encode},
    },
    config::{BitcoinNetwork, DescriptorKind, Fee, RawMintConfig, RawWalletConfig},
    crypto::{
        bls::{G1, G2, Scalar},
        secp::SecretKey,
    },
    modules::{
        Modules,
        mint::{G1Bytes, Mint, Output, OutputV0},
        wallet::{ChainRecord, Discovery, FederationWallet, Wallet},
    },
    protocol::{ModuleId, OutPoint, PeerId},
    storage::{Namespace, Store},
};
use sonic_rs::{JsonValueTrait, Value, json};
use std::collections::BTreeMap;
#[path = "fixtures/storage/mod.rs"]
mod fixture;
fn modules() -> Modules {
    let shares: BTreeMap<_, _> = (0..42)
        .map(|d| (d, Scalar::from_u64(u64::from(d) + 1)))
        .collect();
    let keys: BTreeMap<_, _> = shares
        .iter()
        .map(|(d, scalar)| (*d, G2::generator().mul(scalar).to_bytes()))
        .collect();
    let mint = Mint::new(
        ModuleId(42),
        PeerId(0),
        RawMintConfig {
            aggregate_keys: keys.clone(),
            public_shares: keys
                .into_iter()
                .map(|(d, k)| (d, BTreeMap::from([(PeerId(0), k)])))
                .collect(),
            fee: Fee::mint(0, 0).unwrap(),
            amount_unit: 0,
        },
        shares,
    )
    .unwrap();
    let secret = SecretKey::from_bytes(&[1; 32]).unwrap();
    let wallet = Wallet::new(
        ModuleId(7),
        PeerId(0),
        RawWalletConfig {
            bitcoin_pks: BTreeMap::from([(PeerId(0), secret.public_key())]),
            descriptor: DescriptorKind::Wsh,
            send_tx_vbytes: 166,
            receive_tx_vbytes: 192,
            feerate_base: 250,
            dust_limit: 10000,
            fee_consensus: Fee::wallet(100000, 0).unwrap(),
            network: BitcoinNetwork::Regtest,
        },
        secret,
    )
    .unwrap();
    Modules::new(mint, wallet).unwrap()
}
fn call(modules: &Modules, store: &Store, method: &str, params: Value) -> Value {
    dispatch(modules, &store.snapshot().unwrap(), method, &params).unwrap()
}
#[test]
fn empty_state_native_nulls_ranges_and_configured_instances() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = modules();
    assert_eq!(
        call(&modules, &store, "module_42_recovery_count", json!(null)),
        json!(0)
    );
    assert_eq!(
        call(
            &modules,
            &store,
            "module_42_recovery_slice_hash",
            json!([0, u64::MAX])
        ),
        json!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
    );
    for method in ["recovery_slice", "recovery_signature_shares"] {
        let params = if method == "recovery_slice" {
            json!([0, u64::MAX])
        } else {
            json!([])
        };
        assert_eq!(
            call(&modules, &store, &format!("module_42_{method}"), params),
            json!([])
        );
    }
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_consensus_block_count",
            json!(null)
        ),
        json!(0)
    );
    for method in [
        "consensus_feerate",
        "federation_wallet",
        "receive_fee",
        "send_fee",
    ] {
        assert_eq!(
            call(&modules, &store, &format!("module_7_{method}"), json!(null)),
            json!(null)
        );
    }
    for method in ["pending_transaction_chain", "transaction_chain"] {
        assert_eq!(
            call(&modules, &store, &format!("module_7_{method}"), json!(null)),
            json!([])
        );
    }
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_output_info_slice",
            json!([0, u64::MAX])
        ),
        json!([])
    );
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_transaction_id",
            json!({"txid":"00".repeat(32),"out_idx":u64::MAX})
        ),
        json!(null)
    );
    for method in [
        "module_0_recovery_count",
        "module_042_recovery_count",
        "module_42_send_fee",
        "module_7_no_such_method",
    ] {
        assert_eq!(
            dispatch(&modules, &store.snapshot().unwrap(), method, &json!(null)),
            Err(ModuleApiError::MethodNotFound)
        );
    }
}
#[test]
fn mint_sparse_outputs_repeated_recovery_and_exact_missing_error() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = modules();
    let mut writer = store.transaction().unwrap();
    let mut messages = Vec::new();
    let mut nonces = Vec::new();
    let blind = Scalar::from_u64(9);
    for index in [0, 2] {
        let nonce = minimint_ng::modules::mint::Nonce::from_bytes(
            SecretKey::from_bytes(&[index as u8 + 1; 32])
                .unwrap()
                .public_key(),
        )
        .unwrap();
        nonces.push(nonce);
        let message = G1Bytes::from_bytes(
            minimint_ng::crypto::bls::message_sha256(&nonce.to_bytes())
                .unwrap()
                .mul(&blind)
                .to_bytes(),
        )
        .unwrap();
        messages.push(message);
        modules
            .mint()
            .output(
                &mut writer,
                &Output::V0(OutputV0 {
                    denomination: index as u8,
                    blinded_message: message,
                    tweak: [index as u8; 16],
                }),
                OutPoint {
                    txid: [3; 32],
                    out_idx: index,
                },
            )
            .unwrap();
    }
    writer.commit().unwrap();
    let snapshot = store.snapshot().unwrap();
    let expected: Vec<_> = modules
        .mint()
        .signature_shares(&snapshot, [3; 32], 0..3)
        .unwrap()
        .iter()
        .map(|share| hex_encode(&share.to_bytes()))
        .collect();
    assert_eq!(
        call(
            &modules,
            &store,
            "module_42_signature_shares",
            json!({"txid":"03".repeat(32),"idx_range":{"start":0,"end":3}})
        ),
        json!(expected)
    );
    assert_eq!(
        call(
            &modules,
            &store,
            "module_42_recovery_signature_shares",
            json!([
                hex_encode(&messages[1].to_bytes()),
                hex_encode(&messages[0].to_bytes()),
                hex_encode(&messages[1].to_bytes())
            ])
        ),
        json!([expected[1], expected[0], expected[1]])
    );
    let unknown = hex_encode(&G1::generator().mul(&Scalar::from_u64(99)).to_bytes());
    let error = dispatch(
        &modules,
        &snapshot,
        "module_42_recovery_signature_shares",
        &json!([hex_encode(&messages[0].to_bytes()), unknown]),
    )
    .unwrap_err();
    assert_eq!(
        (error.code(), error.message()),
        (400, "No blinded signature share found")
    );
    let records = modules.mint().recovery_slice(&snapshot, 0..2).unwrap();
    let expected:Vec<_>=records.iter().map(|item| match item {
        minimint_ng::modules::mint::RecoveryItem::Output{denomination,nonce_hash,tweak}=>json!({"Output":{"denomination":denomination,"nonce_hash":hex_encode(nonce_hash),"tweak":tweak}}),
        _=>unreachable!(),
    }).collect();
    assert_eq!(
        call(&modules, &store, "module_42_recovery_slice", json!([0, 2])),
        json!(expected)
    );
    assert_eq!(
        call(&modules, &store, "module_42_recovery_count", json!(null)),
        json!(2)
    );
    assert_eq!(
        call(
            &modules,
            &store,
            "module_42_recovery_slice_hash",
            json!([0, 2])
        ),
        json!(hex_encode(&minimint_ng::crypto::sha256(
            &records.consensus_encode()
        )))
    );
    // Reads leave the same committed recovery state available.
    assert_eq!(
        modules
            .mint()
            .recovery_slice(&store.snapshot().unwrap(), 0..2)
            .unwrap(),
        records
    );
    let share = modules
        .mint()
        .signature_shares(&snapshot, [3; 32], 0..1)
        .unwrap()[0];
    let signature = G1Bytes::from_bytes(
        G1::from_bytes(&share.to_bytes())
            .unwrap()
            .mul(&blind.inverse().unwrap())
            .to_bytes(),
    )
    .unwrap();
    let mut writer = store.transaction().unwrap();
    modules
        .mint()
        .input(
            &mut writer,
            &minimint_ng::modules::mint::Input::V0(minimint_ng::modules::mint::Note {
                denomination: 0,
                nonce: nonces[0],
                signature,
            }),
            OutPoint {
                txid: [9; 32],
                out_idx: 0,
            },
        )
        .unwrap();
    writer.commit().unwrap();
    assert_eq!(
        call(&modules, &store, "module_42_recovery_slice", json!([2, 3])),
        json!([{"Input":{"nonce_hash":hex_encode(&minimint_ng::crypto::hash160(&nonces[0].to_bytes()).unwrap())}}])
    );
}
#[test]
fn malformed_native_params_fail_without_float_or_string_coercion() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = modules();
    for params in [
        json!([1, 0]),
        json!([0]),
        json!([0, 1, 2]),
        json!(["0", 1]),
        json!([-1, 1]),
        json!([0, 1.5]),
        json!(null),
    ] {
        assert_eq!(
            dispatch(
                &modules,
                &store.snapshot().unwrap(),
                "module_42_recovery_slice",
                &params
            ),
            Err(ModuleApiError::InvalidParams)
        );
    }
    for (method, params) in [
        ("module_42_recovery_count", json!([])),
        (
            "module_42_signature_shares",
            json!({"txid":"00".repeat(32),"idx_range":{"start":0}}),
        ),
        (
            "module_42_recovery_signature_shares",
            json!(["00".repeat(48)]),
        ),
        (
            "module_7_transaction_id",
            json!({"txid":"00".repeat(32),"vout":0}),
        ),
        ("module_7_transaction_id", json!({"txid":"00","out_idx":0})),
    ] {
        assert_eq!(
            dispatch(&modules, &store.snapshot().unwrap(), method, &params),
            Err(ModuleApiError::InvalidParams)
        );
    }
}

// Local storage fixture deliberately includes extreme u64 values to test JSON
// presentation independently of the Wallet accounting domain. It is not a
// claim that a consensus transition may create those accounting values.
fn wallet_fixture(store: &Store, pending_count: usize) {
    let txid = bitcoin::Txid(std::array::from_fn(|i| (31 - i) as u8));
    let point = bitcoin::OutPoint {
        txid,
        vout: u32::MAX,
    };
    let precise = 9_007_199_254_740_993u64;
    let wallet = FederationWallet {
        value_sat: precise,
        outpoint: point,
        tweak: [0x12; 32],
    };
    let discoveries = vec![
        Discovery {
            index: 0,
            script: vec![0x51],
            value_sat: 1,
            spent: false,
            outpoint: Some(point),
        },
        Discovery {
            index: 2,
            script: [vec![0, 32], vec![7; 32]].concat(),
            value_sat: precise,
            spent: true,
            outpoint: Some(point),
        },
        Discovery {
            index: 4,
            script: [vec![0, 32], vec![8; 32]].concat(),
            value_sat: u64::MAX,
            spent: false,
            outpoint: None,
        },
    ];
    let chain: Vec<_> = (0..3)
        .map(|index| ChainRecord {
            index,
            txid: bitcoin::Txid([index as u8; 32]),
            input_sat: precise,
            output_sat: precise + 1,
            fee_sat: u64::MAX,
            vbytes: 316,
            created: u64::MAX,
        })
        .collect();
    let mut bytes = BTreeMap::<PeerId, u64>::new().consensus_encode();
    bytes.extend(BTreeMap::from([(PeerId(0), Some(1000u64))]).consensus_encode());
    bytes.extend(u64::MAX.consensus_encode());
    bytes.extend(Some(wallet).consensus_encode());
    bytes.extend(discoveries.consensus_encode());
    bytes.extend(chain.consensus_encode());
    bytes.extend((pending_count as u64).consensus_encode());
    for index in 0..pending_count {
        bytes.extend(bitcoin::Txid([index as u8; 32]).consensus_encode());
        bytes.extend(Vec::<u8>::new().consensus_encode());
        bytes.extend(Vec::<FederationWallet>::new().consensus_encode());
        bytes.extend(0u64.consensus_encode());
        bytes.extend(0u64.consensus_encode());
        bytes.extend(BTreeMap::<PeerId, Vec<[u8; 64]>>::new().consensus_encode());
        bytes.extend(false.consensus_encode());
    }
    bytes.extend(
        BTreeMap::from([(
            OutPoint {
                txid: [3; 32],
                out_idx: u64::MAX,
            }
            .consensus_encode(),
            txid,
        )])
        .consensus_encode(),
    );
    let mut writer = store.transaction().unwrap();
    writer
        .put(Namespace::Replicated, b"wallet/v1/\x00\x07/state", &bytes)
        .unwrap();
    writer.commit().unwrap();
}
#[test]
fn wallet_native_schema_sparse_ranges_display_order_and_exact_integers() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = modules();
    wallet_fixture(&store, 2);
    let display = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    assert_eq!(
        call(&modules, &store, "module_7_federation_wallet", json!(null)),
        json!({"value":9007199254740993u64,"outpoint":format!("{display}:4294967295"),"tweak":"12".repeat(32)})
    );
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_transaction_id",
            json!({"txid":"03".repeat(32),"out_idx":u64::MAX})
        ),
        json!(display)
    );
    let discovery = call(
        &modules,
        &store,
        "module_7_output_info_slice",
        json!([0, 4]),
    );
    assert_eq!(
        discovery,
        json!([{"index":2,"script":format!("0020{}","07".repeat(32)),"value":9007199254740993u64,"spent":true,"outpoint":format!("{display}:4294967295")}])
    );
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_output_info_slice",
            json!([4, 5])
        ),
        json!([{"index":4,"script":format!("0020{}","08".repeat(32)),"value":u64::MAX,"spent":false,"outpoint":null}])
    );
    let chain = call(&modules, &store, "module_7_transaction_chain", json!(null));
    let pending = call(
        &modules,
        &store,
        "module_7_pending_transaction_chain",
        json!(null),
    );
    assert_eq!(pending, json!([chain[2], chain[1]]));
    assert_eq!(
        chain[0],
        json!({"index":0,"txid":"00".repeat(32),"input":9007199254740993u64,"output":9007199254740994u64,"fee":u64::MAX,"vbytes":316,"created":u64::MAX})
    );
    assert_eq!(
        minimint_ng::json::encode(&call(
            &modules,
            &store,
            "module_7_consensus_block_count",
            json!(null)
        ))
        .unwrap(),
        b"18446744073709551615"
    );
    assert_eq!(
        call(&modules, &store, "module_7_consensus_feerate", json!(null)),
        json!(1000)
    );
    // Confirming transactions removes pending records, not retained chain history.
    wallet_fixture(&store, 0);
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_pending_transaction_chain",
            json!(null)
        ),
        json!([])
    );
    assert_eq!(
        call(&modules, &store, "module_7_transaction_chain", json!(null)),
        chain
    );
}
#[test]
fn quote_invariant_does_not_break_unrelated_wallet_reads() {
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let modules = modules();
    wallet_fixture(&store, 33);
    assert_eq!(
        dispatch(
            &modules,
            &store.snapshot().unwrap(),
            "module_7_send_fee",
            &json!(null)
        ),
        Err(ModuleApiError::FatalInvariant)
    );
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_consensus_block_count",
            json!(null)
        ),
        json!(u64::MAX)
    );
}

#[test]
fn wallet_discovery_outpoint_matches_captured_reference_native_string() {
    let captured = include_bytes!(
        "fixtures/interop/wal016-outpoint-conflict/first-deposit-peer2-module_1_output_info_slice.json"
    );
    assert_eq!(
        hex_encode(&minimint_ng::crypto::sha256(captured)),
        "2e48d1835fef0182d00b052666161aa7a622b90cf409c64822c8e07242fd157d"
    );
    let response = minimint_ng::json::parse(captured, 4096, 16).unwrap();
    let mut digest: [u8; 32] =
        hex_decode("441127e88b3be8f451e4ce5a82efc2c45efc98e249eda8a5df892d985c9b5c9e")
            .unwrap()
            .try_into()
            .unwrap();
    digest.reverse();
    let discoveries = vec![Discovery {
        index: 0,
        script: hex_decode("00204fd19b41c50ac829c7d244bebe0fcfed7ce36fbfa98a3ccc7e1bc8f45e326d6a")
            .unwrap(),
        value_sat: 100_000,
        spent: false,
        outpoint: Some(bitcoin::OutPoint {
            txid: bitcoin::Txid(digest),
            vout: 1,
        }),
    }];
    // Local storage fixture recreates the captured discovery; it is not a new
    // live observation. The historical reference federation_wallet was null.
    let mut state = BTreeMap::<PeerId, u64>::new().consensus_encode();
    state.extend(BTreeMap::<PeerId, Option<u64>>::new().consensus_encode());
    state.extend(108u64.consensus_encode());
    state.extend(Option::<FederationWallet>::None.consensus_encode());
    state.extend(discoveries.consensus_encode());
    state.extend(Vec::<ChainRecord>::new().consensus_encode());
    state.extend(0u64.consensus_encode()); // pending records
    state.extend(BTreeMap::<Vec<u8>, bitcoin::Txid>::new().consensus_encode());
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(Namespace::Replicated, b"wallet/v1/\x00\x07/state", &state)
        .unwrap();
    tx.commit().unwrap();
    let modules = modules();
    assert_eq!(
        call(
            &modules,
            &store,
            "module_7_output_info_slice",
            json!([0, 1])
        ),
        response["result"]
    );
    assert!(call(&modules, &store, "module_7_federation_wallet", json!(null)).is_null());
    assert_eq!(
        dispatch(
            &modules,
            &store.snapshot().unwrap(),
            "module_7_transaction_id",
            &json!("00".repeat(32) + ":0")
        ),
        Err(ModuleApiError::InvalidParams)
    );
}

#[test]
fn populated_reference_wallet_and_first_issuance_accounting_capture() {
    use minimint_ng::{codec::decode_whole, protocol::DynamicValue};
    use sonic_rs::JsonContainerTrait;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop/mixed-first-deposit-2026-09-11");
    let read = |name: &str| {
        minimint_ng::json::parse(&std::fs::read(root.join(name)).unwrap(), 1024 * 1024, 64).unwrap()
    };
    for (name, hash) in read("manifest.json")["sha256"].as_object().unwrap() {
        assert_eq!(
            hex_encode(&minimint_ng::crypto::sha256(
                &std::fs::read(root.join(name)).unwrap()
            )),
            hash.as_str().unwrap()
        );
    }
    let captured = read("peer2-module_1_federation_wallet.json")["result"].clone();
    assert_eq!(captured["value"].as_u64(), Some(100000));
    assert_eq!(
        captured["outpoint"].as_str(),
        Some("ae86122c51921eebdbbe8ec997d05792370963933643edca53edab075e501475:0")
    );
    for peer in 0..4 {
        for method in [
            "federation_wallet",
            "output_info_slice",
            "consensus_block_count",
            "consensus_feerate",
            "receive_fee",
            "pending_transaction_chain",
        ] {
            assert_eq!(
                read(&format!("peer{peer}-module_1_{method}.json"))["result"],
                read(&format!("peer2-module_1_{method}.json"))["result"]
            );
        }
        assert_eq!(
            read(&format!("peer{peer}-module_0_recovery_count.json"))["result"].as_u64(),
            Some(55)
        );
    }
    let mut digest: [u8; 32] =
        hex_decode("ae86122c51921eebdbbe8ec997d05792370963933643edca53edab075e501475")
            .unwrap()
            .try_into()
            .unwrap();
    digest.reverse();
    let wallet = FederationWallet {
        value_sat: 100000,
        outpoint: bitcoin::OutPoint {
            txid: bitcoin::Txid(digest),
            vout: 0,
        },
        tweak: hex_decode("15903b2c69fe1899a165f4605eb38f70d326c086e416cc58ffc816426acff8ef")
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let mut state = BTreeMap::<PeerId, u64>::new().consensus_encode();
    state.extend(BTreeMap::<PeerId, Option<u64>>::new().consensus_encode());
    state.extend(137u64.consensus_encode());
    state.extend(Some(wallet).consensus_encode());
    state.extend(Vec::<Discovery>::new().consensus_encode());
    state.extend(Vec::<ChainRecord>::new().consensus_encode());
    state.extend(0u64.consensus_encode());
    state.extend(BTreeMap::<Vec<u8>, bitcoin::Txid>::new().consensus_encode());
    let dir = fixture::TestDir::new();
    let store = Store::open(dir.path()).unwrap();
    let mut tx = store.transaction().unwrap();
    tx.put(Namespace::Replicated, b"wallet/v1/\x00\x07/state", &state)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        call(
            &modules(),
            &store,
            "module_7_federation_wallet",
            json!(null)
        ),
        captured
    );
    let config = read("client-config.json");
    let mint_dynamic: DynamicValue =
        decode_whole(&hex_decode(config["modules"]["0"]["config"].as_str().unwrap()).unwrap())
            .unwrap();
    let wallet_dynamic: DynamicValue =
        decode_whole(&hex_decode(config["modules"]["1"]["config"].as_str().unwrap()).unwrap())
            .unwrap();
    let mint: RawMintConfig = decode_whole(&mint_dynamic.payload).unwrap();
    let wallet: RawWalletConfig = decode_whole(&wallet_dynamic.payload).unwrap();
    assert_eq!(mint.fee.base, 100);
    assert_eq!(mint.fee.parts_per_million, 0);
    assert_eq!(wallet.fee_consensus.base, 100000);
    assert_eq!(wallet.fee_consensus.parts_per_million, 0);
    let report = read("accounting-observation.json");
    let mut count = 0;
    let mut value = 0;
    for (denomination, n) in report["client_note_count_by_denomination"]
        .as_object()
        .unwrap()
    {
        let n = n.as_u64().unwrap();
        count += n;
        value += (1u64 << denomination.parse::<u32>().unwrap()) * n;
    }
    assert_eq!((count, value), (55, 99_261_952));
    // CLI inventory report only: this arithmetic does not independently prove
    // the note signatures or all guardians' outstanding issuance counters.
    // The observed quote is not evidence of the fee supplied in the accepted
    // input. Excess is conditional on the client having supplied this quote.
    let quoted_withholding = read("peer2-module_1_receive_fee.json")["result"]
        .as_u64()
        .unwrap()
        * 1000;
    assert_eq!(quoted_withholding, 632000);
    let module_fees = wallet.fee_consensus.base + count * mint.fee.base;
    assert_eq!(100_000_000 - value - quoted_withholding - module_fees, 548);
    assert_eq!(
        read("peer2-module_1_pending_transaction_chain.json")["result"],
        json!([])
    );
}
