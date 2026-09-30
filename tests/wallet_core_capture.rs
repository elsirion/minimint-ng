//! Confirmed-chain reconstruction, not retained historical mempool or Store evidence.
use minimint_ng::{
    bitcoin::{Block, Transaction, TxOut, Txid, double_sha256},
    codec::text::{hex_decode, hex_encode},
    crypto::{secp, sha256},
    json,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::{collections::BTreeSet, fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/interop/wallet-core-2026-09-10")
}
fn bytes(name: &str) -> Vec<u8> {
    fs::read(root().join(name)).unwrap()
}
fn read(name: &str) -> Value {
    json::parse(&bytes(name), 16 * 1024 * 1024, 64).unwrap()
}
fn raw(name: &str) -> Vec<u8> {
    hex_decode(std::str::from_utf8(&bytes(name)).unwrap().trim()).unwrap()
}
fn sats(v: &Value) -> u64 {
    json::scaled_unsigned(v, 8).unwrap()
}
fn compare(tx: &Transaction, core: &Value) {
    assert_eq!(tx.txid().display_hex(), core["txid"].as_str().unwrap());
    assert_eq!(tx.wtxid().display_hex(), core["hash"].as_str().unwrap());
    assert_eq!(Some(tx.version as i64), core["version"].as_i64());
    assert_eq!(Some(tx.lock_time as u64), core["locktime"].as_u64());
    assert_eq!(Some(tx.encode().len() as u64), core["size"].as_u64());
    assert_eq!(Some(tx.weight()), core["weight"].as_u64());
    assert_eq!(Some(tx.weight().div_ceil(4)), core["vsize"].as_u64());
    assert_eq!(tx.inputs.len(), core["vin"].as_array().unwrap().len());
    for (input, vin) in tx.inputs.iter().zip(core["vin"].as_array().unwrap()) {
        assert_eq!(
            input.previous_output.txid.display_hex(),
            vin["txid"].as_str().unwrap()
        );
        assert_eq!(
            Some(input.previous_output.vout as u64),
            vin["vout"].as_u64()
        );
        assert_eq!(
            hex_encode(&input.script_sig),
            vin["scriptSig"]["hex"].as_str().unwrap()
        );
        assert_eq!(Some(input.sequence as u64), vin["sequence"].as_u64());
        assert_eq!(
            input.witness.len(),
            vin["txinwitness"].as_array().unwrap().len()
        );
        for (item, expected) in input
            .witness
            .iter()
            .zip(vin["txinwitness"].as_array().unwrap())
        {
            assert_eq!(hex_encode(item), expected.as_str().unwrap());
        }
    }
    assert_eq!(tx.outputs.len(), core["vout"].as_array().unwrap().len());
    for (i, (out, vout)) in tx
        .outputs
        .iter()
        .zip(core["vout"].as_array().unwrap())
        .enumerate()
    {
        assert_eq!(Some(i as u64), vout["n"].as_u64());
        assert_eq!(out.value_sat, sats(&vout["value"]));
        assert_eq!(
            hex_encode(&out.script_pubkey),
            vout["scriptPubKey"]["hex"].as_str().unwrap()
        );
    }
}
fn transaction(label: &str, suffix: &str) -> Transaction {
    let wire = raw(&format!("{label}{suffix}.hex"));
    let tx = Transaction::decode(&wire).unwrap();
    assert_eq!(tx.encode(), wire);
    compare(&tx, &read(&format!("{label}-decoded.json")));
    tx
}

/// Execute the narrow CHECKMULTISIG signature ordering for this exact standard
/// 3-of-4 P2WSH script using public BIP143 and strict low-S ECDSA interfaces.
/// This is not a general Bitcoin script interpreter.
fn threshold_witness(tx: &Transaction, index: usize, previous: &TxOut) {
    let input = &tx.inputs[index];
    assert!(input.script_sig.is_empty());
    assert_eq!(input.witness.len(), 5);
    assert!(input.witness[0].is_empty());
    let script = &input.witness[4];
    assert_eq!(script.len(), 139);
    assert_eq!(script[0], 0x53); // OP_3
    assert_eq!(&script[137..], &[0x54, 0xae]); // OP_4 CHECKMULTISIG
    let keys: Vec<[u8; 33]> = script[1..137]
        .chunks_exact(34)
        .map(|push| {
            assert_eq!(push[0], 33);
            let key: [u8; 33] = push[1..].try_into().unwrap();
            secp::validate_public_key(&key).unwrap();
            key
        })
        .collect();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        previous.script_pubkey,
        [vec![0, 32], sha256(script).to_vec()].concat()
    );
    let message = tx.sighash_all(index, script, previous.value_sat).unwrap();
    let mut next_key = 0;
    let mut matched = Vec::new();
    for encoded in &input.witness[1..4] {
        assert_eq!(encoded.last(), Some(&1)); // SIGHASH_ALL
        let signature = secp::ecdsa_der_to_compact(&encoded[..encoded.len() - 1]).unwrap();
        let key_index = (next_key..keys.len())
            .find(|&i| secp::ecdsa_verify(&keys[i], &message, &signature).is_ok())
            .unwrap();
        matched.push(key_index);
        next_key = key_index + 1;
        // A different amount must not validate this captured signature.
        let wrong = tx
            .sighash_all(index, script, previous.value_sat + 1)
            .unwrap();
        assert!(secp::ecdsa_verify(&keys[key_index], &wrong, &signature).is_err());
    }
    assert_eq!(matched.len(), 3);
}

#[test]
fn confirmed_wallet_spends_match_core_and_verify_threshold_signatures() {
    let funding = [transaction("funding-0", ""), transaction("funding-1", "")];
    let consolidation = transaction("consolidation", "-confirmed");
    let withdrawal = transaction("withdrawal", "-confirmed");
    assert_eq!(
        consolidation.txid().display_hex(),
        "54fbc5d65193e59d2cab948470dd3ba1c880c1401eb878886db84d32bbf544a0"
    );
    assert_eq!(
        withdrawal.txid().display_hex(),
        "e10abaf7b1c9413a5e605e0063c0eacfba906598f8d755118040241849c4ab36"
    );
    assert_eq!(consolidation.inputs.len(), 2);
    assert_eq!(consolidation.outputs.len(), 1);
    for (i, deposit) in funding.iter().enumerate() {
        assert_eq!(deposit.outputs[1].value_sat, 100_000);
        assert_eq!(consolidation.inputs[i].previous_output.txid, deposit.txid());
        assert_eq!(consolidation.inputs[i].previous_output.vout, 1);
        threshold_witness(&consolidation, i, &deposit.outputs[1]);
        assert!(bytes(&format!("funding-{i}-spent-current.json")).is_empty());
    }
    assert_eq!(consolidation.outputs[0].value_sat, 199_368);
    assert_eq!(
        200_000
            - consolidation
                .outputs
                .iter()
                .map(|o| o.value_sat)
                .sum::<u64>(),
        632
    );
    assert_eq!(withdrawal.inputs.len(), 1);
    assert_eq!(
        withdrawal.inputs[0].previous_output.txid,
        consolidation.txid()
    );
    assert_eq!(withdrawal.inputs[0].previous_output.vout, 0);
    threshold_witness(&withdrawal, 0, &consolidation.outputs[0]);
    assert_eq!(withdrawal.outputs.len(), 2);
    assert_eq!(withdrawal.outputs[0].value_sat, 148_912);
    assert_eq!(withdrawal.outputs[1].value_sat, 50_000);
    assert_eq!(
        consolidation.outputs[0].value_sat
            - withdrawal.outputs.iter().map(|o| o.value_sat).sum::<u64>(),
        456
    );
    assert!(bytes("consolidation-vout-0-current.json").is_empty());
    for (i, output) in withdrawal.outputs.iter().enumerate() {
        let utxo = read(&format!("withdrawal-vout-{i}-current.json"));
        assert_eq!(sats(&utxo["value"]), output.value_sat);
        assert_eq!(utxo["confirmations"].as_u64(), Some(7));
        assert_eq!(utxo["coinbase"].as_bool(), Some(false));
        assert_eq!(
            utxo["bestblock"],
            read("current-chain.json")["bestblockhash"]
        );
        assert_eq!(
            utxo["scriptPubKey"]["hex"].as_str().unwrap(),
            hex_encode(&output.script_pubkey)
        );
    }
    assert_eq!(&withdrawal.outputs[0].script_pubkey[..2], &[0, 32]);
    assert_eq!(&withdrawal.outputs[1].script_pubkey[..2], &[0, 20]);
    // These are reported funding fees, not independently verified prevout sums.
    let reports = read("funding-fee-reports.json");
    let reported_fees: Vec<u64> = reports
        .as_array()
        .unwrap()
        .iter()
        .map(|report| {
            let encoded = json::encode(&report["fee_btc"]).unwrap();
            assert_eq!(encoded.first(), Some(&b'-'));
            sats(&json::parse(&encoded[1..], 128, 8).unwrap())
        })
        .collect();
    assert_eq!(reported_fees, [1414, 424]);
    assert_eq!(
        reports[0]["txid"].as_str().unwrap(),
        funding[0].txid().display_hex()
    );
    assert_eq!(
        reports[1]["txid"].as_str().unwrap(),
        funding[1].txid().display_hex()
    );
    assert_eq!(
        read("reconstruction-summary.json")["aggregate_actual_fee_sat"].as_u64(),
        Some(reported_fees.iter().sum::<u64>() + 632 + 456)
    );
}

#[test]
fn preserved_manifest_and_confirmed_block_membership_match_core() {
    let manifest = read("manifest.json");
    let names: BTreeSet<String> = manifest["sha256"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, digest)| {
            assert!(!name.contains('/'));
            assert_eq!(hex_encode(&sha256(&bytes(name))), digest.as_str().unwrap());
            name.to_string()
        })
        .collect();
    let disk: BTreeSet<_> = fs::read_dir(root())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n != "manifest.json")
        .collect();
    assert_eq!(names, disk);
    let chain = read("current-chain.json");
    assert_eq!(chain["blocks"].as_u64(), Some(134));
    assert_eq!(chain["bestblockhash"], read("block-134.json")["hash"]);
    for height in [113, 114, 121, 128, 134] {
        let block = Block::decode(&raw(&format!("block-{height}.hex"))).unwrap();
        let core = read(&format!("block-{height}.json"));
        assert_eq!(core["height"].as_u64(), Some(height));
        assert_eq!(
            Txid(block.hash()).display_hex(),
            core["hash"].as_str().unwrap()
        );
        assert_eq!(
            String::from_utf8(bytes(&format!("block-{height}-hash.txt")))
                .unwrap()
                .trim(),
            core["hash"].as_str().unwrap()
        );
        assert_eq!(
            block.transactions.len(),
            core["tx"].as_array().unwrap().len()
        );
        for (tx, expected) in block
            .transactions
            .iter()
            .zip(core["tx"].as_array().unwrap())
        {
            assert_eq!(tx.txid().display_hex(), expected["txid"].as_str().unwrap());
            assert_eq!(tx.wtxid().display_hex(), expected["hash"].as_str().unwrap());
        }
        let mut level: Vec<_> = block.transactions.iter().map(|t| t.txid().0).collect();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level
                .chunks_exact(2)
                .map(|p| double_sha256(&[p[0], p[1]].concat()))
                .collect();
        }
        assert_eq!(block.header[36..68], level[0]);
        assert_eq!(
            Txid(level[0]).display_hex(),
            core["merkleroot"].as_str().unwrap()
        );
        let expected = match height {
            114 => vec![transaction("funding-0", "")],
            121 => vec![transaction("funding-1", "")],
            128 => vec![
                transaction("consolidation", "-confirmed"),
                transaction("withdrawal", "-confirmed"),
            ],
            _ => vec![],
        };
        let mut previous_position = 0;
        for tx in expected {
            let position = block
                .transactions
                .iter()
                .position(|candidate| candidate == &tx)
                .unwrap();
            assert!(position > previous_position);
            previous_position = position;
        }
    }
}
