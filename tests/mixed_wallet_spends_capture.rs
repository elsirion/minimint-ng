//! Actual mixed Wallet parent/child spends captured before and after confirmation.
use minimint_ng::{
    bitcoin::{Block, Transaction, Txid, double_sha256},
    codec::{
        ConsensusEncode, decode_whole,
        text::{hex_decode, hex_encode},
    },
    config::RawWalletConfig,
    crypto::{secp, sha256},
    json,
    protocol::DynamicValue,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::{fs, path::PathBuf};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop/mixed-monetary-2026-09-11")
}
fn read(name: &str) -> Value {
    json::parse(&fs::read(root().join(name)).unwrap(), 1024 * 1024, 64).unwrap()
}
fn raw(name: &str) -> Vec<u8> {
    hex_decode(fs::read_to_string(root().join(name)).unwrap().trim()).unwrap()
}
fn tx(name: &str) -> Transaction {
    let wire = raw(name);
    let t = Transaction::decode(&wire).unwrap();
    assert_eq!(wire, t.encode());
    t
}
fn script(c: &RawWalletConfig, tweak: &[u8; 32]) -> (Vec<u8>, Vec<[u8; 33]>) {
    assert_eq!(c.bitcoin_pks.len(), 4);
    let mut keys: Vec<_> = c
        .bitcoin_pks
        .values()
        .map(|key| secp::add_tweak(key, tweak).unwrap())
        .collect();
    keys.sort();
    assert!(keys.windows(2).all(|p| p[0] < p[1]));
    let mut s = vec![0x53];
    for k in &keys {
        s.push(33);
        s.extend(k);
    }
    s.extend([0x54, 0xae]);
    (s, keys)
}
fn verify(
    t: &Transaction,
    parents: &[Transaction],
    c: &RawWalletConfig,
    tweak: &[u8; 32],
    fee: u64,
) -> [u8; 32] {
    let (witness, keys) = script(c, tweak);
    let mut inputs = 0;
    let mut first_signers = None;
    for (index, input) in t.inputs.iter().enumerate() {
        let p = parents
            .iter()
            .find(|p| p.txid() == input.previous_output.txid)
            .unwrap();
        let o = &p.outputs[input.previous_output.vout as usize];
        inputs += o.value_sat;
        assert_eq!(
            o.script_pubkey,
            [vec![0, 32], sha256(&witness).to_vec()].concat()
        );
        assert!(input.script_sig.is_empty());
        assert_eq!(input.sequence, 0xffff_fffd);
        assert_eq!(input.witness.len(), 5);
        assert!(input.witness[0].is_empty());
        assert_eq!(input.witness[4], witness);
        let digest = t.sighash_all(index, &witness, o.value_sat).unwrap();
        let wrong = t.sighash_all(index, &witness, o.value_sat + 1).unwrap();
        let mut next = 0;
        let mut signers = Vec::new();
        for encoded in &input.witness[1..4] {
            assert_eq!(encoded.last(), Some(&1));
            let sig = secp::ecdsa_der_to_compact(&encoded[..encoded.len() - 1]).unwrap();
            let k = (next..4)
                .find(|&k| secp::ecdsa_verify(&keys[k], &digest, &sig).is_ok())
                .unwrap();
            assert!(secp::ecdsa_verify(&keys[k], &wrong, &sig).is_err());
            next = k + 1;
            signers.push(k);
        }
        if let Some(first) = &first_signers {
            assert_eq!(first, &signers);
        } else {
            first_signers = Some(signers);
        }
    }
    assert_eq!(
        inputs - t.outputs.iter().map(|o| o.value_sat).sum::<u64>(),
        fee
    );
    // WAL-002 change tweak includes the prior wallet value, native Bitcoin
    // outpoint and prior tweak; the consolidation's second deposit is excluded.
    let previous = &t.inputs[0].previous_output;
    let parent = parents.iter().find(|p| p.txid() == previous.txid).unwrap();
    let mut encoded = parent.outputs[previous.vout as usize]
        .value_sat
        .consensus_encode();
    encoded.extend(previous.consensus_encode());
    encoded.extend(tweak);
    let change_tweak = sha256(&encoded);
    let (change_script, _) = script(c, &change_tweak);
    assert_eq!(
        t.outputs[0].script_pubkey,
        [vec![0, 32], sha256(&change_script).to_vec()].concat()
    );
    change_tweak
}
#[test]
fn mixed_parent_and_pending_change_withdrawal_verify_and_confirm_together() {
    for (name, digest) in read("manifest.json")["sha256"].as_object().unwrap() {
        assert!(
            std::path::Path::new(name)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
        );
        assert_eq!(
            hex_encode(&sha256(&fs::read(root().join(name)).unwrap())),
            digest.as_str().unwrap()
        );
    }
    let config = read("peer0-client_config.json");
    let dynamic: DynamicValue =
        decode_whole(&hex_decode(config["modules"]["1"]["config"].as_str().unwrap()).unwrap())
            .unwrap();
    let config: RawWalletConfig = decode_whole(&dynamic.payload).unwrap();
    assert_eq!(
        (config.receive_tx_vbytes, config.send_tx_vbytes),
        (316, 228)
    );
    let funding = [tx("deposit.hex"), tx("second-deposit.hex")];
    let parent = tx("withdrawal_pending/chain-0.hex");
    let child = tx("withdrawal_pending/chain-1.hex");
    assert_eq!((parent.inputs.len(), parent.outputs.len()), (2, 1));
    assert_eq!((child.inputs.len(), child.outputs.len()), (1, 2));
    assert_eq!(child.inputs[0].previous_output.txid, parent.txid());
    assert_eq!(child.inputs[0].previous_output.vout, 0);
    assert_eq!(
        parent.txid().display_hex(),
        "edb37cec427eaf71f8881ec676dfef436dabf368976a54a650c7f5c633c3bb42"
    );
    assert_eq!(
        child.txid().display_hex(),
        "4ce63d469f06f6244bb7b82cd61a40b19c40bfc2c3010466bb0c95f08ac72983"
    );
    let first = read("first_deposit_observed/peer2-module_1_federation_wallet.json");
    let tweak: [u8; 32] = hex_decode(first["result"]["tweak"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let parent_tweak = verify(&parent, &funding, &config, &tweak, 632);
    let child_tweak = verify(
        &child,
        std::slice::from_ref(&parent),
        &config,
        &parent_tweak,
        456,
    );
    assert_eq!(parent.outputs[0].value_sat, 199368);
    assert_eq!(
        (child.outputs[0].value_sat, child.outputs[1].value_sat),
        (148912, 50000)
    );
    assert_eq!(child.outputs[1].script_pubkey.len(), 22);
    assert_eq!(&child.outputs[1].script_pubkey[..2], &[0, 20]);
    // Independent Core replies distinguish actual weight from configured vbytes.
    for (i, t, weight, fee) in [(0, &parent, 1262, 632), (1, &child, 862, 456)] {
        let mem = read(&format!("withdrawal_pending/chain-{i}-mempool.json"));
        let decoded = read(&format!("withdrawal_pending/chain-{i}-decoded.json"));
        assert_eq!(t.weight(), weight);
        assert_eq!(mem["weight"].as_u64(), Some(weight));
        assert_eq!(mem["vsize"].as_u64(), Some(weight.div_ceil(4)));
        assert_eq!(decoded["txid"].as_str().unwrap(), t.txid().display_hex());
        assert_eq!(decoded["hash"].as_str().unwrap(), t.wtxid().display_hex());
        assert_eq!(mem["wtxid"].as_str().unwrap(), t.wtxid().display_hex());
        assert_eq!(json::scaled_unsigned(&mem["fees"]["base"], 8).unwrap(), fee);
        assert_eq!(raw(&format!("monetary_observed/chain-{i}.hex")), t.encode());
        let confirmed = read(&format!("monetary_observed/chain-{i}-transaction.json"));
        assert_eq!(confirmed["confirmations"].as_u64(), Some(7));
        assert_eq!(confirmed["in_active_chain"].as_bool(), Some(true));
        assert_eq!(confirmed["txid"], decoded["txid"]);
        assert_eq!(confirmed["hash"], decoded["hash"]);
    }
    assert_eq!(
        read("withdrawal_pending/chain-1-mempool.json")["depends"][0]
            .as_str()
            .unwrap(),
        parent.txid().display_hex()
    );
    assert_eq!(
        read("withdrawal_pending/chain-0-mempool.json")["spentby"][0]
            .as_str()
            .unwrap(),
        child.txid().display_hex()
    );
    let block = Block::decode(&raw("monetary_observed/chain-0-block.hex")).unwrap();
    assert_eq!(
        raw("monetary_observed/chain-0-block.hex"),
        raw("monetary_observed/chain-1-block.hex")
    );
    let core = read("monetary_observed/chain-0-block.json");
    assert_eq!(core["height"].as_u64(), Some(165));
    assert_eq!(
        read("monetary_observed/core-chain.json")["blocks"].as_u64(),
        Some(171)
    );
    assert_eq!(
        Txid(block.hash()).display_hex(),
        core["hash"].as_str().unwrap()
    );
    assert_eq!(read("confirmation-blocks.json")[0], core["hash"]);
    let p = block
        .transactions
        .iter()
        .position(|t| t == &parent)
        .unwrap();
    let c = block.transactions.iter().position(|t| t == &child).unwrap();
    assert!(p < c);
    let mut hashes: Vec<_> = block.transactions.iter().map(|t| t.txid().0).collect();
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            hashes.push(*hashes.last().unwrap());
        }
        hashes = hashes
            .chunks_exact(2)
            .map(|p| double_sha256(&[p[0], p[1]].concat()))
            .collect();
    }
    assert_eq!(block.header[36..68], hashes[0]);
    for peer in 0..4 {
        let prefix = format!("monetary_observed/peer{peer}-module_1_");
        let wallet = read(&(prefix.clone() + "federation_wallet.json"))["result"].clone();
        assert_eq!(wallet["value"].as_u64(), Some(148912));
        assert_eq!(
            wallet["outpoint"].as_str().unwrap(),
            format!("{}:0", child.txid().display_hex())
        );
        assert_eq!(wallet["tweak"].as_str().unwrap(), hex_encode(&child_tweak));
        assert!(
            read(&(prefix.clone() + "pending_transaction_chain.json"))["result"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            read(&(prefix + "transaction_chain.json"))["result"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
