//! Public mixed-daemon signatures and independent Core mempool observation.
//! No confirmation or first-q consensus-order proof is inferred from a mempool capture.
use minimint_ng::{
    bitcoin::{Transaction, Txid, double_sha256},
    codec::{
        boundary::compact_size,
        decode_whole,
        text::{hex_decode, hex_encode},
    },
    config::RawWalletConfig,
    crypto::{secp, sha256},
    json,
    protocol::{DynamicValue, PeerId},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
fn root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop")
        .join(name)
}
fn read(root: &Path, name: &str) -> Value {
    json::parse(&fs::read(root.join(name)).unwrap(), 1024 * 1024, 64).unwrap()
}
fn raw(root: &Path, name: &str) -> Vec<u8> {
    hex_decode(fs::read_to_string(root.join(name)).unwrap().trim()).unwrap()
}
fn manifest(root: &Path) {
    let m = read(root, "manifest.json");
    for (name, digest) in m["sha256"].as_object().unwrap() {
        assert!(
            Path::new(name)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
        );
        assert_eq!(
            hex_encode(&sha256(&fs::read(root.join(name)).unwrap())),
            digest.as_str().unwrap()
        );
    }
    let listed: BTreeSet<_> = m["sha256"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(n, _)| n.to_owned())
        .collect();
    fn files(base: &Path, directory: &Path, result: &mut BTreeSet<String>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                files(base, &entry.path(), result);
            } else {
                assert!(kind.is_file());
                let name = entry
                    .path()
                    .strip_prefix(base)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
                if name != "manifest.json" {
                    result.insert(name);
                }
            }
        }
    }
    let mut actual = BTreeSet::new();
    files(root, root, &mut actual);
    assert_eq!(listed, actual);
}
fn tx(root: &Path, name: &str, decoded: &str) -> Transaction {
    let wire = raw(root, name);
    let t = Transaction::decode(&wire).unwrap();
    assert_eq!(wire, t.encode());
    let c = read(root, decoded);
    assert_eq!(t.txid().display_hex(), c["txid"].as_str().unwrap());
    assert_eq!(t.wtxid().display_hex(), c["hash"].as_str().unwrap());
    assert_eq!(Some(t.weight()), c["weight"].as_u64());
    assert_eq!(Some(t.weight().div_ceil(4)), c["vsize"].as_u64());
    assert_eq!(t.outputs.len(), c["vout"].as_array().unwrap().len());
    for (o, v) in t.outputs.iter().zip(c["vout"].as_array().unwrap()) {
        assert_eq!(o.value_sat, json::scaled_unsigned(&v["value"], 8).unwrap());
        assert_eq!(
            hex_encode(&o.script_pubkey),
            v["scriptPubKey"]["hex"].as_str().unwrap()
        );
    }
    t
}
fn script(config: &RawWalletConfig, tweak: &[u8; 32]) -> (Vec<u8>, Vec<([u8; 33], PeerId)>) {
    assert_eq!(config.bitcoin_pks.len(), 4);
    let mut keys: Vec<_> = config
        .bitcoin_pks
        .iter()
        .map(|(peer, key)| (secp::add_tweak(key, tweak).unwrap(), *peer))
        .collect();
    keys.sort();
    let mut bytes = vec![0x53];
    for (key, _) in &keys {
        bytes.push(33);
        bytes.extend(key);
    }
    bytes.extend([0x54, 0xae]);
    assert_eq!(bytes.len(), 139);
    (bytes, keys)
}
// BIP143 SIGHASH_ALL preimage assembled directly from the captured transaction.
// Amount and scriptCode are independently resolved from its retained parent.
fn sighash(t: &Transaction, index: usize, script: &[u8], value: u64) -> [u8; 32] {
    let mut prevouts = Vec::new();
    let mut sequences = Vec::new();
    let mut outputs = Vec::new();
    for i in &t.inputs {
        prevouts.extend(i.previous_output.txid.0);
        prevouts.extend(i.previous_output.vout.to_le_bytes());
        sequences.extend(i.sequence.to_le_bytes());
    }
    for o in &t.outputs {
        outputs.extend(o.value_sat.to_le_bytes());
        outputs.extend(compact_size(o.script_pubkey.len() as u64));
        outputs.extend(&o.script_pubkey);
    }
    let i = &t.inputs[index];
    let mut p = t.version.to_le_bytes().to_vec();
    p.extend(double_sha256(&prevouts));
    p.extend(double_sha256(&sequences));
    p.extend(i.previous_output.txid.0);
    p.extend(i.previous_output.vout.to_le_bytes());
    p.extend(compact_size(script.len() as u64));
    p.extend(script);
    p.extend(value.to_le_bytes());
    p.extend(i.sequence.to_le_bytes());
    p.extend(double_sha256(&outputs));
    p.extend(t.lock_time.to_le_bytes());
    p.extend(1u32.to_le_bytes());
    double_sha256(&p)
}
#[test]
fn mixed_consolidation_matches_core_and_verifies_public_guardian_signatures() {
    let r = root("mixed-consolidation-2026-09-11");
    let first = root("mixed-first-deposit-2026-09-11");
    manifest(&r);
    manifest(&first);
    let config = read(&first, "client-config.json");
    let dynamic: DynamicValue =
        decode_whole(&hex_decode(config["modules"]["1"]["config"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(dynamic.module_id.0, 1);
    let config: RawWalletConfig = decode_whole(&dynamic.payload).unwrap();
    let parents = [
        tx(&r, "funding-0.hex", "funding-0-decoded.json"),
        tx(&r, "funding-1.hex", "funding-1-decoded.json"),
    ];
    let t = tx(&r, "pending-0.hex", "pending-0-decoded.json");
    assert_eq!(
        t.txid().display_hex(),
        "772ce84e635f9c0c55ee91d810188cb63dbb53d130452e815482e0747beaf811"
    );
    assert_eq!(
        t.wtxid().display_hex(),
        "abcbb132f17ae9d5f1f62df996d90dbc20da823864b0c047db5ebb69ba3aecdd"
    );
    assert_eq!(t.weight(), 1261);
    assert_eq!((t.version, t.lock_time), (2, 0));
    assert_eq!(t.inputs.len(), 2);
    assert_eq!(t.outputs.len(), 1);
    let old = read(&first, "peer2-module_1_federation_wallet.json")["result"].clone();
    let tweak: [u8; 32] = hex_decode(old["tweak"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let (witness, keys) = script(&config, &tweak);
    let mut selected = Vec::new();
    for (index, (input, parent)) in t.inputs.iter().zip(&parents).enumerate() {
        assert_eq!(input.previous_output.txid, parent.txid());
        assert_eq!(input.previous_output.vout, 0);
        assert_eq!(input.sequence, 0xffff_fffd);
        assert!(input.script_sig.is_empty());
        let previous = &parent.outputs[0];
        assert_eq!(previous.value_sat, 100000);
        assert_eq!(
            previous.script_pubkey,
            [vec![0, 32], sha256(&witness).to_vec()].concat()
        );
        assert_eq!(input.witness.len(), 5);
        assert!(input.witness[0].is_empty());
        assert_eq!(input.witness[4], witness);
        let digest = sighash(&t, index, &witness, previous.value_sat);
        assert_eq!(
            digest,
            t.sighash_all(index, &witness, previous.value_sat).unwrap()
        );
        let mut next = 0;
        let mut peers = Vec::new();
        for encoded in &input.witness[1..4] {
            assert_eq!(encoded.last(), Some(&1));
            let sig = secp::ecdsa_der_to_compact(&encoded[..encoded.len() - 1]).unwrap();
            let matched = (next..keys.len())
                .find(|&k| secp::ecdsa_verify(&keys[k].0, &digest, &sig).is_ok())
                .unwrap();
            peers.push(keys[matched].1);
            next = matched + 1;
            assert!(
                secp::ecdsa_verify(
                    &keys[matched].0,
                    &sighash(&t, index, &witness, previous.value_sat + 1),
                    &sig
                )
                .is_err()
            );
        }
        assert_eq!(peers.len(), 3);
        selected.push(peers);
    }
    assert_eq!(selected[0], selected[1]);
    // WAL-002 E(previous wallet): BigSize satoshis, native Bitcoin outpoint,
    // prior raw tweak. Explicit bytes prevent accidentally hashing JSON.
    assert_eq!(old["value"].as_u64(), Some(100000));
    let mut previous = vec![0xfe, 0, 1, 0x86, 0xa0];
    previous.extend(parents[0].txid().0);
    previous.extend(0u32.to_le_bytes());
    previous.extend(tweak);
    let change_tweak = sha256(&previous);
    let (change_script, _) = script(&config, &change_tweak);
    assert_eq!(t.outputs[0].value_sat, 199368);
    assert_eq!(200000 - t.outputs[0].value_sat, 632);
    assert_eq!(
        t.outputs[0].script_pubkey,
        [vec![0, 32], sha256(&change_script).to_vec()].concat()
    );
    for peer in 0..4 {
        let wallet =
            read(&r, &format!("peer{peer}-module_1_federation_wallet.json"))["result"].clone();
        assert_eq!(wallet["tweak"].as_str().unwrap(), hex_encode(&change_tweak));
        assert_eq!(wallet["value"].as_u64(), Some(199368));
        assert_eq!(
            wallet["outpoint"].as_str().unwrap(),
            format!("{}:0", t.txid().display_hex())
        );
        let chain = read(
            &r,
            &format!("peer{peer}-module_1_pending_transaction_chain.json"),
        )["result"]
            .clone();
        assert_eq!(chain.as_array().unwrap().len(), 1);
        assert_eq!(chain[0]["txid"].as_str().unwrap(), t.txid().display_hex());
        for (field, value) in [
            ("input", 100000),
            ("output", 199368),
            ("fee", 632),
            ("vbytes", 316),
            ("created", 144),
            ("index", 0),
        ] {
            assert_eq!(chain[0][field].as_u64(), Some(value));
        }
    }
    let mempool = read(&r, "pending-0-mempool.json");
    assert_eq!(mempool["wtxid"].as_str().unwrap(), t.wtxid().display_hex());
    assert_eq!(mempool["weight"].as_u64(), Some(t.weight()));
    assert_eq!(mempool["vsize"].as_u64(), Some(316));
    assert_eq!(
        json::scaled_unsigned(&mempool["fees"]["base"], 8).unwrap(),
        632
    );
    assert!(mempool["depends"].as_array().unwrap().is_empty());
    assert!(mempool["spentby"].as_array().unwrap().is_empty());
    assert_eq!(
        Txid(double_sha256(&t.encode())).display_hex(),
        mempool["wtxid"].as_str().unwrap()
    );
}
