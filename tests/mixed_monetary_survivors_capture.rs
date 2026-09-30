//! Offline regressions for all four completed monetary survivor cases in the
//! corrected retry federation. Each case passed its gate before live advancement.
use minimint_ng::{
    bitcoin::{Block, Transaction as BitcoinTransaction, Txid, double_sha256},
    codec::{
        ConsensusEncode, decode_whole, rpc,
        text::{hex_decode, hex_encode},
    },
    config::{RawMintConfig, RawWalletConfig},
    core::{
        history::{HistoryVerifier, SignaturePolicy},
        transaction::transaction_id,
    },
    crypto::{
        bls::{self, G1, G2},
        secp, sha256,
    },
    json,
    modules::mint,
    protocol::{ConsensusItem, DynamicValue, PeerId, SignedSessionOutcome, Transaction},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
fn root() -> PathBuf {
    if let Some(path) = std::env::var_os("MINIMINT_SURVIVOR_FIXTURE_ROOT") {
        return PathBuf::from(path);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop/mixed-monetary-survivors-retry-2026-09-11")
}
fn read(path: &Path) -> Value {
    json::parse(&fs::read(path).unwrap(), 16 * 1024 * 1024, 64).unwrap()
}
fn raw(path: &Path) -> Vec<u8> {
    hex_decode(fs::read_to_string(path).unwrap().trim()).unwrap()
}
fn signed_history(path: &Path) -> SignedSessionOutcome {
    let value = read(path);
    let strings: Vec<_> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    rpc::decode_hex(&strings).unwrap()
}
fn fixture_files(base: &Path, directory: &Path, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        assert!(!kind.is_symlink(), "fixture symlink");
        if kind.is_dir() {
            fixture_files(base, &entry.path(), files);
        } else {
            assert!(kind.is_file());
            let path = entry.path();
            let name = path.strip_prefix(base).unwrap().to_str().unwrap();
            if name != "manifest.json" {
                files.insert(name.to_owned());
            }
        }
    }
}
fn script(config: &RawWalletConfig, tweak: &[u8; 32]) -> (Vec<u8>, Vec<([u8; 33], PeerId)>) {
    assert_eq!(config.bitcoin_pks.len(), 4);
    let mut keys: Vec<_> = config
        .bitcoin_pks
        .iter()
        .map(|(peer, key)| (secp::add_tweak(key, tweak).unwrap(), *peer))
        .collect();
    keys.sort();
    let mut script = vec![0x53];
    for (key, _) in &keys {
        script.push(33);
        script.extend(key);
    }
    script.extend([0x54, 0xae]);
    (script, keys)
}
fn target(
    case: &Path,
    name: &str,
    verifier: &HistoryVerifier,
    survivors: &BTreeSet<PeerId>,
    stopped_count: u64,
) -> Transaction {
    let pointer = read(&case.join(format!("{name}-target.json")));
    let index = pointer["session"].as_u64().unwrap();
    assert!(index >= stopped_count);
    let value = read(&case.join(format!("{name}-history.json")));
    let strings: Vec<_> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let signed: SignedSessionOutcome = rpc::decode_hex(&strings).unwrap();
    verifier
        .verify(index, &signed, SignaturePolicy::GuardianAdoption)
        .unwrap();
    assert_eq!(
        signed.signatures.keys().copied().collect::<BTreeSet<_>>(),
        *survivors
    );
    let found: Vec<_> = signed
        .outcome
        .items
        .iter()
        .filter_map(|item| match &item.item {
            ConsensusItem::Transaction(tx)
                if hex_encode(&transaction_id(tx))
                    == pointer["transaction_id"].as_str().unwrap() =>
            {
                Some(tx.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1);
    found[0].clone()
}
fn shares(
    case: &Path,
    name: &str,
    transaction: &Transaction,
    config: &RawMintConfig,
    restored: PeerId,
) {
    let value = read(&case.join(format!("{name}-restored-shares.json")));
    let replies = value.as_array().unwrap();
    let outputs: Vec<_> = transaction
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| o.module_id.0 == 0)
        .collect();
    assert!(!outputs.is_empty() && outputs.len() <= 256);
    assert_eq!(replies.len(), outputs.len());
    for (reply, (index, output)) in replies.iter().zip(outputs) {
        let mint::Output::V0(output) = decode_whole::<mint::Output>(&output.payload).unwrap()
        else {
            panic!("Mint output version")
        };
        assert_eq!(reply["output_index"].as_u64(), Some(index as u64));
        assert_eq!(
            reply["denomination"].as_u64(),
            Some(u64::from(output.denomination))
        );
        assert_eq!(
            reply["request"]["txid"].as_str().unwrap(),
            hex_encode(&transaction_id(transaction))
        );
        assert_eq!(
            reply["request"]["idx_range"]["start"].as_u64(),
            Some(index as u64)
        );
        assert_eq!(
            reply["request"]["idx_range"]["end"].as_u64(),
            Some(index as u64 + 1)
        );
        assert_eq!(reply["response"].as_array().unwrap().len(), 1);
        let bytes: [u8; 48] = hex_decode(reply["response"][0].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let public =
            G2::from_bytes(&config.public_shares[&output.denomination][&restored]).unwrap();
        let message = G1::from_bytes(&output.blinded_message.to_bytes()).unwrap();
        bls::verify_share(&message, &public, &G1::from_bytes(&bytes).unwrap()).unwrap();
    }
}
fn verify_case(peer: u16) {
    let root = root();
    let case = root.join(format!("case{peer}"));
    let manifest = read(&root.join("manifest.json"));
    for (name, digest) in manifest["sha256"].as_object().unwrap() {
        assert!(
            Path::new(name)
                .components()
                .all(|p| matches!(p, std::path::Component::Normal(_)))
        );
        assert_eq!(
            hex_encode(&sha256(&fs::read(root.join(name)).unwrap())),
            digest.as_str().unwrap()
        );
    }
    let listed: BTreeSet<_> = manifest["sha256"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, _)| name.to_owned())
        .collect();
    let mut actual = BTreeSet::new();
    fixture_files(&root, &root, &mut actual);
    assert_eq!(
        actual, listed,
        "manifest must cover every consumed fixture file"
    );
    let config = read(&root.join("peer0-client_config.json"));
    let decode_config = |id: &str| {
        decode_whole::<DynamicValue>(
            &hex_decode(config["modules"][id]["config"].as_str().unwrap()).unwrap(),
        )
        .unwrap()
    };
    let wallet: RawWalletConfig = decode_whole(&decode_config("1").payload).unwrap();
    let mint: RawMintConfig = decode_whole(&decode_config("0").payload).unwrap();
    let verifier = HistoryVerifier::new(
        config["broadcast_public_keys"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(id, key)| {
                (
                    PeerId(id.parse().unwrap()),
                    hex_decode(key.as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
            })
            .collect(),
    )
    .unwrap();
    let marker = read(&case.join("marker.json"));
    assert_eq!(marker["schema"].as_u64(), Some(1));
    assert_eq!(marker["peer"].as_u64(), Some(u64::from(peer)));
    let stop = read(&case.join("stop-ack.json"));
    let restart = read(&case.join("restart-ack.json"));
    for ack in [&stop, &restart] {
        assert_eq!(ack["schema"].as_u64(), Some(1));
        assert_eq!(ack["peer"].as_u64(), Some(u64::from(peer)));
    }
    assert_eq!(stop["id"].as_u64(), Some(u64::from(peer) * 2));
    assert_eq!(restart["id"].as_u64(), Some(u64::from(peer) * 2 + 1));
    assert_eq!(stop["action"].as_str(), Some("stop"));
    assert_eq!(restart["action"].as_str(), Some("restart"));
    assert!(matches!(stop["exit"].as_i64(), Some(0 | 255)));
    let artifacts = read(&root.join("artifacts.json"));
    match artifacts["guardian_implementations"][usize::from(peer)]
        .as_str()
        .unwrap()
    {
        "independent" => assert_eq!(stop["exit"].as_i64(), Some(0)),
        "reference" => {}
        _ => panic!("unknown guardian implementation"),
    }
    assert!(restart["exit"].is_null());
    assert!(
        marker["final_count"].as_u64().unwrap()
            > marker["post_broadcast_completed_count"].as_u64().unwrap()
    );
    assert!(
        restart["completed_count"].as_u64().unwrap() >= marker["final_count"].as_u64().unwrap()
    );
    assert!(
        marker["post_broadcast_completed_count"].as_u64().unwrap()
            >= stop["completed_count"].as_u64().unwrap()
    );
    let survivors: BTreeSet<_> = (0..4).filter(|p| *p != peer).map(PeerId).collect();
    let count = restart["completed_count"].as_u64().unwrap();
    assert!((1..=1024).contains(&count));
    let reference_peer = survivors.first().unwrap().0;
    for index in 0..count {
        let reference = signed_history(&case.join(format!(
            "before-peer{reference_peer}-signed-session{index}.json"
        )));
        for p in 0..4 {
            for phase in ["before", "after"] {
                if phase == "before" && p == peer {
                    continue;
                }
                let history = signed_history(
                    &case.join(format!("{phase}-peer{p}-signed-session{index}.json")),
                );
                verifier
                    .verify(index, &history, SignaturePolicy::GuardianAdoption)
                    .unwrap();
                assert_eq!(
                    history.outcome, reference.outcome,
                    "completed outcome changed across joined restart"
                );
            }
        }
    }
    for name in ["withdrawal", "reissue"] {
        let pointer = read(&case.join(format!("{name}-target.json")));
        let index = pointer["session"].as_u64().unwrap();
        assert!(index < count);
        let reference = signed_history(&case.join(format!(
            "before-peer{reference_peer}-signed-session{index}.json"
        )));
        assert_eq!(
            signed_history(&case.join(format!("{name}-history.json"))).outcome,
            reference.outcome
        );
    }
    let withdrawal = target(
        &case,
        "withdrawal",
        &verifier,
        &survivors,
        stop["completed_count"].as_u64().unwrap(),
    );
    let reissue = target(
        &case,
        "reissue",
        &verifier,
        &survivors,
        stop["completed_count"].as_u64().unwrap(),
    );
    let note_markers: BTreeSet<_> = marker["reissue_notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["denomination"].as_u64().unwrap(),
                m["signature_sha256"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(!note_markers.is_empty());
    assert_eq!(
        note_markers.len(),
        marker["reissue_notes"].as_array().unwrap().len()
    );
    assert!(note_markers.len() <= 256);
    assert!(!reissue.inputs.is_empty() && reissue.inputs.len() <= 256);
    assert!(!reissue.outputs.is_empty() && reissue.outputs.len() <= 256);
    assert!(reissue.outputs.iter().all(|output| output.module_id.0 == 0));
    let mut notes = BTreeSet::new();
    for input in &reissue.inputs {
        assert_eq!(input.module_id.0, 0);
        let mint::Input::V0(note) = decode_whole::<mint::Input>(&input.payload).unwrap() else {
            panic!("note version")
        };
        assert!(notes.insert((
            u64::from(note.denomination),
            hex_encode(&sha256(&note.signature.to_bytes()))
        )));
    }
    assert!(
        note_markers.is_subset(&notes),
        "every exported note must be consumed exactly once"
    );
    let mut marker_uses = std::collections::BTreeMap::new();
    let mut reissue_occurrences = 0;
    for index in 0..count {
        let history = signed_history(&case.join(format!(
            "before-peer{reference_peer}-signed-session{index}.json"
        )));
        for item in history.outcome.items {
            if let ConsensusItem::Transaction(tx) = item.item {
                if transaction_id(&tx) == transaction_id(&reissue) {
                    reissue_occurrences += 1;
                }
                for input in tx.inputs.iter().filter(|input| input.module_id.0 == 0) {
                    let mint::Input::V0(note) =
                        decode_whole::<mint::Input>(&input.payload).unwrap()
                    else {
                        panic!("note version")
                    };
                    let marker = (
                        u64::from(note.denomination),
                        hex_encode(&sha256(&note.signature.to_bytes())),
                    );
                    if note_markers.contains(&marker) {
                        *marker_uses.entry(marker).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    assert_eq!(reissue_occurrences, 1);
    assert_eq!(
        marker_uses,
        note_markers
            .iter()
            .cloned()
            .map(|marker| (marker, 1))
            .collect()
    );
    shares(&case, "withdrawal", &withdrawal, &mint, PeerId(peer));
    shares(&case, "reissue", &reissue, &mint, PeerId(peer));
    let before = read(&case.join("before-stop-money.json"));
    let old = &before["module_1_federation_wallet"];
    let parent_wire = raw(&case.join("parent.hex"));
    let parent = BitcoinTransaction::decode(&parent_wire).unwrap();
    assert_eq!(parent.encode(), parent_wire);
    let old_point = old["outpoint"].as_str().unwrap();
    let (old_id, vout) = old_point.split_once(':').unwrap();
    assert_eq!(old_id, parent.txid().display_hex());
    let vout: usize = vout.parse().unwrap();
    let previous = &parent.outputs[vout];
    assert_eq!(Some(previous.value_sat), old["value"].as_u64());
    assert_eq!(marker["parent_bitcoin_txid"].as_str(), Some(old_id));
    let tweak: [u8; 32] = hex_decode(old["tweak"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let (witness, keys) = script(&wallet, &tweak);
    assert_eq!(
        previous.script_pubkey,
        [vec![0, 32], sha256(&witness).to_vec()].concat()
    );
    let child_wire = raw(&case.join("withdrawal.hex"));
    let child = BitcoinTransaction::decode(&child_wire).unwrap();
    assert_eq!(child.encode(), child_wire);
    assert_eq!(child.inputs.len(), 1);
    assert_eq!(child.outputs.len(), 2);
    assert_eq!((child.version, child.lock_time), (2, 0));
    let input = &child.inputs[0];
    assert_eq!(input.previous_output.txid, parent.txid());
    assert_eq!(input.previous_output.vout as usize, vout);
    assert_eq!(input.sequence, 0xffff_fffd);
    assert!(input.script_sig.is_empty());
    assert_eq!(input.witness.len(), 5);
    assert!(input.witness[0].is_empty());
    assert_eq!(input.witness[4], witness);
    let digest = child.sighash_all(0, &witness, previous.value_sat).unwrap();
    let mut next = 0;
    let mut signers = BTreeSet::new();
    for encoded in &input.witness[1..4] {
        assert_eq!(encoded.last(), Some(&1));
        let signature = secp::ecdsa_der_to_compact(&encoded[..encoded.len() - 1]).unwrap();
        let index = (next..keys.len())
            .find(|&i| secp::ecdsa_verify(&keys[i].0, &digest, &signature).is_ok())
            .unwrap();
        assert!(signers.insert(keys[index].1));
        next = index + 1;
    }
    assert_eq!(
        signers, survivors,
        "actual Bitcoin signatures must be from all three surviving guardian IDs"
    );
    let amount = marker["amount_sat"].as_u64().unwrap();
    assert_eq!(amount, 10000);
    let fee = marker["fee_sat"].as_u64().unwrap();
    assert_eq!(
        previous.value_sat - child.outputs.iter().map(|o| o.value_sat).sum::<u64>(),
        fee
    );
    assert_eq!(child.outputs[1].value_sat, amount);
    assert_eq!(child.outputs[1].script_pubkey.len(), 22);
    assert_eq!(&child.outputs[1].script_pubkey[..2], &[0, 20]);
    assert_eq!(
        hex_encode(&child.outputs[1].script_pubkey),
        marker["destination_script"].as_str().unwrap()
    );
    assert_eq!(
        child.txid().display_hex(),
        marker["bitcoin_txid"].as_str().unwrap()
    );
    let mut previous_encoding = previous.value_sat.consensus_encode();
    previous_encoding.extend(input.previous_output.consensus_encode());
    previous_encoding.extend(tweak);
    let change_tweak = sha256(&previous_encoding);
    let (change_script, _) = script(&wallet, &change_tweak);
    assert_eq!(
        child.outputs[0].script_pubkey,
        [vec![0, 32], sha256(&change_script).to_vec()].concat()
    );
    let pointer = read(&case.join("withdrawal-target.json"));
    let out_idx = pointer["out_idx"].as_u64().unwrap() as usize;
    assert_eq!(withdrawal.outputs[out_idx].module_id.0, 1);
    let minimint_ng::modules::wallet::Output::V0 {
        destination,
        value_sat,
        mining_fee_sat,
    } = decode_whole(&withdrawal.outputs[out_idx].payload).unwrap()
    else {
        panic!("Wallet output version")
    };
    assert_eq!(
        destination.script_pubkey().unwrap(),
        child.outputs[1].script_pubkey
    );
    assert_eq!((value_sat, mining_fee_sat), (amount, fee));
    assert_eq!(pointer["bitcoin_txid"], marker["bitcoin_txid"]);
    let decoded = read(&case.join("withdrawal-decoded.json"));
    assert_eq!(
        decoded["txid"].as_str().unwrap(),
        child.txid().display_hex()
    );
    assert_eq!(
        decoded["hash"].as_str().unwrap(),
        child.wtxid().display_hex()
    );
    assert_eq!(decoded["weight"].as_u64(), Some(child.weight()));
    assert!(decoded["confirmations"].as_u64().unwrap() >= 1);
    let mempool = read(&case.join("withdrawal-mempool.json"));
    assert_eq!(mempool["wtxid"], decoded["hash"]);
    assert_eq!(
        json::scaled_unsigned(&mempool["fees"]["base"], 8).unwrap(),
        fee
    );
    let block = Block::decode(&raw(&case.join("confirmed-block.hex"))).unwrap();
    let core = read(&case.join("confirmed-block.json"));
    assert_eq!(
        Txid(block.hash()).display_hex(),
        marker["block_hash"].as_str().unwrap()
    );
    assert_eq!(core["hash"], marker["block_hash"]);
    assert_eq!(decoded["blockhash"], marker["block_hash"]);
    assert_eq!(core["height"], marker["confirmed_height"]);
    assert_eq!(
        block.transactions.iter().filter(|t| *t == &child).count(),
        1
    );
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
    let completed = read(&case.join("before-restart-money.json"));
    for p in 0..4 {
        assert_eq!(
            read(&case.join(format!("after-restart-peer{p}-money.json"))),
            completed
        );
    }
    let final_wallet = &completed["module_1_federation_wallet"];
    assert_eq!(
        final_wallet["value"].as_u64(),
        Some(child.outputs[0].value_sat)
    );
    assert_eq!(
        final_wallet["tweak"].as_str().unwrap(),
        hex_encode(&change_tweak)
    );
    assert_eq!(
        final_wallet["outpoint"].as_str().unwrap(),
        format!("{}:0", child.txid().display_hex())
    );
    assert!(
        completed["module_1_pending_transaction_chain"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
#[test]
fn survivor_case0() {
    verify_case(0)
}
#[test]
fn survivor_case1() {
    verify_case(1)
}
#[test]
fn survivor_case2() {
    verify_case(2)
}
#[test]
fn survivor_case3() {
    verify_case(3)
}
