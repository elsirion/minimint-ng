//! Public certificates establish acceptance; API/Core captures corroborate the
//! resulting assets. No client tokens, private keys, or local DB state are used.
use minimint_ng::{
    codec::{
        ConsensusDecode, ConsensusEncode, DecodeError, Reader, decode_whole, rpc,
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
    modules::{mint, wallet},
    protocol::{
        ConsensusItem, DynamicValue, ModuleId, ModuleRegistry, ModuleValueKind, PeerId,
        SignedSessionOutcome, TransactionSignatures,
    },
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

struct Registry;
impl ModuleRegistry for Registry {
    fn decode_payload(
        &self,
        id: ModuleId,
        kind: ModuleValueKind,
        r: &mut Reader<'_>,
    ) -> Result<(), DecodeError> {
        match (id.0, kind) {
            (0, ModuleValueKind::Input) => {
                mint::Input::consensus_decode(r)?;
            }
            (0, ModuleValueKind::Output) => {
                mint::Output::consensus_decode(r)?;
            }
            (1, ModuleValueKind::Input) => {
                wallet::Input::consensus_decode(r)?;
            }
            (1, ModuleValueKind::Output) => {
                wallet::Output::consensus_decode(r)?;
            }
            (1, ModuleValueKind::ConsensusItem) => {
                wallet::ConsensusItem::consensus_decode(r)?;
            }
            _ => return Err(DecodeError::UnknownModule),
        }
        Ok(())
    }
}
fn read(root: &Path, name: &str) -> Value {
    minimint_ng::json::parse(&fs::read(root.join(name)).unwrap(), 4 * 1024 * 1024, 64).unwrap()
}
fn result(root: &Path, name: &str) -> Value {
    let value = read(root, name);
    assert!(value.get("error").is_none());
    value.get("result").cloned().unwrap_or(value)
}
fn manifest(root: &Path) {
    let value = read(root, "manifest.json");
    for (name, digest) in value["sha256"].as_object().unwrap() {
        assert!(!Path::new(name).is_absolute() && !name.split('/').any(|part| part == ".."));
        assert_eq!(
            hex_encode(&sha256(&fs::read(root.join(name)).unwrap())),
            digest.as_str().unwrap()
        );
    }
}
fn fee(amount: u64, base: u64, ppm: u64) -> u64 {
    base.checked_add(amount.saturating_mul(ppm) / 1_000_000)
        .unwrap()
}
fn amount(denomination: u8, config: &RawMintConfig) -> u64 {
    assert!(config.aggregate_keys.contains_key(&denomination));
    1u64.checked_shl(denomination.into()).unwrap()
}
fn deposit_script(claimant: &[u8; 33], config: &RawWalletConfig) -> Vec<u8> {
    let tweak = sha256(claimant);
    let mut keys: Vec<_> = config
        .bitcoin_pks
        .values()
        .map(|key| secp::add_tweak(key, &tweak).unwrap())
        .collect();
    keys.sort();
    assert_eq!(keys.len(), 4);
    let mut witness = vec![0x53];
    for key in keys {
        witness.push(33);
        witness.extend(key);
    }
    witness.extend([0x54, 0xae]);
    [vec![0, 32], sha256(&witness).to_vec()].concat()
}
fn config<T: ConsensusDecode>(json: &Value, id: u16) -> T {
    let dynamic: DynamicValue = decode_whole(
        &hex_decode(json["modules"][&id.to_string()]["config"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(dynamic.module_id, ModuleId(id));
    decode_whole(&dynamic.payload).unwrap()
}

#[test]
fn completed_mixed_monetary_history_verifies_authorization_and_exact_accounting() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/interop/mixed-monetary-2026-09-11");
    manifest(&root);
    let stage = root.join("monetary_observed");
    // Absence of this final fixture must fail, never downgrade to an earlier
    // successful stage that did not yet certify withdrawal acceptance.
    manifest(&stage);
    let public = result(&root, "peer0-client_config.json");
    assert_eq!(public["modules"].as_object().unwrap().len(), 2);
    for (id, kind) in [("0", "mintv2"), ("1", "walletv2")] {
        assert_eq!(public["modules"][id]["kind"].as_str(), Some(kind));
        assert_eq!(public["modules"][id]["version"]["major"].as_u64(), Some(1));
        assert_eq!(public["modules"][id]["version"]["minor"].as_u64(), Some(0));
    }
    let mut peer_ids: Vec<_> = public["broadcast_public_keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, _)| id.parse::<u16>().unwrap())
        .collect();
    peer_ids.sort();
    assert_eq!(peer_ids, [0, 1, 2, 3]);
    assert_eq!(public["consensus_version"]["major"].as_u64(), Some(2));
    assert_eq!(public["consensus_version"]["minor"].as_u64(), Some(1));
    let mint_config: RawMintConfig = config(&public, 0);
    let wallet_config: RawWalletConfig = config(&public, 1);
    assert_eq!(
        wallet_config
            .bitcoin_pks
            .keys()
            .map(|id| id.0)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    let keys = public["broadcast_public_keys"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(peer, value)| {
            (
                PeerId(peer.parse().unwrap()),
                hex_decode(value.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
        })
        .collect();
    let verifier = HistoryVerifier::new(keys).unwrap();
    assert_eq!(verifier.quorum(), 3);
    let count = result(&stage, "peer0-session_count.json").as_u64().unwrap();
    assert!((1..=128).contains(&count));
    let mut history = Vec::new();
    for index in 0..count {
        let mut common = None;
        for peer in 0..4 {
            assert_eq!(
                result(&stage, &format!("peer{peer}-session_count.json")).as_u64(),
                Some(count)
            );
            let value = result(&stage, &format!("peer{peer}-signed-session-{index}.json"));
            let wrapper: Vec<_> = value
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            let framed = rpc::decode_hex::<SignedSessionOutcome>(&wrapper).unwrap();
            let signed =
                SignedSessionOutcome::decode_with_registry(&framed.consensus_encode(), &Registry)
                    .unwrap();
            verifier
                .verify(index, &signed, SignaturePolicy::GuardianAdoption)
                .unwrap();
            assert!(
                verifier
                    .verify(index + 1, &signed, SignaturePolicy::GuardianAdoption)
                    .is_err()
            );
            if let Some(expected) = &common {
                assert_eq!(&signed.outcome, expected);
            } else {
                common = Some(signed.outcome);
            }
        }
        history.extend(common.unwrap().items.into_iter().map(|item| (index, item)));
    }
    let discoveries = result(&stage, "peer0-module_1_output_info_slice.json");
    let discoveries: BTreeMap<_, _> = discoveries
        .as_array()
        .unwrap()
        .iter()
        .map(|value| (value["index"].as_u64().unwrap(), value.clone()))
        .collect();
    assert_eq!(discoveries.len(), 2);
    // Corroborate the unsigned discovery values/scripts/outpoints with captured
    // public Bitcoin funding transactions, without treating API JSON as signed.
    for (index, name) in [
        (0, "deposit-decode.json"),
        (1, "second-deposit-decode.json"),
    ] {
        let funding = result(&root, name);
        let discovery = &discoveries[&index];
        let outpoint = discovery["outpoint"].as_str().unwrap();
        let (txid, vout) = outpoint.rsplit_once(':').unwrap();
        assert_eq!(funding["txid"].as_str(), Some(txid));
        let output = &funding["vout"][vout.parse::<usize>().unwrap()];
        assert_eq!(output["scriptPubKey"]["hex"], discovery["script"]);
        assert_eq!(discovery["value"].as_u64(), Some(100_000));
        let filename = if index == 0 {
            "deposit.hex"
        } else {
            "second-deposit.hex"
        };
        let bytes = hex_decode(fs::read_to_string(root.join(filename)).unwrap().trim()).unwrap();
        let bitcoin = minimint_ng::bitcoin::Transaction::decode(&bytes).unwrap();
        assert_eq!(bitcoin.txid().display_hex(), txid);
        let bitcoin_output = &bitcoin.outputs[vout.parse::<usize>().unwrap()];
        assert_eq!(bitcoin_output.value_sat, 100_000);
        assert_eq!(
            hex_encode(&bitcoin_output.script_pubkey),
            discovery["script"].as_str().unwrap()
        );
        assert_eq!(discovery["spent"].as_bool(), Some(true));
    }
    let mut counters = BTreeMap::<u8, u64>::new();
    let mut spent = BTreeSet::new();
    let mut accepted = BTreeSet::new();
    let mut claimed = BTreeSet::new();
    let mut wallet_value = 0u64;
    let mut audited = 0u64;
    let mut claim_fees = Vec::new();
    let mut withdrawals = Vec::new();
    let mut pure_reissues = 0;
    let mut recovery_records = 0u64;
    let mut chain_steps = Vec::new();
    for (session, accepted_item) in history {
        let ConsensusItem::Transaction(tx) = accepted_item.item else {
            continue;
        };
        let id = transaction_id(&tx);
        assert!(accepted.insert(id), "accepted transaction executed twice");
        let mut input_amount = 0u64;
        let mut output_amount = 0u64;
        let mut fees = 0u64;
        let mut public_keys = Vec::new();
        let mut input_notes = 0;
        let mut wallet_actions = 0;
        let audit_before = audited;
        let mut initial_claim_mining = 0u64;
        for input in &tx.inputs {
            let (value, input_fee, public_key) = match input.module_id.0 {
                0 => {
                    let mint::Input::V0(note) = decode_whole(&input.payload).unwrap() else {
                        panic!("unknown accepted Mint input")
                    };
                    let value = amount(note.denomination, &mint_config);
                    let public =
                        G2::from_bytes(&mint_config.aggregate_keys[&note.denomination]).unwrap();
                    let message = bls::message_sha256(&note.nonce.to_bytes()).unwrap();
                    let signature = G1::from_bytes(&note.signature.to_bytes()).unwrap();
                    bls::verify_share(&message, &public, &signature).unwrap();
                    assert!(
                        spent.insert(note.nonce.to_bytes()),
                        "note nonce accepted twice"
                    );
                    let counter = counters
                        .get_mut(&note.denomination)
                        .expect("spend before issuance");
                    *counter = counter.checked_sub(1).unwrap();
                    input_notes += 1;
                    recovery_records += 1;
                    (
                        value,
                        fee(
                            value,
                            mint_config.fee.base,
                            mint_config.fee.parts_per_million,
                        ),
                        note.nonce.to_bytes(),
                    )
                }
                1 => {
                    let wallet::Input::V0 {
                        output_index,
                        claimant,
                        mining_fee_sat,
                    } = decode_whole(&input.payload).unwrap()
                    else {
                        panic!("unknown accepted Wallet input")
                    };
                    assert!(claimed.insert(output_index), "discovery claimed twice");
                    assert_eq!(
                        hex_encode(&deposit_script(&claimant, &wallet_config)),
                        discoveries[&output_index]["script"].as_str().unwrap(),
                        "claim authorization key must own the captured deposit script"
                    );
                    let deposit = discoveries[&output_index]["value"].as_u64().unwrap();
                    let credit = deposit
                        .checked_sub(mining_fee_sat)
                        .unwrap()
                        .checked_mul(1000)
                        .unwrap();
                    let previous = wallet_value;
                    if previous == 0 {
                        wallet_value = deposit;
                        initial_claim_mining = mining_fee_sat.checked_mul(1000).unwrap();
                    } else {
                        wallet_value = previous
                            .checked_add(deposit)
                            .unwrap()
                            .checked_sub(mining_fee_sat)
                            .unwrap();
                        chain_steps.push((previous, wallet_value, mining_fee_sat));
                    }
                    claim_fees.push((output_index, mining_fee_sat));
                    wallet_actions += 1;
                    (
                        credit,
                        fee(
                            credit,
                            wallet_config.fee_consensus.base,
                            wallet_config.fee_consensus.parts_per_million,
                        ),
                        claimant,
                    )
                }
                _ => panic!("unknown accepted input module"),
            };
            input_amount = input_amount.checked_add(value).unwrap();
            fees = fees.checked_add(input_fee).unwrap();
            public_keys.push(public_key);
        }
        let TransactionSignatures::Schnorr(signatures) = &tx.signatures else {
            panic!("unexpected signature scheme")
        };
        assert_eq!(signatures.len(), public_keys.len());
        for (key, signature) in public_keys.iter().zip(signatures) {
            secp::schnorr_verify(&secp::x_only(key).unwrap(), &id, signature).unwrap();
            let mut changed = id;
            changed[0] ^= 1;
            assert!(
                secp::schnorr_verify(&secp::x_only(key).unwrap(), &changed, signature).is_err()
            );
        }
        for output in &tx.outputs {
            let (value, output_fee) = match output.module_id.0 {
                0 => {
                    let mint::Output::V0(output) = decode_whole(&output.payload).unwrap() else {
                        panic!("unknown accepted Mint output")
                    };
                    let value = amount(output.denomination, &mint_config);
                    *counters.entry(output.denomination).or_default() += 1;
                    recovery_records += 1;
                    (
                        value,
                        fee(
                            value,
                            mint_config.fee.base,
                            mint_config.fee.parts_per_million,
                        ),
                    )
                }
                1 => {
                    let wallet::Output::V0 {
                        destination,
                        value_sat,
                        mining_fee_sat,
                    } = decode_whole(&output.payload).unwrap()
                    else {
                        panic!("unknown accepted Wallet output")
                    };
                    assert_eq!(value_sat, 50_000);
                    assert!((1..=5000).contains(&mining_fee_sat));
                    let previous = wallet_value;
                    wallet_value = previous
                        .checked_sub(value_sat)
                        .unwrap()
                        .checked_sub(mining_fee_sat)
                        .unwrap();
                    assert!(wallet_value >= wallet_config.dust_limit);
                    chain_steps.push((previous, wallet_value, mining_fee_sat));
                    withdrawals.push((session, id, destination, value_sat, mining_fee_sat));
                    wallet_actions += 1;
                    let value = value_sat
                        .checked_add(mining_fee_sat)
                        .unwrap()
                        .checked_mul(1000)
                        .unwrap();
                    (
                        value,
                        fee(
                            value,
                            wallet_config.fee_consensus.base,
                            wallet_config.fee_consensus.parts_per_million,
                        ),
                    )
                }
                _ => panic!("unknown accepted output module"),
            };
            output_amount = output_amount.checked_add(value).unwrap();
            fees = fees.checked_add(output_fee).unwrap();
        }
        if input_notes > 0 && wallet_actions == 0 {
            pure_reissues += 1;
        }
        let excess = input_amount
            .checked_sub(output_amount.checked_add(fees).unwrap())
            .unwrap();
        let liabilities = counters
            .iter()
            .try_fold(0u64, |total, (denomination, count)| {
                total.checked_add(
                    amount(*denomination, &mint_config)
                        .checked_mul(*count)
                        .unwrap(),
                )
            })
            .unwrap();
        let assets = wallet_value.checked_mul(1000).unwrap();
        audited = assets.checked_sub(liabilities).unwrap();
        assert!(
            audited <= i64::MAX as u64
                && assets <= i64::MAX as u64
                && liabilities <= i64::MAX as u64
        );
        assert_eq!(audited - audit_before, initial_claim_mining + fees + excess);
        eprintln!(
            "certified session={session} tx={} inputs_msat={input_amount} outputs_msat={output_amount} fees_msat={fees} excess_msat={excess} audit_msat={audited}",
            hex_encode(&id)
        );
    }
    assert_eq!(claim_fees.len(), 2);
    assert_eq!(
        withdrawals.len(),
        1,
        "fixture must certify withdrawal, not just earlier issuance"
    );
    assert!(pure_reissues >= 1, "fixture must certify Mint reissuance");
    let raw_bitcoin = |index| {
        minimint_ng::bitcoin::Transaction::decode(
            &hex_decode(
                fs::read_to_string(stage.join(format!("chain-{index}.hex")))
                    .unwrap()
                    .trim(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let parent = raw_bitcoin(0);
    let child = raw_bitcoin(1);
    assert_eq!(parent.inputs.len(), 2);
    assert_eq!(parent.outputs.len(), 1);
    assert_eq!(child.inputs.len(), 1);
    assert_eq!(child.outputs.len(), 2);
    assert_eq!(child.inputs[0].previous_output.txid, parent.txid());
    assert_eq!(child.inputs[0].previous_output.vout, 0);
    let (_, _, destination, value, mining) = &withdrawals[0];
    assert_eq!(
        child.outputs[1].script_pubkey,
        destination.script_pubkey().unwrap()
    );
    assert_eq!(child.outputs[1].value_sat, *value);
    assert_eq!(
        parent.outputs[0].value_sat
            - child
                .outputs
                .iter()
                .map(|output| output.value_sat)
                .sum::<u64>(),
        *mining
    );
    assert_eq!(child.outputs[0].value_sat, wallet_value);
    // These CLI maps are unsigned inventory reports, not proof of possession.
    // Their per-denomination totals must match the liabilities reconstructed
    // independently from every certified issuance and accepted note spend.
    let mut inventory = BTreeMap::<u8, u64>::new();
    for client in ["a", "b"] {
        let counts = result(&root, &format!("confirmation-notes-{client}.json"));
        for (denomination, count) in counts.as_object().unwrap() {
            let parsed: u8 = denomination.parse().unwrap();
            assert_eq!(denomination, parsed.to_string());
            amount(parsed, &mint_config);
            let count = count.as_u64().unwrap();
            let total = inventory.entry(parsed).or_default();
            *total = total.checked_add(count).unwrap();
        }
    }
    inventory.retain(|_, count| *count != 0);
    counters.retain(|_, count| *count != 0);
    assert_eq!(inventory, counters);
    let inventory_value = inventory
        .iter()
        .try_fold(0u64, |total, (denomination, count)| {
            total.checked_add(
                amount(*denomination, &mint_config)
                    .checked_mul(*count)
                    .unwrap(),
            )
        })
        .unwrap();
    assert_eq!(
        wallet_value.checked_mul(1000).unwrap() - inventory_value,
        audited
    );
    for peer in 0..4 {
        let view = result(
            &stage,
            &format!("peer{peer}-module_1_federation_wallet.json"),
        );
        assert_eq!(view["value"].as_u64(), Some(wallet_value));
        assert_eq!(
            result(&stage, &format!("peer{peer}-module_0_recovery_count.json")).as_u64(),
            Some(recovery_records)
        );
        let chain = result(
            &stage,
            &format!("peer{peer}-module_1_transaction_chain.json"),
        );
        assert_eq!(chain.as_array().unwrap().len(), chain_steps.len());
        for (item, (input, output, mining)) in chain.as_array().unwrap().iter().zip(&chain_steps) {
            assert_eq!(item["input"].as_u64(), Some(*input));
            assert_eq!(item["output"].as_u64(), Some(*output));
            assert_eq!(item["fee"].as_u64(), Some(*mining));
        }
        assert!(
            result(
                &stage,
                &format!("peer{peer}-module_1_pending_transaction_chain.json")
            )
            .as_array()
            .unwrap()
            .is_empty()
        );
    }
    eprintln!(
        "certified claims={claim_fees:?}, withdrawal_fee_sat={}, final_wallet_sat={wallet_value}, net_audit_msat={audited}",
        withdrawals[0].4
    );
}
