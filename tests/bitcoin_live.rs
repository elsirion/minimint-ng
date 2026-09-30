//! Explicit live regtest backend evidence, not a Fedimint client or monetary flow.
//! Run: cargo test --test bitcoin_live -- --ignored --nocapture --test-threads=1
//! Requires verified Core 31.1, funded wallet `interop`, and the private cookie.
//! The broadcast test spends one mature wallet UTXO back to that wallet; no mining.
use minimint_ng::{
    bitcoin::{BitcoinBackend, Transaction, Txid, rpc::CoreRpc},
    codec::{
        boundary::compact_size,
        text::{hex_decode, hex_encode},
    },
    daemon::options::read_secret,
    json,
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json as value};
use std::{env, path::PathBuf, process::Command, time::Duration};
fn configured(name: &str, fallback: &str) -> String {
    env::var(name).unwrap_or_else(|_| fallback.into())
}
fn cli(method: &str, args: &[&str], wallet: bool) -> String {
    let loader = configured(
        "MINIMINT_BITCOIN_LOADER",
        "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/ld-linux-x86-64.so.2",
    );
    let binary = configured(
        "MINIMINT_BITCOIN_CLI",
        "/tmp/minimint-bitcoin-31.1/bitcoin-31.1/bin/bitcoin-cli",
    );
    let directory = configured(
        "MINIMINT_BITCOIN_DATADIR",
        "/tmp/minimint-bitcoin-31.1/regtest-smoke",
    );
    // timeout bounds the CLI process; cookie authentication stays in its protected
    // datadir and is never placed in command arguments or diagnostic output.
    let mut command = Command::new("timeout");
    command
        .arg("15s")
        .arg(loader)
        .arg(binary)
        .arg(format!("-datadir={directory}"));
    if wallet {
        command.arg("-rpcwallet=interop");
    }
    let result = command.arg(method).args(args).output().unwrap();
    assert!(result.status.success(), "Bitcoin CLI failed for {method}");
    assert!(result.stdout.len() <= 16 * 1024 * 1024);
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}
fn cli_json(method: &str, args: &[&str], wallet: bool) -> Value {
    json::parse(cli(method, args, wallet).as_bytes(), 16 * 1024 * 1024, 64).unwrap()
}
fn backend() -> CoreRpc {
    let cookie = PathBuf::from(configured(
        "MINIMINT_BITCOIN_COOKIE",
        "/tmp/minimint-bitcoin-31.1/regtest-smoke/regtest/.cookie",
    ));
    let credentials = read_secret(&cookie).expect("private Core cookie unavailable");
    let address = configured("MINIMINT_BITCOIN_RPC", "127.0.0.1:42257")
        .parse()
        .unwrap();
    CoreRpc::new(address, &credentials, Duration::from_secs(5), 6).unwrap()
}
fn require_regtest() -> u64 {
    let network = cli_json("getnetworkinfo", &[], false);
    assert_eq!(json::unsigned(&network["version"]).unwrap(), 310100);
    let chain = cli_json("getblockchaininfo", &[], false);
    assert_eq!(chain["chain"].as_str(), Some("regtest"));
    assert_eq!(chain["initialblockdownload"].as_bool(), Some(false));
    json::unsigned(&chain["blocks"]).unwrap()
}
#[test]
#[ignore = "requires explicitly provisioned verified Bitcoin Core 31.1 regtest service"]
fn live_core_block_count_raw_block_codec_hashes_and_fee_observation_are_exact() {
    let height = require_regtest();
    let backend = backend();
    assert_eq!(backend.block_count().unwrap(), height + 1);
    backend.wait_for_count(height + 1).unwrap();
    let mut heights = vec![0, 1, height];
    heights.sort();
    heights.dedup();
    for height in heights {
        let display_hash = cli("getblockhash", &[&height.to_string()], false);
        let hash = backend.block_hash(height).unwrap();
        assert_eq!(Txid(hash).display_hex(), display_hash);
        let raw = hex_decode(&cli("getblock", &[&display_hash, "0"], false)).unwrap();
        let block = backend.block(hash).unwrap();
        let mut encoded = block.header.to_vec();
        encoded.extend(compact_size(block.transactions.len() as u64));
        for transaction in &block.transactions {
            encoded.extend(transaction.encode());
        }
        assert_eq!(encoded, raw);
        assert_eq!(block.hash(), hash);
        let verbose = cli_json("getblock", &[&display_hash, "1"], false);
        let txids: Vec<_> = verbose["tx"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tx| tx.as_str().unwrap())
            .collect();
        assert_eq!(
            block
                .transactions
                .iter()
                .map(|tx| tx.txid().display_hex())
                .collect::<Vec<_>>(),
            txids
        );
        eprintln!(
            "Core31.1 live block height={height} hash={display_hash} bytes={} transactions={}",
            raw.len(),
            block.transactions.len()
        );
    }
    let fee = cli_json("estimatesmartfee", &["6", "CONSERVATIVE"], false);
    // Compare the actual observation. A provisioned node may have enough real
    // mempool/block history to estimate fees; neither state is synthesized here.
    let expected_fee = fee
        .get("feerate")
        .map(|rate| json::scaled_unsigned(rate, 8).unwrap());
    if expected_fee.is_none() {
        assert!(!fee["errors"].as_array().unwrap().is_empty());
    }
    assert_eq!(backend.fee_rate().unwrap(), expected_fee);
    assert_eq!(require_regtest(), height);
    eprintln!(
        "Core31.1 live observation: Core height={height}, backend count={}, IBD=false, fee_sat_per_kvb={expected_fee:?}",
        height + 1
    );
}
#[test]
#[ignore = "mutates the provisioned regtest wallet and mempool; spends one mature coinbase to self, without mining"]
fn live_core_accepts_backend_broadcast_of_controlled_wallet_self_transaction() {
    let height = require_regtest();
    let unspent = cli_json("listunspent", &["100", "9999999"], true);
    let coin = unspent
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["spendable"].as_bool() == Some(true) && u["safe"].as_bool() == Some(true))
        .expect("funded regtest wallet needs a mature spendable UTXO");
    let input_value = json::scaled_unsigned(&coin["amount"], 8).unwrap();
    let fee_sat = 1000u64;
    let output_value = input_value.checked_sub(fee_sat).unwrap();
    assert!(output_value >= 10000);
    let address = cli("getnewaddress", &["backend-live-smoke", "bech32"], true);
    let inputs = value!([{"txid":coin["txid"].as_str().unwrap(),"vout":json::unsigned(&coin["vout"]).unwrap()}]);
    let inputs = String::from_utf8(json::encode(&inputs).unwrap()).unwrap();
    let outputs = format!(
        "{{\"{address}\":{}.{:08}}}",
        output_value / 100_000_000,
        output_value % 100_000_000
    );
    let unsigned = cli("createrawtransaction", &[&inputs, &outputs], false);
    let signed = cli_json("signrawtransactionwithwallet", &[&unsigned], true);
    assert_eq!(signed["complete"].as_bool(), Some(true));
    let raw = hex_decode(signed["hex"].as_str().unwrap()).unwrap();
    let transaction = Transaction::decode(&raw).unwrap();
    assert_eq!(transaction.encode(), raw);
    assert!(transaction.inputs.iter().any(|i| !i.witness.is_empty()));
    assert_eq!(
        transaction.outputs.iter().map(|o| o.value_sat).sum::<u64>(),
        output_value
    );
    let decoded = cli_json("decoderawtransaction", &[&hex_encode(&raw)], false);
    let txid = transaction.txid().display_hex();
    assert_eq!(decoded["txid"].as_str(), Some(txid.as_str()));
    let candidate = String::from_utf8(json::encode(&value!([hex_encode(&raw)])).unwrap()).unwrap();
    let policy = cli_json("testmempoolaccept", &[&candidate], false);
    assert_eq!(policy[0]["allowed"].as_bool(), Some(true));
    backend().broadcast(&transaction).unwrap();
    let entry = cli_json("getmempoolentry", &[&txid], false);
    assert_eq!(
        json::scaled_unsigned(&entry["fees"]["base"], 8).unwrap(),
        fee_sat
    );
    assert_eq!(
        hex_decode(&cli("getrawtransaction", &[&txid, "false"], false)).unwrap(),
        raw
    );
    assert_eq!(require_regtest(), height);
    eprintln!(
        "Core31.1 accepted CoreRpc broadcast txid={txid}, fee_sat={fee_sat}, vsize={}, height unchanged={height}; Core wallet signing, not guardian multisig",
        json::unsigned(&entry["vsize"]).unwrap()
    );
}
