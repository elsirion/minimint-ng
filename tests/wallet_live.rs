//! Explicit, bounded local Core conformance for real Wallet 3-of-4 transactions.
//! Direct module inputs/outputs are test fixtures, not a client or Mint/core funding test.
//! Run only with exclusive ownership of the verified regtest node. Evidence is retained.
use minimint_ng::{
    bitcoin::{self, BitcoinBackend, Transaction, rpc::CoreRpc},
    codec::text::{hex_decode, hex_encode},
    config::{BitcoinNetwork, DescriptorKind, Fee, RawWalletConfig},
    crypto::{secp::SecretKey, sha256},
    daemon::options::read_secret,
    json,
    modules::wallet,
    protocol::{ModuleId, OutPoint, PeerId},
    storage::{Namespace, Store},
};
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
use std::{
    env, fs,
    io::Write,
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn configured(k: &str, v: &str) -> String {
    env::var(k).unwrap_or_else(|_| v.into())
}
fn cli_path() -> String {
    configured(
        "MINIMINT_BITCOIN_CLI",
        "/tmp/minimint-bitcoin-31.1/bitcoin-31.1/bin/bitcoin-cli",
    )
}
fn cli(method: &str, args: &[&str], wallet: bool) -> String {
    let mut c = Command::new("timeout");
    c.args(["--foreground", "--kill-after=1s", "15s"])
        .arg(configured(
            "MINIMINT_BITCOIN_LOADER",
            "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/ld-linux-x86-64.so.2",
        ))
        .arg(cli_path())
        .arg(format!(
            "-datadir={}",
            configured(
                "MINIMINT_BITCOIN_DATADIR",
                "/tmp/minimint-bitcoin-31.1/regtest-smoke"
            )
        ));
    if wallet {
        c.arg("-rpcwallet=interop");
    }
    let r = c.arg(method).args(args).output().unwrap();
    assert!(r.status.success(), "Core CLI method failed: {method}");
    assert!(r.stdout.len() < 16 * 1024 * 1024);
    String::from_utf8(r.stdout).unwrap().trim().into()
}
fn cj(m: &str, a: &[&str], w: bool) -> Value {
    let text = cli(m, a, w);
    // Verified Core CLI prints no bytes for the documented gettxout null result.
    // Do not generalize empty output to null for other methods.
    let text = if m == "gettxout" && text.is_empty() {
        "null"
    } else {
        &text
    };
    json::parse(text.as_bytes(), 16 * 1024 * 1024, 64).unwrap()
}
fn uint(v: &Value) -> u64 {
    json::unsigned(v).unwrap()
}
fn sat(v: &Value) -> u64 {
    json::scaled_unsigned(v, 8).unwrap()
}
fn persist(path: &Path, bytes: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
fn secret(n: u64) -> SecretKey {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    SecretKey::from_bytes(&b).unwrap()
}
fn guardian(p: u16) -> wallet::Wallet {
    wallet::Wallet::new(
        ModuleId(99),
        PeerId(p),
        RawWalletConfig {
            bitcoin_pks: (0..4)
                .map(|i| (PeerId(i), secret(u64::from(i) + 1).public_key()))
                .collect(),
            descriptor: DescriptorKind::Wsh,
            send_tx_vbytes: 228,
            receive_tx_vbytes: 316,
            feerate_base: 250,
            dust_limit: 10000,
            fee_consensus: Fee::wallet(100000, 0).unwrap(),
            network: BitcoinNetwork::Regtest,
        },
        secret(u64::from(p) + 1),
    )
    .unwrap()
}
fn vote(w: &wallet::Wallet, s: &Store, b: &CoreRpc, item: wallet::ConsensusItem) {
    for p in 0..3 {
        let req = w
            .required_scan(&s.snapshot().unwrap(), PeerId(p), &item)
            .unwrap();
        let batch = req.map(|r| wallet::prepare_scan(b, r).unwrap());
        let mut tx = s.transaction().unwrap();
        w.process_consensus(&mut tx, PeerId(p), &item, batch.as_ref())
            .unwrap();
        tx.commit().unwrap();
    }
}
fn scan(w: &wallet::Wallet, s: &Store, b: &CoreRpc) {
    let count = b.block_count().unwrap();
    let target = count.checked_sub(6).unwrap();
    while w.snapshot(&s.snapshot().unwrap()).unwrap().block_count < target {
        let item = w.block_proposal(&s.snapshot().unwrap(), count).unwrap();
        vote(w, s, b, item);
    }
}
struct Budget {
    fees: u64,
    deposits: u64,
    blocks: u64,
    dir: PathBuf,
    sequence: u64,
}
impl Budget {
    fn reserve(&mut self, fee: u64, deposit: u64, tx: &Transaction) {
        let fees = self.fees.checked_add(fee).unwrap();
        let deposits = self.deposits.checked_add(deposit).unwrap();
        assert!(fees <= 50000 && deposits <= 200000);
        self.fees = fees;
        self.deposits = deposits;
        self.sequence += 1;
        let record = format!(
            "txid={} fee_sat={fee} total_fee_sat={} deposit_sat={deposit} total_deposit_sat={}\n",
            tx.txid().display_hex(),
            self.fees,
            self.deposits
        );
        persist(
            &self.dir.join(format!("{}-reserved.txt", self.sequence)),
            record.as_bytes(),
        );
        persist(
            &self.dir.join(format!("{}-signed.hex", self.sequence)),
            hex_encode(&tx.encode()).as_bytes(),
        );
    }
    fn mine(&mut self, address: &str) -> Vec<String> {
        self.blocks += 7;
        assert!(self.blocks <= 21);
        persist(
            &self.dir.join(format!("mine-{}-intent.txt", self.blocks)),
            format!(
                "blocks=7 total_reserved_blocks={} address={address}\n",
                self.blocks
            )
            .as_bytes(),
        );
        let r = cj("generatetoaddress", &["7", address], false);
        persist(
            &self.dir.join(format!("mine-{}-response.json", self.blocks)),
            &json::encode(&r).unwrap(),
        );
        r.as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    }
}
fn fund(
    b: &CoreRpc,
    budget: &mut Budget,
    address: &str,
    script: &[u8],
    rate: u64,
) -> bitcoin::OutPoint {
    assert!(
        cj("getrawmempool", &[], false)
            .as_array()
            .unwrap()
            .is_empty()
    );
    let outputs = format!("{{\"{address}\":0.00100000}}");
    let raw = cli("createrawtransaction", &["[]", &outputs], false);
    // sat/kvB -> sat/vB exact decimal, no floating point and no guessed estimate.
    let options = format!(
        "{{\"fee_rate\":\"{}.{:03}\",\"minconf\":1,\"include_unsafe\":false}}",
        rate / 1000,
        rate % 1000
    );
    let funded = cj("fundrawtransaction", &[&raw, &options], true);
    let fee = sat(&funded["fee"]);
    assert!(budget.fees.checked_add(fee).unwrap() <= 50000);
    let signed = cj(
        "signrawtransactionwithwallet",
        &[funded["hex"].as_str().unwrap()],
        true,
    );
    assert_eq!(signed["complete"].as_bool(), Some(true));
    let tx = Transaction::decode(&hex_decode(signed["hex"].as_str().unwrap()).unwrap()).unwrap();
    let mut input = 0u64;
    for i in &tx.inputs {
        let coin = cj(
            "gettxout",
            &[
                &i.previous_output.txid.display_hex(),
                &i.previous_output.vout.to_string(),
                "true",
            ],
            false,
        );
        assert!(uint(&coin["confirmations"]) >= 1);
        input = input.checked_add(sat(&coin["value"])).unwrap();
    }
    assert_eq!(
        input - tx.outputs.iter().map(|o| o.value_sat).sum::<u64>(),
        fee
    );
    let outputs: Vec<_> = tx
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey == script)
        .collect();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].1.value_sat, 100000);
    let point = bitcoin::OutPoint {
        txid: tx.txid(),
        vout: outputs[0].0.try_into().unwrap(),
    };
    budget.reserve(fee, 100000, &tx); // Intent persists BEFORE broadcast. Failure is terminal; never fund again automatically.
    b.broadcast(&tx).unwrap();
    assert_eq!(
        cli("getrawtransaction", &[&tx.txid().display_hex()], false),
        hex_encode(&tx.encode())
    );
    point
}
fn claim(w: &wallet::Wallet, s: &Store, point: bitcoin::OutPoint, script: &[u8], marker: u8) {
    let view = w.snapshot(&s.snapshot().unwrap()).unwrap();
    let found: Vec<_> = view
        .output_info_slice(0, u64::MAX)
        .into_iter()
        .filter(|d| d.outpoint == Some(point))
        .collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].script, script);
    assert_eq!(found[0].value_sat, 100000);
    assert!(!found[0].spent);
    let fee = w.receive_fee(&s.snapshot().unwrap()).unwrap().unwrap();
    let mut tx = s.transaction().unwrap();
    w.input(
        &mut tx,
        &wallet::Input::V0 {
            output_index: found[0].index,
            claimant: secret(53843).public_key(),
            mining_fee_sat: fee,
        },
        OutPoint {
            txid: [marker; 32],
            out_idx: 0,
        },
    )
    .unwrap();
    tx.commit().unwrap();
}
fn signed(w: &wallet::Wallet, s: &Store) -> Transaction {
    for p in [0, 2, 3] {
        let items = guardian(p)
            .local_signatures(&s.snapshot().unwrap())
            .unwrap();
        assert_eq!(items.len(), 1);
        let mut tx = s.transaction().unwrap();
        w.process_consensus(&mut tx, PeerId(p), &items[0], None)
            .unwrap();
        tx.commit().unwrap();
    }
    let view = w.snapshot(&s.snapshot().unwrap()).unwrap();
    let txid = view.chain.last().unwrap().txid;
    s.snapshot()
        .unwrap()
        .scan_prefix(Namespace::Outbox, b"")
        .unwrap()
        .iter()
        .map(|(_, v)| Transaction::decode(v).unwrap())
        .find(|t| t.txid() == txid)
        .unwrap()
}
fn accepted(tx: &Transaction, dir: &Path, label: &str) -> bool {
    let arg = format!("[\"{}\"]", hex_encode(&tx.encode()));
    let r = cj("testmempoolaccept", &[&arg], false);
    persist(
        &dir.join(format!("{label}-testmempoolaccept.json")),
        &json::encode(&r).unwrap(),
    );
    persist(
        &dir.join(format!("{label}-tested.hex")),
        hex_encode(&tx.encode()).as_bytes(),
    );
    r[0]["allowed"].as_bool().unwrap()
}
fn check_core(tx: &Transaction, fee: u64, dir: &Path, label: &str) {
    let id = tx.txid().display_hex();
    let actual = cli("getrawtransaction", &[&id], false);
    persist(
        &dir.join(format!("{label}-core-raw.hex")),
        actual.as_bytes(),
    );
    assert_eq!(actual, hex_encode(&tx.encode()));
    let decoded = cj("decoderawtransaction", &[&hex_encode(&tx.encode())], false);
    persist(
        &dir.join(format!("{label}-core-decoded.json")),
        &json::encode(&decoded).unwrap(),
    );
    assert_eq!(decoded["txid"].as_str(), Some(id.as_str()));
    assert_eq!(
        decoded["hash"].as_str(),
        Some(tx.wtxid().display_hex().as_str())
    );
    assert_eq!(uint(&decoded["weight"]), tx.weight());
    assert_eq!(uint(&decoded["vsize"]), (tx.weight() + 3) / 4);
    let entry = cj("getmempoolentry", &[&id], false);
    persist(
        &dir.join(format!("{label}-core-mempool.json")),
        &json::encode(&entry).unwrap(),
    );
    assert_eq!(sat(&entry["fees"]["base"]), fee);
}
fn live(dir: PathBuf) {
    assert_eq!(
        hex_encode(&sha256(&fs::read(cli_path()).unwrap())),
        "4e3a0fde23ec768a61cdd193602be937b29b6e8f21bcb614af87a2786bf86034"
    );
    assert_eq!(
        hex_encode(&sha256(
            &fs::read(configured(
                "MINIMINT_BITCOIND",
                "/tmp/minimint-bitcoin-31.1/bitcoin-31.1/bin/bitcoind"
            ))
            .unwrap()
        )),
        "986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08"
    );
    assert_eq!(uint(&cj("getnetworkinfo", &[], false)["version"]), 310100);
    let chain = cj("getblockchaininfo", &[], false);
    assert_eq!(chain["chain"].as_str(), Some("regtest"));
    assert_eq!(chain["initialblockdownload"].as_bool(), Some(false));
    let height = uint(&chain["blocks"]);
    let cookie = read_secret(Path::new(&configured(
        "MINIMINT_BITCOIN_COOKIE",
        "/tmp/minimint-bitcoin-31.1/regtest-smoke/regtest/.cookie",
    )))
    .unwrap();
    let b = CoreRpc::new(
        configured("MINIMINT_BITCOIN_RPC", "127.0.0.1:42257")
            .parse()
            .unwrap(),
        &cookie,
        Duration::from_secs(5),
        6,
    )
    .unwrap();
    assert_eq!(b.block_count().unwrap(), height + 1);
    let tip = cli("getblockhash", &[&height.to_string()], false);
    assert_eq!(
        bitcoin::Txid(b.block_hash(height).unwrap()).display_hex(),
        tip
    );
    let rate = b
        .fee_rate()
        .unwrap()
        .expect("genuine conservative estimate required");
    assert_eq!(
        rate,
        sat(&cj("estimatesmartfee", &["6", "CONSERVATIVE"], false)["feerate"])
    );
    assert!(rate > 0);
    persist(
        &dir.join("start-chain.json"),
        &json::encode(&chain).unwrap(),
    );
    let metadata = format!(
        "scope=direct Wallet module/Core conformance; no Mint or core transaction authorization claim\ntest_executable_sha256={}\nbitcoin_cli_sha256={}\nbitcoind_sha256={}\nstart_height={height}\nstart_tip={tip}\nconservative_estimate_sat_per_kvb={rate}\nfunding_cap_sat=200000\nwithdrawal_sat=50000\nactual_bitcoin_fee_cap_sat=50000\nmining_cap_blocks=21\ndeadline_seconds=300\n",
        hex_encode(&sha256(&fs::read(env::current_exe().unwrap()).unwrap())),
        hex_encode(&sha256(&fs::read(cli_path()).unwrap())),
        hex_encode(&sha256(
            &fs::read(configured(
                "MINIMINT_BITCOIND",
                "/tmp/minimint-bitcoin-31.1/bitcoin-31.1/bin/bitcoind"
            ))
            .unwrap()
        ))
    );
    persist(&dir.join("artifact-metadata.txt"), metadata.as_bytes());
    let s = Store::open(dir.join("store")).unwrap();
    let w = guardian(0);
    vote(&w, &s, &b, wallet::Wallet::fee_proposal(Some(rate)));
    let script = w.deposit_script(&secret(53843).public_key()).unwrap();
    assert!(w.matches_filter(&script));
    let decoded = cj("decodescript", &[&hex_encode(&script)], false);
    let address = decoded["address"].as_str().unwrap();
    let validated = cj("validateaddress", &[address], false);
    assert_eq!(
        validated["scriptPubKey"].as_str(),
        Some(hex_encode(&script).as_str())
    );
    let own = cli("getnewaddress", &["wallet-live", "bech32"], true);
    let own_info = cj("getaddressinfo", &[&own], true);
    assert_eq!(own_info["ismine"].as_bool(), Some(true));
    let destination_script = hex_decode(own_info["scriptPubKey"].as_str().unwrap()).unwrap();
    assert_eq!(&destination_script[..2], &[0, 20]);
    assert_eq!(destination_script.len(), 22);
    let mut budget = Budget {
        fees: 0,
        deposits: 0,
        blocks: 0,
        dir: dir.clone(),
        sequence: 0,
    };
    let first = fund(&b, &mut budget, address, &script, rate);
    let mined = budget.mine(&own);
    assert!(
        cj("getblock", &[&mined[0], "1"], false)["tx"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(first.txid.display_hex().as_str()))
    );
    scan(&w, &s, &b);
    claim(&w, &s, first, &script, 1);
    assert_eq!(
        w.snapshot(&s.snapshot().unwrap())
            .unwrap()
            .wallet
            .unwrap()
            .value_sat,
        100000
    );
    let second = fund(&b, &mut budget, address, &script, rate);
    let mined = budget.mine(&own);
    assert!(
        cj("getblock", &[&mined[0], "1"], false)["tx"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(second.txid.display_hex().as_str()))
    );
    scan(&w, &s, &b);
    claim(&w, &s, second, &script, 2);
    let consolidation = signed(&w, &s);
    assert_eq!(consolidation.inputs.len(), 2);
    for input in &consolidation.inputs {
        assert_eq!(input.witness.len(), 5);
        assert!(input.witness[0].is_empty());
    }
    let consolidation_fee = 200000
        - consolidation
            .outputs
            .iter()
            .map(|o| o.value_sat)
            .sum::<u64>();
    assert_eq!(
        consolidation_fee,
        w.receive_fee(&s.snapshot().unwrap()).unwrap().unwrap()
    );
    assert!(accepted(&consolidation, &dir, "consolidation"));
    let mut bad = consolidation.clone();
    bad.inputs[0].witness[1] = vec![0];
    assert!(!accepted(&bad, &dir, "bad-witness"));
    assert!(
        cj("getrawmempool", &[], false)
            .as_array()
            .unwrap()
            .is_empty()
    );
    budget.reserve(consolidation_fee, 0, &consolidation);
    w.broadcast_pending(&s, &b).unwrap();
    check_core(&consolidation, consolidation_fee, &dir, "consolidation");
    let fee = w.send_fee(&s.snapshot().unwrap()).unwrap().unwrap();
    let output_point = OutPoint {
        txid: [3; 32],
        out_idx: 0,
    };
    let mut tx = s.transaction().unwrap();
    w.output(
        &mut tx,
        &wallet::Output::V0 {
            destination: wallet::Destination::P2wpkh(destination_script[2..].try_into().unwrap()),
            value_sat: 50000,
            mining_fee_sat: fee,
        },
        output_point,
    )
    .unwrap();
    tx.commit().unwrap();
    let withdrawal = signed(&w, &s);
    assert_eq!(withdrawal.inputs.len(), 1);
    assert_eq!(
        withdrawal.inputs[0].previous_output.txid,
        consolidation.txid()
    );
    assert_eq!(
        withdrawal
            .outputs
            .iter()
            .filter(|o| o.script_pubkey == destination_script && o.value_sat == 50000)
            .count(),
        1
    );
    let withdrawal_fee = consolidation.outputs[0].value_sat
        - withdrawal.outputs.iter().map(|o| o.value_sat).sum::<u64>();
    assert_eq!(withdrawal_fee, fee);
    assert!(accepted(&withdrawal, &dir, "withdrawal"));
    budget.reserve(fee, 0, &withdrawal);
    w.broadcast_pending(&s, &b).unwrap();
    check_core(&withdrawal, fee, &dir, "withdrawal");
    let before = w.snapshot(&s.snapshot().unwrap()).unwrap();
    assert_eq!(before.chain.len(), 2);
    assert_eq!(before.pending_chain.len(), 2);
    assert_eq!(before.transaction_id(output_point), Some(withdrawal.txid()));
    let assets = w.audit(&s.transaction().unwrap()).unwrap();
    let mined = budget.mine(&own);
    let block = cj("getblock", &[&mined[0], "1"], false);
    persist(
        &dir.join("confirmation-block.json"),
        &json::encode(&block).unwrap(),
    );
    for transaction in [&consolidation, &withdrawal] {
        assert!(
            block["tx"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(transaction.txid().display_hex().as_str()))
        );
    }
    scan(&w, &s, &b);
    let after = w.snapshot(&s.snapshot().unwrap()).unwrap();
    assert!(after.pending_chain.is_empty());
    assert_eq!(after.chain, before.chain);
    assert_eq!(after.wallet, before.wallet);
    assert!(
        s.snapshot()
            .unwrap()
            .scan_prefix(Namespace::Outbox, b"")
            .unwrap()
            .is_empty()
    );
    assert_eq!(w.audit(&s.transaction().unwrap()).unwrap(), assets);
    for point in [first, second] {
        let spent = cj(
            "gettxout",
            &[&point.txid.display_hex(), &point.vout.to_string()],
            false,
        );
        persist(
            &dir.join(format!(
                "spent-{}-{}.json",
                point.txid.display_hex(),
                point.vout
            )),
            &json::encode(&spent).unwrap(),
        );
        assert!(spent.is_null());
    }
    let remaining = after.wallet.unwrap();
    assert_eq!(
        remaining.value_sat,
        200000 - consolidation_fee - 50000 - withdrawal_fee
    );
    let coin = cj(
        "gettxout",
        &[
            &remaining.outpoint.txid.display_hex(),
            &remaining.outpoint.vout.to_string(),
        ],
        false,
    );
    persist(
        &dir.join("final-wallet-gettxout.json"),
        &json::encode(&coin).unwrap(),
    );
    assert_eq!(sat(&coin["value"]), remaining.value_sat);
    assert!(uint(&coin["confirmations"]) >= 7);
    let destination_vout = withdrawal
        .outputs
        .iter()
        .position(|o| o.script_pubkey == destination_script && o.value_sat == 50000)
        .unwrap();
    let destination_coin = cj(
        "gettxout",
        &[
            &withdrawal.txid().display_hex(),
            &destination_vout.to_string(),
        ],
        false,
    );
    persist(
        &dir.join("final-destination-gettxout.json"),
        &json::encode(&destination_coin).unwrap(),
    );
    assert_eq!(sat(&destination_coin["value"]), 50000);
    assert!(uint(&destination_coin["confirmations"]) >= 7);
    assert_eq!(
        uint(&cj("getblockchaininfo", &[], false)["blocks"]),
        height + 21
    );
    let result = format!(
        "passed\nconsolidation={}\nwithdrawal={}\nactual_fee_sat={}\nfunded_sat={}\nmined_blocks={}\nfinal_wallet_sat={}\n",
        consolidation.txid().display_hex(),
        withdrawal.txid().display_hex(),
        budget.fees,
        budget.deposits,
        budget.blocks,
        remaining.value_sat
    );
    persist(&dir.join("result.txt"), result.as_bytes());
    eprintln!("{result}");
}
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", self.0.id())])
            .status();
        let _ = self.0.wait();
    }
}
// Deliberately independent of TMPDIR: nix-shell removes its temporary root on exit.
fn evidence_root(configured: Option<&std::ffi::OsStr>) -> std::io::Result<PathBuf> {
    let root = configured
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    if !root.is_absolute() || !root.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "evidence root must be an existing absolute directory",
        ));
    }
    Ok(root)
}
#[test]
#[ignore = "explicitly mutates exclusively owned verified regtest Core; 200000 sat funding, 50000 sat fee cap, 21 blocks"]
fn wallet_live_accepts_threshold_consolidation_and_withdrawal() {
    let root = evidence_root(env::var_os("MINIMINT_WALLET_LIVE_EVIDENCE_ROOT").as_deref()).unwrap();
    let dir = root.join(format!(
        "minimint-wallet-live-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    eprintln!("public evidence: {}", dir.display());
    let child = Command::new(env::current_exe().unwrap())
        .args(["--exact", "wallet_live_child", "--ignored", "--nocapture"])
        .env("MINIMINT_WALLET_LIVE_CHILD", &dir)
        .process_group(0)
        .spawn()
        .unwrap();
    let mut owned = Owned(child);
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if let Some(status) = owned.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "live child failed; inspect retained public evidence"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "live child exceeded 300 second deadline"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
#[test]
#[ignore = "private subprocess entry; parent owns deadline and process group"]
fn wallet_live_child() {
    if let Some(dir) = env::var_os("MINIMINT_WALLET_LIVE_CHILD") {
        live(PathBuf::from(dir));
    }
}

#[path = "fixtures/storage/mod.rs"]
mod fixture;
#[test]
fn evidence_root_is_persistent_and_requires_explicit_absolute_directory() {
    assert_eq!(evidence_root(None).unwrap(), PathBuf::from("/tmp"));
    assert!(evidence_root(Some(std::ffi::OsStr::new("relative"))).is_err());
    let directory = fixture::TestDir::new();
    assert_eq!(
        evidence_root(Some(directory.path().as_os_str())).unwrap(),
        directory.path()
    );
    assert!(evidence_root(Some(directory.path().join("missing").as_os_str())).is_err());
    let file = directory.path().join("file");
    persist(&file, b"not a directory");
    assert!(evidence_root(Some(file.as_os_str())).is_err());
}
#[test]
fn reservation_caps_fail_before_new_intent_and_signed_bytes() {
    let dir = fixture::TestDir::new();
    let mut budget = Budget {
        fees: 0,
        deposits: 0,
        blocks: 0,
        dir: dir.path().into(),
        sequence: 0,
    };
    let tx = Transaction {
        version: 2,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    budget.reserve(50000, 200000, &tx);
    assert_eq!(
        fs::read_to_string(dir.path().join("1-signed.hex")).unwrap(),
        hex_encode(&tx.encode())
    );
    for (fee, deposit) in [(1, 0), (0, 1), (u64::MAX, 0)] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || budget.reserve(fee, deposit, &tx)
            ))
            .is_err()
        );
        assert_eq!(
            (budget.fees, budget.deposits, budget.sequence),
            (50000, 200000, 1)
        );
        assert!(!dir.path().join("2-reserved.txt").exists());
        assert!(!dir.path().join("2-signed.hex").exists());
    }
}
