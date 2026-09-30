#!/usr/bin/env python3
"""Exact-artifact black-box interop driver; no client implementation.

Initially performs diagnostics only, then waits for reviewed control in the
private handoff directory. Run --self-test without a federation for local checks.
"""
import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

REVISION = "0c316439d60b5a08eea26fab216780eb893c45bf"
CLIENT = Path("/tmp/minimint-upstream-build.2Clk9R/checkout/target-nix/release/fedimint-cli")
CLIENT_SHA = "4c93df5a0cd6633ac7add340d7089b712b14b6a48655df89f9bfbb8a2d7eed23"
CORE = Path("/tmp/minimint-bitcoin-31.1/bitcoin-31.1/bin/bitcoin-cli")
CORE_SHA = "4e3a0fde23ec768a61cdd193602be937b29b6e8f21bcb614af87a2786bf86034"
LOADER = "/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84/lib/ld-linux-x86-64.so.2"
MAX_OUTPUT = 16 * 1024 * 1024


class DriverError(Exception):
    """Contains only a fixed diagnostic identifier, never command arguments."""


def require(condition, code):
    if not condition:
        raise DriverError(code)


def read_json(path):
    require(path.stat().st_size <= MAX_OUTPUT, "json-size-limit")
    return json.loads(path.read_bytes(), parse_float=Decimal)


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "w", encoding="utf8") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, default=str)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def shape(value):
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return {"type": "array", "length": len(value), "first": shape(value[0]) if value else None}
    if isinstance(value, Decimal):
        return "exact-decimal"
    return type(value).__name__


def verify_artifact(path, digest):
    require(path.is_file(), "artifact-missing")
    with open(path, "rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    require(actual == digest, "artifact-digest-mismatch")


def btc_satoshis(value):
    scaled = Decimal(str(value)) * 100_000_000
    require(scaled.is_finite() and scaled >= 0 and scaled == scaled.to_integral_value(), "invalid-btc-amount")
    require(scaled <= 0xffffffffffffffff, "btc-amount-overflow")
    return int(scaled)


def source_snapshot(root, source, reviewed=None):
    """Copy one read of reviewed bytes, then execute only the verified copy."""
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if reviewed is not None:
        require(digest == reviewed, "resume-script-digest")
    directory = root / "driver-sources"
    directory.mkdir(mode=0o700, exist_ok=True)
    require(stat.S_ISDIR(directory.lstat().st_mode) and directory.stat().st_mode & 0o077 == 0, "snapshot-directory-permissions")
    target = directory / (digest + ".py")
    try:
        with open(target, "xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(target, 0o400)
    except FileExistsError:
        require(stat.S_ISREG(target.lstat().st_mode) and stat.S_IMODE(target.stat().st_mode) == 0o400, "snapshot-file-permissions")
        require(target.read_bytes() == data, "snapshot-bytes-mismatch")
    verify_artifact(target, digest)
    return target, digest


def survivors_enabled():
    value = os.environ.get("MINIMINT_MIXED_MONETARY_SURVIVORS")
    require(value in (None, "0", "1"), "survivor-mode-option")
    return value == "1"


def write_initial_manifest(root, entry_script, digest, deadline, federation_id):
    manifest = root / "driver-initial-manifest.json"
    with open(manifest, "x", encoding="utf8") as output:
        json.dump({"schema": 1, "deadline_monotonic": deadline,
            "initial_script_sha256": digest, "entry_script": str(entry_script),
            "monetary_survivors": survivors_enabled(),
            "federation_id": federation_id,
            "linux_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}, output)
        output.flush()
        os.fsync(output.fileno())
    os.chmod(manifest, 0o400)



def exported_note_summary(token, federation_id, correlation=None):
    # Test-only amount inspection. This does not verify note signatures.
    require(isinstance(token, str) and token.startswith("fedimint") and len(token) <= 65536, "export-token-format")
    alphabet = "0123456789abcdefghijklmnopqrstuv"
    data, accumulator, bits = bytearray(), 0, 0
    for character in token[8:]:
        require(character in alphabet, "export-token-alphabet")
        accumulator |= alphabet.index(character) << bits
        bits += 5
        while bits >= 8:
            data.append(accumulator & 255)
            accumulator >>= 8
            bits -= 8
    reader = ConfigReader(bytes(data))
    fields = reader.integer()
    require(2 <= fields <= 256, "export-token-field-count")
    total, count = 0, 0
    for index in range(fields):
        tag = reader.integer()
        payload = reader.take(reader.integer())
        if index == 0:
            require(tag == 0 and payload.hex() == federation_id, "export-token-federation")
        else:
            require(tag == 1 and len(payload) == 81 and payload[0] <= 41, "export-token-note")
            total += 1 << payload[0]
            count += 1
            if correlation is not None:
                correlation.append({"denomination": payload[0],
                    "signature_sha256": hashlib.sha256(payload[33:]).hexdigest()})
    reader.end()
    return total, count


class ConfigReader:
    """Bounded test-only reader for the numbered public configuration fields."""
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        require(0 <= size <= len(self.data) - self.offset, "config-truncated")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def integer(self):
        first = self.take(1)[0]
        if first < 253:
            return first
        size = {253: 2, 254: 4, 255: 8}[first]
        value = int.from_bytes(self.take(size), "big")
        require(value >= {253: 253, 254: 65536, 255: 4294967296}[first], "config-noncanonical")
        return value

    def end(self):
        require(self.offset == len(self.data), "config-trailing")


def configured_fees(config):
    modules = config["modules"]
    def payload(module, kind):
        require(modules[str(module)]["kind"] == kind, "config-module-kind")
        outer = ConfigReader(bytes.fromhex(modules[str(module)]["config"]))
        require(outer.integer() == module, "config-module-id")
        inner = ConfigReader(outer.take(outer.integer()))
        outer.end()
        return inner
    mint = payload(0, "mintv2")
    require(mint.integer() == 42, "config-denominations")
    for denomination in range(42):
        require(mint.take(1)[0] == denomination, "config-denomination-order")
        mint.take(96)
    require(mint.integer() == 42, "config-share-denominations")
    for denomination in range(42):
        require(mint.take(1)[0] == denomination and mint.integer() == 4, "config-share-map")
        for peer in range(4):
            require(mint.integer() == peer, "config-peer-order")
            mint.take(96)
    mint_fee = (mint.integer(), mint.integer())
    require(mint.integer() == 0, "config-amount-unit")
    mint.end()
    wallet = payload(1, "walletv2")
    require(wallet.integer() == 4, "config-wallet-peers")
    for peer in range(4):
        require(wallet.integer() == peer, "config-wallet-peer-order")
        wallet.take(33)
    require(wallet.integer() == 0 and wallet.integer() == 0, "config-descriptor")
    for _ in range(4):
        wallet.integer()
    wallet_fee = (wallet.integer(), wallet.integer())
    # Bitcoin network is the fixed four-byte magic from ENC-013.
    require(wallet.take(4) == bytes.fromhex("fabfb5da"), "config-regtest")
    wallet.end()
    return mint_fee, wallet_fee


def note_totals(counts):
    require(isinstance(counts, dict), "mint-count-shape")
    total = number = 0
    for key, count in counts.items():
        require(isinstance(key, str) and key.isascii() and key.isdecimal(), "mint-denomination")
        denomination = int(key)
        require(str(denomination) == key and 0 <= denomination <= 41, "mint-denomination")
        require(type(count) is int and 0 <= count <= 0xffffffffffffffff, "mint-count")
        total += count * (1 << denomination)
        number += count
    require(total <= 0x7fffffffffffffff, "mint-liability-domain")
    return total, number


def validate_withdrawal_child(child, record):
    require(len(child["vin"]) == 1 and len(child["vout"]) == 2, "withdrawal-child-structure")
    txin = child["vin"][0]
    require(txin["txid"] == record["parent_txid"] and txin["vout"] == 0, "withdrawal-pending-parent")
    change, destination = child["vout"]
    change_value, destination_value = btc_satoshis(change["value"]), btc_satoshis(destination["value"])
    require(change["n"] == 0 and destination["n"] == 1, "withdrawal-output-order")
    require(destination_value == record["amount_sat"] and destination["scriptPubKey"]["hex"] == record["destination_script"], "withdrawal-destination-mismatch")
    script = change["scriptPubKey"]["hex"]
    require(isinstance(script, str) and script.startswith("0020") and len(script) == 68, "withdrawal-change-p2wsh")
    require(change_value >= 10_000 and destination_value >= 10_000, "withdrawal-dust")
    require(record["parent_value_sat"] - change_value - destination_value == record["fee_sat"], "withdrawal-exact-fee")


class Driver:
    def __init__(self, directory, resume=False, original_deadline=None, snapshot_sha=None, entry_script=None):
        self.survivors = survivors_enabled()
        self.root = Path(directory).resolve()
        mode = self.root.stat().st_mode
        require(stat.S_ISDIR(mode) and mode & 0o077 == 0, "handoff-directory-permissions")
        path = self.root / "handoff.json"
        mode = path.stat().st_mode
        require(stat.S_ISREG(mode) and mode & 0o077 == 0, "handoff-file-permissions")
        self.handoff = read_json(path)
        require(self.handoff.get("schema") == 1, "handoff-schema")
        require(len(self.handoff["api_urls"]) == 4, "guardian-count")
        require(len(self.handoff["invite_codes"]) >= 1, "invite-missing")
        for name in ("progress_path", "result_path"):
            require(Path(self.handoff[name]).resolve().parent == self.root, "output-path-outside-handoff")
        seconds = int(os.environ.get("MINIMINT_MIXED_DRIVER_TIMEOUT_SECS", "1200"))
        require(1 <= seconds <= 3600, "driver-deadline")
        require(not self.survivors or seconds == 3600, "survivor-original-deadline")
        self.script = Path(entry_script or __file__).resolve()
        executed = Path(__file__).resolve()
        self.script_digest = hashlib.sha256(executed.read_bytes()).hexdigest()
        manifest = self.root / "driver-initial-manifest.json"
        if resume or snapshot_sha is not None:
            initial = read_json(manifest)
            require(initial.get("monetary_survivors", False) == self.survivors, "resume-survivor-mode")
            require(initial["linux_boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "resume-boot-mismatch")
            self.end = float(initial["deadline_monotonic"])
            require(original_deadline == self.end, "resume-deadline-mismatch")
            require(self.end > time.monotonic(), "driver-deadline")
            require(initial["federation_id"] == self.handoff["federation_id"], "resume-federation-mismatch")
            require(Path(initial["entry_script"]) == self.script, "resume-entry-script-mismatch")
            if snapshot_sha is not None:
                require(self.script_digest == snapshot_sha, "executed-snapshot-digest")
                require(executed == self.root / "driver-sources" / (snapshot_sha + ".py"), "executed-snapshot-path")
                require(stat.S_IMODE(executed.stat().st_mode) == 0o400, "executed-snapshot-permissions")
        else:
            self.end = time.monotonic() + seconds
            write_initial_manifest(self.root, self.script, self.script_digest, self.end, self.handoff["federation_id"])
        self.outputs = self.root / "driver-private"
        if not resume:
            self.outputs.mkdir(mode=0o700)
        self.checks = []
        self.observations = {}
        self.sequence = 0
        self.script_digests = [self.script_digest]
        self.phase = "diagnostics"
        self.finance = {"funded_sat": 0, "core_fee_sat": 0, "deposits": []}
        if resume:
            state = read_json(self.root / "driver-state.json")
            self.checks = state["checks"]
            self.observations = state["observations"]
            self.sequence = state["sequence"]
            self.script_digests = state["script_digests"] + [self.script_digest]
            self.phase = state.get("phase", "diagnostics_ready")
            self.finance = state.get("finance", self.finance)
        self.client_dirs = {name: self.outputs / ("client-" + name) for name in ("a", "b")}
        self.progress("starting")

    def remaining(self):
        remaining = self.end - time.monotonic()
        require(remaining > 0, "driver-deadline")
        return remaining

    def progress(self, stage, **extra):
        atomic_json(Path(self.handoff["progress_path"]), {
            "schema": 1, "stage": stage, "checks": self.checks,
            "observations": self.observations, "script_sha256": self.script_digests,
            "script_snapshots": [{"sha256": digest, "path": str(self.root / "driver-sources" / (digest + ".py"))}
                for digest in self.script_digests], **extra,
        })

    def command(self, label, args, limit=90):
        self.sequence += 1
        # Reserve output names before launching; an interrupted await must not
        # collide with or overwrite its partial stdout/stderr on a later retry.
        self.save_state()
        prefix = self.outputs / f"{self.sequence:03d}-{label}"
        stdout_path = prefix.with_suffix(".stdout")
        stderr_path = prefix.with_suffix(".stderr")
        deadline = min(time.monotonic() + min(limit, self.remaining()),
            getattr(self, "stage_deadline", float("inf")))
        require(deadline > time.monotonic(), "stage-deadline")
        with open(stdout_path, "xb") as output, open(stderr_path, "xb") as errors:
            os.chmod(stdout_path, 0o600)
            os.chmod(stderr_path, 0o600)
            # Inherit the harness-owned process group. No session or daemon fork.
            process = subprocess.Popen(args, stdout=output, stderr=errors)
            try:
                while process.poll() is None:
                    require(time.monotonic() < deadline, "command-timeout-" + label)
                    require(stdout_path.stat().st_size <= MAX_OUTPUT, "stdout-limit-" + label)
                    require(stderr_path.stat().st_size <= MAX_OUTPUT, "stderr-limit-" + label)
                    time.sleep(0.05)
                require(process.returncode == 0, "command-failed-" + label)
                require(time.monotonic() < deadline, "command-timeout-" + label)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        require(stdout_path.stat().st_size <= MAX_OUTPUT, "stdout-limit-" + label)
        require(stderr_path.stat().st_size <= MAX_OUTPUT, "stderr-limit-" + label)
        raw = stdout_path.read_bytes()
        try:
            value = json.loads(raw, parse_float=Decimal)
            result_shape = shape(value)
        except (ValueError, UnicodeError):
            value = None
            result_shape = "non-json-output"
        self.observations[label] = {"stdout_path": str(stdout_path), "stderr_path": str(stderr_path), "shape": result_shape}
        return value, raw

    def cli(self, client, label, *args, limit=90):
        return self.command(label, [str(CLIENT), "--data-dir", str(self.client_dirs[client]), *args], limit)

    def core(self, label, *args):
        datadir = os.environ.get("MINIMINT_DRIVER_CORE_DATADIR", "/tmp/minimint-bitcoin-31.1/regtest-smoke")
        return self.command(label, [LOADER, str(CORE), "-regtest", "-datadir=" + datadir, "-rpcclienttimeout=10", *args], 15)

    def core_value(self, label, method, *args, wallet=False):
        parameters = [arg if isinstance(arg, str) else json.dumps(arg) for arg in args]
        prefix = ["-rpcwallet=interop"] if wallet else []
        value, raw = self.core(label, *prefix, method, *parameters)
        if method in ("getnewaddress", "createrawtransaction", "sendrawtransaction"):
            value = raw.decode("ascii").strip()
            require(bool(value) and not any(c.isspace() for c in value), "core-string-shape")
        return value

    def prior(self, name):
        return read_json(Path(self.observations[name]["stdout_path"]))

    def save_state(self):
        atomic_json(self.root / "driver-state.json", {"checks": self.checks,
            "observations": self.observations, "sequence": self.sequence,
            "script_digests": self.script_digests, "phase": self.phase,
            "finance": self.finance})

    def reserve_mining(self, blocks):
        previous = self.finance.get("mined_blocks_reserved", 0)
        cap = 49 if getattr(self, "survivors", False) else 21
        require(type(previous) is int and 0 <= previous <= cap, "mining-budget-state")
        require(type(blocks) is int and 0 < blocks <= cap - previous, "mining-budget")
        self.finance["mined_blocks_reserved"] = previous + blocks
        self.save_state()

    def first_accounting(self):
        require(self.phase == "first_deposit_observed", "first-accounting-phase")
        require(self.prior("a-first-await-receive") == ["Success", 2], "first-receipt-schema")
        deposits = self.finance["deposits"]
        require(len(deposits) == 1 and deposits[0]["amount_sat"] == 100_000, "first-deposit-ledger")
        require(self.prior("a-first-wallet-value") == 100_000, "first-wallet-satoshi-unit")
        require(self.prior("a-first-pending-chain") == [], "first-deposit-created-chain")
        notes = self.prior("a-first-mint-count")
        liability, count = note_totals(notes)
        mint_fee, wallet_fee = configured_fees(self.handoff["client_config"])
        # This bounded stage requires the actual configured flat-fee profile;
        # it does not infer an accepted mining fee from a prior quote.
        require(mint_fee[1] == 0 and wallet_fee[1] == 0, "accounting-relative-fee-profile")
        module_fees = count * mint_fee[0] + wallet_fee[0]
        assets = 100_000_000
        residual = assets - liability - module_fees
        require(liability > 0 and residual >= 0, "first-accounting-balance")
        quote = self.prior("a-receive-fee")
        require(type(quote) is int and quote >= 0, "first-receive-quote")
        accounting = {"wallet_assets_msat": assets, "mint_liabilities_msat": liability,
            "note_count": count, "configured_module_fees_msat": module_fees,
            "audit_net_msat": assets - liability,
            "supplied_mining_fee_times_1000_plus_core_excess_msat": residual,
            "prior_receive_quote_sat": quote,
            "excess_if_supplied_fee_equals_prior_quote_msat": residual - quote * 1000,
            "accepted_mining_fee_verified": False}
        self.finance["first_accounting"] = accounting
        if "mined_blocks_reserved" not in self.finance:
            blocks = self.prior("deposit-mine")
            require(isinstance(blocks, list) and len(blocks) == 7, "prior-mining-evidence")
            self.finance["mined_blocks_reserved"] = 7
        self.save_state()
        self.progress("first_accounting_checked", accounting=accounting, monetary_workflow=False)

    def first_deposit(self):
        require(self.phase == "diagnostics_ready", "deposit-phase")
        verify_artifact(CLIENT, CLIENT_SHA)
        verify_artifact(CORE, CORE_SHA)
        address = self.prior("a-deposit-address")
        cursor = self.prior("a-cursor-before-address")
        require(isinstance(address, str), "deposit-address-shape")
        require(type(cursor) is int and cursor >= 0, "event-cursor-shape")
        require(self.prior("a-mint-count") == {} and self.prior("b-mint-count") == {}, "initial-mint-balance")
        require(self.prior("a-info-total-value") == 0, "initial-wallet-balance")
        decoded_address = self.core_value("deposit-validate-address", "validateaddress", address)
        require(decoded_address["isvalid"] and decoded_address.get("iswitness") is True
            and decoded_address.get("witness_version") == 0
            and len(decoded_address.get("witness_program", "")) == 64, "deposit-not-p2wsh")
        require(self.core_value("deposit-initial-mempool", "getrawmempool") == [], "unexpected-initial-mempool")
        estimate = self.core_value("deposit-core-fee", "estimatesmartfee", 6, "CONSERVATIVE")
        require(isinstance(estimate, dict) and "feerate" in estimate, "deposit-no-genuine-estimate")
        sat_per_kvb = btc_satoshis(estimate["feerate"])
        require(sat_per_kvb > 0, "deposit-zero-estimate")
        amount_sat = 100_000
        require(self.finance["funded_sat"] + amount_sat <= 1_000_000, "deposit-budget")
        self.progress("preparing-first-deposit")
        raw = self.core_value("deposit-create", "createrawtransaction", [], {address: "0.00100000"})
        funded = self.core_value("deposit-fund", "fundrawtransaction", raw,
            {"minconf": 1, "include_unsafe": False, "fee_rate": str(Decimal(sat_per_kvb) / 1000)}, wallet=True)
        fee_sat = btc_satoshis(funded["fee"])
        require(self.finance["core_fee_sat"] + fee_sat <= 100_000, "bitcoin-fee-budget")
        signed = self.core_value("deposit-sign", "signrawtransactionwithwallet", funded["hex"], wallet=True)
        require(signed.get("complete") is True, "deposit-signing-incomplete")
        decoded = self.core_value("deposit-decode", "decoderawtransaction", signed["hex"])
        input_total = 0
        for index, txin in enumerate(decoded["vin"]):
            utxo = self.core_value("deposit-input-" + str(index), "gettxout", txin["txid"], txin["vout"], True)
            require(isinstance(utxo, dict) and utxo.get("confirmations", 0) >= 1, "deposit-input-not-confirmed")
            input_total += btc_satoshis(utxo["value"])
        require(input_total - sum(btc_satoshis(v["value"]) for v in decoded["vout"]) == fee_sat, "deposit-fee-crosscheck")
        matching = [v for v in decoded["vout"] if v["scriptPubKey"]["hex"] == decoded_address["scriptPubKey"]]
        require(len(matching) == 1 and btc_satoshis(matching[0]["value"]) == amount_sat, "deposit-output-crosscheck")
        # Reserve before broadcast. Never repeat a possibly accepted broadcast
        # after an ambiguous timeout or recreate this stage after a restart.
        self.finance["funded_sat"] += amount_sat
        self.finance["core_fee_sat"] += fee_sat
        self.finance["deposits"].append({"txid": decoded["txid"], "vout": matching[0]["n"], "amount_sat": amount_sat, "bitcoin_fee_sat": fee_sat})
        self.phase = "first_deposit_reserved"
        self.save_state()
        txid = self.core_value("deposit-broadcast", "sendrawtransaction", signed["hex"])
        require(txid == decoded["txid"], "deposit-broadcast-txid")
        entry = self.core_value("deposit-mempool-entry", "getmempoolentry", txid)
        require(btc_satoshis(entry["fees"]["base"]) == fee_sat, "deposit-mempool-fee")
        require(self.core_value("deposit-mempool", "getrawmempool") == [txid], "unexpected-deposit-mempool")
        mining_address = self.core_value("deposit-mining-address", "getnewaddress", "mixed-driver-mining", "bech32", wallet=True)
        before = self.core_value("deposit-height-before", "getblockcount")
        # backend count is height+1; count-6 must exceed the deposit's height.
        # Seven real blocks include the deposit and provide its six-block delay.
        self.reserve_mining(7)
        blocks = self.core_value("deposit-mine", "generatetoaddress", 7, mining_address)
        require(len(blocks) == 7, "deposit-mined-block-count")
        first = self.core_value("deposit-mined-first-block", "getblock", blocks[0], 1)
        require(first["height"] == before + 1 and txid in first["tx"], "deposit-mined-inclusion")
        self.finance["deposits"][-1]["height"] = first["height"]
        self.finance["deposits"][-1]["required_consensus_count"] = first["height"] + 1
        self.phase = "first_deposit_mined"
        self.save_state()
        self.progress("awaiting-first-deposit", public_deposit=self.finance["deposits"][-1])
        self.cli("a", "a-first-await-receive", "module", "walletv2", "--", "await-receive", str(cursor), limit=600)
        total, _ = self.cli("a", "a-first-wallet-value", "module", "walletv2", "--", "info", "total-value")
        count, _ = self.cli("a", "a-first-wallet-count", "module", "walletv2", "--", "info", "block-count")
        notes, _ = self.cli("a", "a-first-mint-count", "module", "mintv2", "--", "count")
        # The zero-valued diagnostic did not establish this CLI field's units.
        # Preserve its positive observation for review before exact accounting.
        require(type(total) is int and total > 0, "first-wallet-value-absent")
        require(type(count) is int and count >= first["height"] + 1, "deposit-burial-consensus-count")
        require(isinstance(notes, dict) and bool(notes), "first-deposit-no-notes")
        self.cli("a", "a-first-pending-chain", "module", "walletv2", "--", "info", "pending-tx-chain")
        self.checks.append("First 100000-satoshi deposit mined with six-block burial; external CLI receipt response, positive Wallet value and nonempty Mint notes observed; exact accounting awaits review")
        self.phase = "first_deposit_observed"
        self.progress("first_deposit_observed", finance=self.finance, monetary_workflow=False)

    def second_deposit(self):
        require(self.phase == "first_deposit_observed", "second-deposit-phase")
        self.first_accounting()
        verify_artifact(CLIENT, CLIENT_SHA)
        verify_artifact(CORE, CORE_SHA)
        self.phase = "second_deposit_preparing"
        self.save_state()
        self.cli("a", "a-second-cursor-before-address", "dev", "next-event-log-id")
        self.cli("a", "a-second-deposit-address", "module", "walletv2", "--", "receive")
        verify_artifact(CLIENT, CLIENT_SHA)
        verify_artifact(CORE, CORE_SHA)
        address = self.prior("a-second-deposit-address")
        cursor = self.prior("a-second-cursor-before-address")
        require(isinstance(address, str), "second-deposit-address-shape")
        require(type(cursor) is int and cursor >= 0, "event-cursor-shape")
        require(self.prior("a-first-wallet-value") == 100_000, "second-initial-wallet")
        decoded_address = self.core_value("second-deposit-validate-address", "validateaddress", address)
        require(decoded_address["isvalid"] and decoded_address.get("iswitness") is True
            and decoded_address.get("witness_version") == 0
            and len(decoded_address.get("witness_program", "")) == 64, "second-deposit-not-p2wsh")
        require(self.core_value("second-deposit-initial-mempool", "getrawmempool") == [], "unexpected-initial-mempool")
        estimate = self.core_value("second-deposit-core-fee", "estimatesmartfee", 6, "CONSERVATIVE")
        require(isinstance(estimate, dict) and "feerate" in estimate, "second-deposit-no-genuine-estimate")
        sat_per_kvb = btc_satoshis(estimate["feerate"])
        require(sat_per_kvb > 0, "second-deposit-zero-estimate")
        amount_sat = 100_000
        require(self.finance["funded_sat"] + amount_sat <= 1_000_000, "second-deposit-budget")
        self.progress("preparing-second-deposit")
        raw = self.core_value("second-deposit-create", "createrawtransaction", [], {address: "0.00100000"})
        funded = self.core_value("second-deposit-fund", "fundrawtransaction", raw,
            {"minconf": 1, "include_unsafe": False, "fee_rate": str(Decimal(sat_per_kvb) / 1000)}, wallet=True)
        fee_sat = btc_satoshis(funded["fee"])
        require(self.finance["core_fee_sat"] + fee_sat <= 100_000, "bitcoin-fee-budget")
        signed = self.core_value("second-deposit-sign", "signrawtransactionwithwallet", funded["hex"], wallet=True)
        require(signed.get("complete") is True, "second-deposit-signing-incomplete")
        decoded = self.core_value("second-deposit-decode", "decoderawtransaction", signed["hex"])
        input_total = 0
        for index, txin in enumerate(decoded["vin"]):
            utxo = self.core_value("second-deposit-input-" + str(index), "gettxout", txin["txid"], txin["vout"], True)
            require(isinstance(utxo, dict) and utxo.get("confirmations", 0) >= 1, "second-deposit-input-not-confirmed")
            input_total += btc_satoshis(utxo["value"])
        require(input_total - sum(btc_satoshis(v["value"]) for v in decoded["vout"]) == fee_sat, "second-deposit-fee-crosscheck")
        matching = [v for v in decoded["vout"] if v["scriptPubKey"]["hex"] == decoded_address["scriptPubKey"]]
        require(len(matching) == 1 and btc_satoshis(matching[0]["value"]) == amount_sat, "second-deposit-output-crosscheck")
        # Reserve before broadcast. Never repeat a possibly accepted broadcast
        # after an ambiguous timeout or recreate this stage after a restart.
        self.finance["funded_sat"] += amount_sat
        self.finance["core_fee_sat"] += fee_sat
        self.finance["deposits"].append({"txid": decoded["txid"], "vout": matching[0]["n"], "amount_sat": amount_sat, "bitcoin_fee_sat": fee_sat})
        self.phase = "second_deposit_reserved"
        self.save_state()
        txid = self.core_value("second-deposit-broadcast", "sendrawtransaction", signed["hex"])
        require(txid == decoded["txid"], "second-deposit-broadcast-txid")
        entry = self.core_value("second-deposit-mempool-entry", "getmempoolentry", txid)
        require(btc_satoshis(entry["fees"]["base"]) == fee_sat, "second-deposit-mempool-fee")
        require(self.core_value("second-deposit-mempool", "getrawmempool") == [txid], "unexpected-deposit-mempool")
        mining_address = self.core_value("second-deposit-mining-address", "getnewaddress", "mixed-driver-mining", "bech32", wallet=True)
        before = self.core_value("second-deposit-height-before", "getblockcount")
        # backend count is height+1; count-6 must exceed the deposit's height.
        # Seven real blocks include the deposit and provide its six-block delay.
        self.reserve_mining(7)
        blocks = self.core_value("second-deposit-mine", "generatetoaddress", 7, mining_address)
        require(len(blocks) == 7, "second-deposit-mined-block-count")
        first = self.core_value("second-deposit-mined-first-block", "getblock", blocks[0], 1)
        require(first["height"] == before + 1 and txid in first["tx"], "second-deposit-mined-inclusion")
        self.finance["deposits"][-1]["height"] = first["height"]
        self.finance["deposits"][-1]["required_consensus_count"] = first["height"] + 1
        self.phase = "second_deposit_mined"
        self.save_state()
        self.progress("awaiting-second-deposit", public_deposit=self.finance["deposits"][-1])
        receipt, _ = self.cli("a", "a-second-await-receive", "module", "walletv2", "--", "await-receive", str(cursor), limit=600)
        require(isinstance(receipt, list) and len(receipt) == 2 and receipt[0] == "Success"
            and type(receipt[1]) is int and receipt[1] > cursor, "second-receipt-schema")
        total, _ = self.cli("a", "a-second-wallet-value", "module", "walletv2", "--", "info", "total-value")
        count, _ = self.cli("a", "a-second-wallet-count", "module", "walletv2", "--", "info", "block-count")
        notes, _ = self.cli("a", "a-second-mint-count", "module", "mintv2", "--", "count")
        # The zero-valued diagnostic did not establish this CLI field's units.
        # Preserve its positive observation for review before exact accounting.
        require(type(total) is int and 100_000 < total < 200_000, "second-wallet-consolidation-value")
        require(type(count) is int and count >= first["height"] + 1, "second-deposit-burial-consensus-count")
        require(isinstance(notes, dict) and bool(notes), "second-deposit-no-notes")
        require(note_totals(notes)[0] > self.finance["first_accounting"]["mint_liabilities_msat"], "second-issuance-not-observed")
        pending, _ = self.cli("a", "a-second-pending-chain", "module", "walletv2", "--", "info", "pending-tx-chain")
        require(isinstance(pending, list) and len(pending) == 1, "second-pending-consolidation")
        self.cli("a", "a-second-chain", "module", "walletv2", "--", "info", "tx-chain")
        self.checks.append("Second 100000-satoshi deposit mined with six-block burial; external CLI receipt response, positive Wallet value and nonempty Mint notes observed; exact accounting awaits review")
        self.phase = "second_deposit_observed"
        self.progress("second_deposit_observed", finance=self.finance, monetary_workflow=False)

    def export_transfer(self):
        require(self.phase == "second_deposit_observed", "transfer-export-phase")
        verify_artifact(CLIENT, CLIENT_SHA)
        before_a, _ = self.cli("a", "transfer-before-a", "module", "mintv2", "--", "count")
        before_b, _ = self.cli("b", "transfer-before-b", "module", "mintv2", "--", "count")
        require(before_b == {}, "transfer-recipient-not-empty")
        require(note_totals(before_a)[0] > 10_000_000, "transfer-sender-balance")
        # The pinned CLI accepted this explicit unit in an empty-wallet probe.
        # Export may consume/reissue notes. Never repeat an ambiguous export.
        self.finance["transfer"] = {"requested_sat": 10_000,
            "sender_before_msat": note_totals(before_a)[0], "recipient_before_msat": 0}
        self.phase = "transfer_export_reserved"
        self.save_state()
        self.cli("a", "transfer-private-token", "module", "mintv2", "--", "send", "10000sat", limit=600)
        after_a, _ = self.cli("a", "transfer-after-export-a", "module", "mintv2", "--", "count")
        self.finance["transfer"]["sender_after_export_msat"] = note_totals(after_a)[0]
        self.phase = "transfer_exported"
        self.progress("transfer_exported", monetary_workflow=False)

    def reissue_transfer(self):
        require(self.phase == "transfer_exported", "transfer-reissue-phase")
        verify_artifact(CLIENT, CLIENT_SHA)
        token = self.prior("transfer-private-token")
        amount, count = exported_note_summary(token, self.handoff["federation_id"])
        transfer = self.finance["transfer"]
        require(amount == transfer["sender_before_msat"] - transfer["sender_after_export_msat"], "export-amount-accounting")
        require(10_000_000 <= amount < 10_001_000, "export-amount-bound")
        before, _ = self.cli("b", "transfer-before-reissue-b", "module", "mintv2", "--", "count")
        require(before == {}, "reissue-recipient-not-empty")
        transfer.update({"exported_msat": amount, "exported_note_count": count})
        self.phase = "transfer_reissue_reserved"
        self.save_state()
        self.cli("b", "transfer-receive-result", "module", "mintv2", "--", "receive", token, limit=600)
        # The baseline CLI returned "Success" while its durable reissuance was
        # still pending. Keep that same client running until its state machines
        # finish; never resubmit the token to try to make progress.
        self.cli("b", "transfer-reissue-complete", "dev", "wait-complete", limit=600)
        after, _ = self.cli("b", "transfer-after-reissue-b", "module", "mintv2", "--", "count")
        received, _ = note_totals(after)
        require(0 < received < amount, "reissue-recipient-value")
        transfer["recipient_after_msat"] = received
        self.cli("a", "transfer-after-reissue-a", "module", "mintv2", "--", "count")
        self.phase = "transfer_reissued"
        self.progress("transfer_reissued", finance=self.finance, monetary_workflow=False)

    def bitcoin_transaction(self, label, txid, block_hash=None):
        arguments = (txid, True) if block_hash is None else (txid, True, block_hash)
        transaction = self.core_value(label, "getrawtransaction", *arguments)
        require(isinstance(transaction, dict) and transaction.get("txid") == txid, "bitcoin-transaction-id")
        require(transaction.get("version") == 2 and transaction.get("locktime") == 0, "bitcoin-transaction-header")
        require(isinstance(transaction.get("hex"), str), "bitcoin-transaction-raw")
        for txin in transaction["vin"]:
            require(txin.get("sequence") == 0xfffffffd and txin["scriptSig"]["hex"] == "", "bitcoin-input-shape")
            witness = txin.get("txinwitness")
            require(isinstance(witness, list) and len(witness) == 5 and witness[0] == "", "bitcoin-q3-witness-shape")
            require(all(isinstance(value, str) and len(value) % 2 == 0 for value in witness), "bitcoin-witness-hex")
        return transaction

    def withdraw_pending_change(self):
        require(self.phase == "transfer_reissued", "withdrawal-phase")
        verify_artifact(CLIENT, CLIENT_SHA)
        verify_artifact(CORE, CORE_SHA)
        pending = self.prior("a-second-pending-chain")
        require(isinstance(pending, list) and len(pending) == 1, "withdrawal-parent-record")
        parent = pending[0]
        parent_id = parent["txid"]
        require(self.core_value("withdrawal-initial-mempool", "getrawmempool") == [parent_id], "withdrawal-parent-only")
        raw_parent = self.bitcoin_transaction("withdrawal-parent-raw", parent_id)
        deposits = self.finance["deposits"]
        require(len(deposits) == 2 and len(raw_parent["vin"]) == 2 and len(raw_parent["vout"]) == 1, "withdrawal-parent-structure")
        require([(item["txid"], item["vout"]) for item in raw_parent["vin"]]
            == [(item["txid"], item["vout"]) for item in deposits], "withdrawal-parent-input-order")
        parent_value = btc_satoshis(raw_parent["vout"][0]["value"])
        require(parent_value == parent["output"] == self.prior("a-second-wallet-value")
            and sum(item["amount_sat"] for item in deposits) - parent_value == parent["fee"], "withdrawal-parent-accounting")
        require(raw_parent["vout"][0]["n"] == 0, "withdrawal-parent-output-index")
        parent_entry = self.core_value("withdrawal-parent-entry", "getmempoolentry", parent_id)
        require(parent_entry["depends"] == [] and btc_satoshis(parent_entry["fees"]["base"]) == parent["fee"], "withdrawal-parent-mempool-fee")
        fee, _ = self.cli("a", "withdrawal-send-fee", "module", "walletv2", "--", "send-fee")
        require(type(fee) is int and 0 < fee <= 5000, "withdrawal-fee-bound")
        before, _ = self.cli("a", "withdrawal-before-notes", "module", "mintv2", "--", "count")
        require(note_totals(before)[0] > (50_000 + fee) * 1000 + 100_000, "withdrawal-note-funding")
        address = self.core_value("withdrawal-destination", "getnewaddress", "mixed-driver-withdrawal", "bech32", wallet=True)
        destination = self.core_value("withdrawal-validate-destination", "validateaddress", address)
        require(destination.get("isvalid") is True and destination.get("witness_version") == 0
            and len(destination.get("witness_program", "")) == 40, "withdrawal-p2wpkh-destination")
        record = {"amount_sat": 50_000, "fee_sat": fee, "parent_txid": parent_id,
            "parent_value_sat": parent_value, "destination_script": destination["scriptPubKey"],
            "destination": address, "sender_before_msat": note_totals(before)[0]}
        require("withdrawal" not in self.finance, "withdrawal-already-reserved")
        self.finance["withdrawal"] = record
        self.phase = "withdrawal_reserved"
        self.save_state()
        self.stage_deadline = time.monotonic() + min(180, self.remaining())
        self.cli("a", "withdrawal-send-result", "module", "walletv2", "--", "send", address,
            "50000sat", "--fee", str(fee) + "sat", limit=90)
        attempt = 0
        while True:
            require(time.monotonic() < self.stage_deadline, "withdrawal-broadcast-deadline")
            attempt += 1
            # Keep durable client state machines running without waiting for a
            # confirmation that the coordinator deliberately has not mined yet.
            self.cli("a", f"withdrawal-wait-{attempt}", "dev", "wait", "5", limit=15)
            mempool = self.core_value(f"withdrawal-mempool-{attempt}", "getrawmempool")
            require(isinstance(mempool, list) and parent_id in mempool and len(mempool) <= 2, "withdrawal-unexpected-mempool")
            if len(mempool) == 2:
                break
        child_id = next(txid for txid in mempool if txid != parent_id)
        child = self.bitcoin_transaction("withdrawal-child-raw", child_id)
        validate_withdrawal_child(child, record)
        entry = self.core_value("withdrawal-child-entry", "getmempoolentry", child_id)
        require(entry["depends"] == [parent_id] and btc_satoshis(entry["fees"]["base"]) == fee, "withdrawal-mempool-accounting")
        record["child_txid"] = child_id
        record["change_sat"] = parent_value - 50_000 - fee
        pending, _ = self.cli("a", "withdrawal-pending-chain", "module", "walletv2", "--", "info", "pending-tx-chain")
        require(isinstance(pending, list) and [item["txid"] for item in pending] == [child_id, parent_id], "withdrawal-pending-chain-order")
        value, _ = self.cli("a", "withdrawal-wallet-value", "module", "walletv2", "--", "info", "total-value")
        require(value == record["change_sat"], "withdrawal-wallet-change")
        del self.stage_deadline
        self.phase = "withdrawal_pending"
        self.save_state()
        self.checks.append("Core admitted a partial withdrawal spending the unconfirmed consolidation output; exact destination, change, fee and witness shapes checked")
        self.progress("withdrawal_pending", finance=self.finance, monetary_workflow=False)

    def confirm_monetary(self):
        require(self.phase == "withdrawal_pending", "confirmation-phase")
        verify_artifact(CLIENT, CLIENT_SHA)
        verify_artifact(CORE, CORE_SHA)
        record = self.finance["withdrawal"]
        expected = {record["parent_txid"], record["child_txid"]}
        mempool = self.core_value("confirmation-initial-mempool", "getrawmempool")
        require(len(mempool) == 2 and set(mempool) == expected, "confirmation-mempool-set")
        self.phase = "confirmation_reserved"
        self.reserve_mining(7)  # Saves the phase and budget before any mining.
        address = self.core_value("confirmation-mining-address", "getnewaddress", "mixed-driver-confirm", "bech32", wallet=True)
        self.stage_deadline = time.monotonic() + min(180, self.remaining())
        blocks = self.core_value("confirmation-mine", "generatetoaddress", 7, address)
        require(isinstance(blocks, list) and len(blocks) == 7, "confirmation-block-count")
        included = set()
        inclusion_blocks = {}
        for index, block_hash in enumerate(blocks):
            block = self.core_value(f"confirmation-block-{index}", "getblock", block_hash, 1)
            require(block["hash"] == block_hash and block["confirmations"] > 0, "confirmation-canonical-block")
            included.update(expected.intersection(block["tx"]))
            for txid in expected.intersection(block["tx"]):
                inclusion_blocks[txid] = block_hash
        require(included == expected, "confirmation-package-inclusion")
        record["confirmation_blocks"] = blocks
        record["transaction_blocks"] = inclusion_blocks
        self.phase = "confirmation_mined"
        self.save_state()
        for name, txid in (("parent", record["parent_txid"]), ("child", record["child_txid"])):
            transaction = self.bitcoin_transaction(f"confirmation-{name}-raw", txid, inclusion_blocks[txid])
            require(transaction.get("confirmations", 0) >= 1, "confirmation-transaction-depth")
        attempt = 0
        while True:
            require(time.monotonic() < self.stage_deadline, "confirmation-scan-deadline")
            attempt += 1
            self.cli("a", f"confirmation-wait-{attempt}", "dev", "wait", "5", limit=15)
            pending, _ = self.cli("a", f"confirmation-pending-{attempt}", "module", "walletv2", "--", "info", "pending-tx-chain")
            if pending == []:
                break
        require(self.core_value("confirmation-final-mempool", "getrawmempool") == [], "confirmation-final-mempool")
        value, _ = self.cli("a", "confirmation-wallet-value", "module", "walletv2", "--", "info", "total-value")
        require(value == record["change_sat"], "confirmation-wallet-value-changed")
        chain, _ = self.cli("a", "confirmation-chain", "module", "walletv2", "--", "info", "tx-chain")
        require(isinstance(chain, list) and [item["txid"] for item in chain]
            == [record["parent_txid"], record["child_txid"]], "confirmation-retained-chain")
        for client in ("a", "b"):
            self.cli(client, f"confirmation-notes-{client}", "module", "mintv2", "--", "count")
        del self.stage_deadline
        self.phase = "monetary_observed"
        self.save_state()
        self.checks.append("Parent and pending-change withdrawal included in canonical Core blocks; client pending chain cleared and Wallet value retained")
        self.progress("monetary_observed", finance=self.finance, monetary_workflow=False)

    def completed_count(self, label):
        response, _ = self.cli("a", label, "dev", "session-count", limit=30)
        require(isinstance(response, dict) and set(response) == {"count"}, "completed-session-count-shape")
        count = response["count"]
        require(type(count) is int and 0 <= count <= 0xffffffffffffffff, "completed-session-count-shape")
        return count

    def guardian_control(self, peer, action):
        require(getattr(self, "survivors", False), "guardian-control-mode")
        require(type(peer) is int and 0 <= peer < 4 and action in ("stop", "restart"), "guardian-control-request")
        identifier = peer * 2 + (action == "restart")
        request = {"schema": 1, "id": identifier, "action": action, "peer": peer}
        path = self.root / "guardian-control.json"
        acknowledgement = self.root / f"guardian-ack-{identifier}.json"
        require(not path.exists() and not acknowledgement.exists(), "guardian-control-already-issued")
        self.phase = f"survivor_{peer}_{action}_reserved"
        self.save_state()
        atomic_json(path, request)
        end = min(time.monotonic() + 240, self.end, getattr(self, "stage_deadline", float("inf")))
        while not acknowledgement.exists():
            require(time.monotonic() < end, "guardian-ack-deadline")
            time.sleep(min(0.1, max(0, end - time.monotonic())))
        reply = read_json(acknowledgement)
        for key, expected in request.items():
            require(type(reply.get(key)) is type(expected) and reply[key] == expected, "guardian-ack-mismatch")
        if action == "stop":
            require(type(reply.get("exit")) is int and reply["exit"] in (0, 255), "guardian-stop-not-joined")
        else:
            require("exit" in reply and reply["exit"] is None, "guardian-restart-ack")
        self.finance["survivor_cases"][peer][action + "_ack"] = reply
        self.save_state()

    def survivor_case(self, peer):
        require(getattr(self, "survivors", False), "survivor-mode-required")
        require(type(peer) is int and 0 <= peer < 4, "survivor-peer")
        expected_phase = "monetary_observed" if peer == 0 else f"monetary_survivor_{peer - 1}_observed"
        require(self.phase == expected_phase, "survivor-phase")
        verify_artifact(CLIENT, CLIENT_SHA)
        verify_artifact(CORE, CORE_SHA)
        require(self.finance["funded_sat"] == 200_000 and len(self.finance["deposits"]) == 2, "survivor-no-new-funding")
        require(self.finance["mined_blocks_reserved"] == 21 + peer * 7, "survivor-mining-prefix")
        cases = self.finance.setdefault("survivor_cases", [])
        require(len(cases) == peer, "survivor-case-already-reserved")
        cases.append({"peer": peer})
        record = cases[peer]
        self.stage_deadline = time.monotonic() + min(600, self.remaining())
        self.guardian_control(peer, "stop")
        # Every monetary operation starts after the owned guardian was joined.
        label = f"survivor-{peer}"
        before_a, _ = self.cli("a", label + "-before-a", "module", "mintv2", "--", "count")
        before_b, _ = self.cli("b", label + "-before-b", "module", "mintv2", "--", "count")
        record.update({"sender_before_msat": note_totals(before_a)[0],
            "recipient_before_msat": note_totals(before_b)[0], "export_requested_sat": 5000})
        require(record["sender_before_msat"] > 5_001_000, "survivor-export-funding")
        self.phase = f"survivor_{peer}_export_reserved"
        self.save_state()
        self.cli("a", label + "-private-token", "module", "mintv2", "--", "send", "5000sat", limit=180)
        self.cli("a", label + "-export-complete", "dev", "wait-complete", limit=180)
        token = self.prior(label + "-private-token")
        correlation = []
        exported, notes = exported_note_summary(token, self.handoff["federation_id"], correlation)
        require(len({(item["denomination"], item["signature_sha256"]) for item in correlation}) == notes, "survivor-duplicate-exported-note")
        require(5_000_000 <= exported < 5_001_000, "survivor-export-bound")
        after_a, _ = self.cli("a", label + "-after-export-a", "module", "mintv2", "--", "count")
        require(record["sender_before_msat"] - note_totals(after_a)[0] >= exported, "survivor-export-accounting")
        record.update({"exported_msat": exported, "exported_note_count": notes, "reissue_notes": correlation,
            "sender_after_export_msat": note_totals(after_a)[0]})
        self.phase = f"survivor_{peer}_receipt_reserved"
        self.save_state()
        self.cli("b", label + "-receive-result", "module", "mintv2", "--", "receive", token, limit=180)
        self.cli("b", label + "-receive-complete", "dev", "wait-complete", limit=180)
        after_b, _ = self.cli("b", label + "-after-reissue-b", "module", "mintv2", "--", "count")
        received = note_totals(after_b)[0] - record["recipient_before_msat"]
        require(0 < received < exported, "survivor-reissue-inventory")
        record["recipient_after_msat"] = note_totals(after_b)[0]
        require(self.core_value(label + "-initial-mempool", "getrawmempool") == [], "survivor-initial-mempool")
        if peer == 0:
            previous = self.finance["withdrawal"]
            parent_id = previous["child_txid"]
            parent_block = previous["transaction_blocks"][parent_id]
        else:
            previous = cases[peer - 1]
            parent_id, parent_block = previous["bitcoin_txid"], previous["block_hash"]
        parent = self.bitcoin_transaction(label + "-confirmed-parent", parent_id, parent_block)
        require(parent.get("confirmations", 0) >= 1, "survivor-parent-unconfirmed")
        parent_value = btc_satoshis(parent["vout"][0]["value"])
        value, _ = self.cli("a", label + "-wallet-before", "module", "walletv2", "--", "info", "total-value")
        chain, _ = self.cli("a", label + "-chain-before", "module", "walletv2", "--", "info", "tx-chain")
        require(value == parent_value and chain[-1]["txid"] == parent_id, "survivor-current-change")
        fee, _ = self.cli("a", label + "-send-fee", "module", "walletv2", "--", "send-fee")
        require(type(fee) is int and 0 < fee <= 5000, "survivor-fee-bound")
        address = self.core_value(label + "-destination", "getnewaddress", label, "bech32", wallet=True)
        destination = self.core_value(label + "-validate-destination", "validateaddress", address)
        require(destination.get("isvalid") is True and destination.get("witness_version") == 0
            and len(destination.get("witness_program", "")) == 40, "survivor-destination-shape")
        record.update({"parent_txid": parent_id, "parent_value_sat": parent_value,
            "amount_sat": 10000, "fee_sat": fee, "destination": address,
            "destination_script": destination["scriptPubKey"]})
        require(parent_value - 10000 - fee >= 10000, "survivor-change-dust")
        self.phase = f"survivor_{peer}_withdrawal_reserved"
        self.save_state()
        self.cli("a", label + "-send-result", "module", "walletv2", "--", "send", address,
            "10000sat", "--fee", str(fee) + "sat", limit=90)
        case_deadline = self.stage_deadline
        self.stage_deadline = min(time.monotonic() + 180, case_deadline)
        attempt = 0
        while True:
            require(time.monotonic() < self.stage_deadline, "survivor-broadcast-deadline")
            attempt += 1
            self.cli("a", f"{label}-broadcast-wait-{attempt}", "dev", "wait", "5", limit=15)
            mempool = self.core_value(f"{label}-mempool-{attempt}", "getrawmempool")
            require(isinstance(mempool, list) and len(mempool) <= 1, "survivor-unexpected-mempool")
            if mempool:
                break
        child_id = mempool[0]
        child = self.bitcoin_transaction(label + "-child-raw", child_id)
        validate_withdrawal_child(child, record)
        entry = self.core_value(label + "-child-entry", "getmempoolentry", child_id)
        require(entry["depends"] == [] and btc_satoshis(entry["fees"]["base"]) == fee, "survivor-mempool-fee")
        self.stage_deadline = case_deadline
        record.update({"bitcoin_txid": child_id, "change_sat": parent_value - 10000 - fee,
            "post_broadcast_completed_count": self.completed_count(label + "-post-broadcast-count")})
        self.phase = f"survivor_{peer}_mining_reserved"
        self.reserve_mining(7)
        mining_address = self.core_value(label + "-mining-address", "getnewaddress", label + "-mine", "bech32", wallet=True)
        require(self.core_value(label + "-premine-mempool", "getrawmempool") == [child_id], "survivor-premine-set")
        blocks = self.core_value(label + "-mine", "generatetoaddress", 7, mining_address)
        require(isinstance(blocks, list) and len(blocks) == 7, "survivor-mined-count")
        included = None
        for index, block_hash in enumerate(blocks):
            block = self.core_value(f"{label}-block-{index}", "getblock", block_hash, 1)
            require(block["hash"] == block_hash and block["confirmations"] > 0, "survivor-canonical-block")
            if child_id in block["tx"]:
                included = (block_hash, block["height"])
        require(included is not None, "survivor-mined-inclusion")
        record.update({"block_hash": included[0], "confirmed_height": included[1], "mined_blocks": blocks})
        confirmed = self.bitcoin_transaction(label + "-confirmed-child", child_id, included[0])
        require(confirmed.get("confirmations", 0) >= 1, "survivor-confirmation-depth")
        self.phase = f"survivor_{peer}_confirmed"
        self.save_state()
        attempt = 0
        while True:
            require(time.monotonic() < self.stage_deadline, "survivor-completed-history-deadline")
            attempt += 1
            self.cli("a", f"{label}-confirmation-wait-{attempt}", "dev", "wait", "5", limit=15)
            pending, _ = self.cli("a", f"{label}-pending-{attempt}", "module", "walletv2", "--", "info", "pending-tx-chain")
            count = self.completed_count(f"{label}-completed-count-{attempt}")
            if pending == [] and count > record["post_broadcast_completed_count"]:
                break
        record["final_count"] = count
        value, _ = self.cli("a", label + "-wallet-final", "module", "walletv2", "--", "info", "total-value")
        require(value == record["change_sat"], "survivor-final-wallet-value")
        for client in ("a", "b"):
            self.cli(client, label + "-final-notes-" + client, "module", "mintv2", "--", "count")
        require(self.core_value(label + "-final-mempool", "getrawmempool") == [], "survivor-final-mempool")
        public = {key: record[key] for key in ("peer", "bitcoin_txid", "destination_script", "amount_sat",
            "fee_sat", "post_broadcast_completed_count", "final_count", "block_hash", "confirmed_height",
            "reissue_notes", "recipient_before_msat", "recipient_after_msat")}
        public.update({"schema": 1, "parent_bitcoin_txid": parent_id})
        self.save_state()
        atomic_json(self.root / f"survivor-case-{peer}-public.json", public)
        # Harness verifies actual target inclusion and survivor-only q3 signers
        # before restarting; a later count alone is not that membership proof.
        self.guardian_control(peer, "restart")
        record["complete"] = True
        del self.stage_deadline
        self.phase = "monetary_survivors_observed" if peer == 3 else f"monetary_survivor_{peer}_observed"
        self.save_state()
        self.checks.append(f"Peer {peer} joined outage: recipient reissue and confirmed withdrawal observed; harness restart/catch-up acknowledgement retained")
        self.progress(self.phase, finance=self.finance, monetary_workflow=False)

    def resume(self):
        if self.phase == "diagnostics_ready":
            self.first_deposit()
        elif self.phase == "first_deposit_observed":
            self.second_deposit()
        elif self.phase == "second_deposit_observed":
            self.export_transfer()
        elif self.phase == "transfer_exported":
            self.reissue_transfer()
        elif self.phase == "transfer_reissued":
            self.withdraw_pending_change()
        elif self.phase == "withdrawal_pending":
            self.confirm_monetary()
        elif self.phase == "monetary_observed" and getattr(self, "survivors", False):
            self.survivor_case(0)
        elif getattr(self, "survivors", False) and self.phase in [f"monetary_survivor_{peer}_observed" for peer in range(3)]:
            self.survivor_case(int(self.phase.split("_")[2]) + 1)
        else:
            raise DriverError("reviewed-resume-not-implemented")

    def diagnostics(self):
        verify_artifact(CLIENT, CLIENT_SHA)
        verify_artifact(CORE, CORE_SHA)
        _, raw = self.command("client-version-hash", [str(CLIENT), "version-hash"], 15)
        require(raw.decode("ascii").strip() == REVISION, "client-version-hash")
        self.checks.append("Exact client and Core CLI artifact digests verified; client revision matches pinned daemon")
        chain, _ = self.core("core-chain", "getblockchaininfo")
        require(chain["chain"] == "regtest" and not chain["initialblockdownload"], "core-not-ready-regtest")
        self.core("core-fee-conservative", "estimatesmartfee", "6", "CONSERVATIVE")
        self.checks.append("Real Core regtest readiness and conservative fee response captured")
        invite = self.handoff["invite_codes"][0]
        require(isinstance(invite, str) and invite, "invite-shape")
        for client in ("a", "b"):
            self.client_dirs[client].mkdir(mode=0o700)
            self.progress("joining-client-" + client)
            self.cli(client, client + "-join", "join", invite, limit=120)
            self.checks.append("Private durable client " + client + " joined using the verified external CLI")
        if self.survivors:
            self.completed_count("diagnostic-completed-session-count")
        self.progress("querying-diagnostics")
        for client in ("a", "b"):
            self.cli(client, client + "-mint-count", "module", "mintv2", "--", "count")
        for name in ("send-fee", "receive-fee"):
            self.cli("a", "a-" + name, "module", "walletv2", "--", name)
        for name in ("total-value", "block-count", "feerate", "pending-tx-chain"):
            self.cli("a", "a-info-" + name, "module", "walletv2", "--", "info", name)
        # The published external Wallet receive help requires this exact order.
        self.cli("a", "a-cursor-before-address", "dev", "next-event-log-id")
        self.cli("a", "a-deposit-address", "module", "walletv2", "--", "receive")
        self.checks.append("Wallet fee/state and Mint counts captured; event cursor captured before deposit address")
        self.phase = "diagnostics_ready"
        self.progress("diagnostics_ready", control_path=str(self.root / "driver-control.json"), monetary_workflow=False)

    def await_control(self):
        self.save_state()
        control_path = self.root / "driver-control.json"
        while True:
            self.remaining()
            if control_path.exists():
                value = read_json(control_path)
                require(value.get("schema") == 1, "control-schema")
                action = value.get("action")
                if action == "finish-diagnostics":
                    atomic_json(Path(self.handoff["result_path"]), {
                        "schema": 1, "status": "passed", "checks": self.checks,
                        "monetary_workflow": False,
                    })
                    self.progress("diagnostics_finished", monetary_workflow=False)
                    return
                if action == "abort":
                    raise DriverError("coordinator-aborted")
                if action == "resume-reviewed":
                    reviewed = value.get("script_sha256")
                    require(isinstance(reviewed, str), "resume-script-digest")
                    snapshot, actual = source_snapshot(self.root, self.script, reviewed)
                    require(self.remaining() > 0, "driver-deadline")
                    os.replace(control_path, self.root / f"driver-control-consumed-{self.sequence}.json")
                    self.progress("resuming-reviewed", reviewed_script_sha256=actual)
                    # Only this owned path can run; preserve interpreter/process group
                    # and the initial deadline independently recorded in the manifest.
                    os.execv(sys.executable, [sys.executable, str(snapshot),
                        "--handoff", str(self.root), "--resume",
                        "--original-deadline", repr(self.end),
                        "--snapshot-sha", actual, "--entry-script", str(self.script)])
                raise DriverError("unsupported-control-action")
            time.sleep(min(0.2, self.remaining()))


def self_test():
    # Exact public CLI response captured by the unfunded diagnostic on 2026-09-11.
    count_reader = Driver.__new__(Driver)
    for response in ({"count": 0}, {"count": 0xffffffffffffffff}):
        count_reader.cli = lambda *args, **kwargs: (response, b"")
        require(count_reader.completed_count("fixture") == response["count"], "self-test-session-count-object")
    for response in (0, {}, {"count": True}, {"count": -1}, {"count": 1 << 64},
            {"count": "0"}, {"count": 0, "extra": 1}):
        count_reader.cli = lambda *args, **kwargs: (response, b"")
        try:
            count_reader.completed_count("fixture")
        except DriverError as error:
            require(str(error) == "completed-session-count-shape", "self-test-session-count-rejection")
        else:
            raise DriverError("self-test-invalid-session-count")
    require(note_totals({"9": 3, "10": 4}) == (5632, 7), "self-test-note-units")
    for invalid in ({"09": 1}, {"42": 1}, {"9": True}, {"9": -1}):
        try:
            note_totals(invalid)
        except DriverError:
            pass
        else:
            raise DriverError("self-test-invalid-note-count")
    budget = Driver.__new__(Driver)
    budget.finance = {"mined_blocks_reserved": 7}
    saved = []
    budget.save_state = lambda: saved.append(budget.finance["mined_blocks_reserved"])
    budget.reserve_mining(7)
    budget.reserve_mining(7)
    try:
        budget.reserve_mining(1)
    except DriverError:
        pass
    else:
        raise DriverError("self-test-mining-cap")
    require(saved == [14, 21], "self-test-mining-reservations")
    invoked = []
    budget.first_deposit = lambda: invoked.append("first")
    budget.second_deposit = lambda: invoked.append("second")
    budget.phase = "first_deposit_observed"
    budget.resume()
    require(invoked == ["second"], "self-test-no-refund-first")
    budget.export_transfer = lambda: invoked.append("export")
    budget.phase = "second_deposit_observed"
    budget.resume()
    require(invoked == ["second", "export"], "self-test-export-dispatch")
    budget.reissue_transfer = lambda: invoked.append("reissue")
    budget.phase = "transfer_exported"
    budget.resume()
    require(invoked == ["second", "export", "reissue"], "self-test-reissue-dispatch")
    for phase in ("second_deposit_preparing", "second_deposit_reserved", "second_deposit_mined", "transfer_export_reserved", "transfer_reissue_reserved", "withdrawal_reserved", "confirmation_reserved", "confirmation_mined", "monetary_observed"):
        budget.phase = phase
        try:
            budget.resume()
        except DriverError:
            pass
        else:
            raise DriverError("self-test-ambiguous-retry")
    import tempfile
    import sys
    from unittest.mock import patch
    import copy
    record = {"parent_txid": "11" * 32, "parent_value_sat": 199368,
        "amount_sat": 50000, "fee_sat": 456, "destination_script": "0014" + "22" * 20}
    child = {"vin": [{"txid": record["parent_txid"], "vout": 0}], "vout": [
        {"n": 0, "value": "0.00148912", "scriptPubKey": {"hex": "0020" + "33" * 32}},
        {"n": 1, "value": "0.00050000", "scriptPubKey": {"hex": record["destination_script"]}}]}
    validate_withdrawal_child(child, record)
    for mutation in ("parent", "destination", "fee", "extra-output"):
        invalid = copy.deepcopy(child)
        if mutation == "parent":
            invalid["vin"][0]["vout"] = 1
        elif mutation == "destination":
            invalid["vout"][1]["scriptPubKey"]["hex"] = "0014" + "44" * 20
        elif mutation == "fee":
            invalid["vout"][0]["value"] = "0.00148913"
        else:
            invalid["vout"].append(copy.deepcopy(invalid["vout"][0]))
        try:
            validate_withdrawal_child(invalid, record)
        except DriverError:
            pass
        else:
            raise DriverError("self-test-child-validation")
    mock = Driver.__new__(Driver)
    mock.end = time.monotonic() + 600
    mock.phase = "transfer_reissued"
    mock.finance = {"deposits": [{"txid": "a", "vout": 0, "amount_sat": 100000},
        {"txid": "b", "vout": 1, "amount_sat": 100000}], "mined_blocks_reserved": 14}
    saved = []
    mock.save_state = lambda: saved.append((mock.phase, copy.deepcopy(mock.finance)))
    mock.prior = lambda name: ([{"txid": record["parent_txid"], "output": 199368, "fee": 632}]
        if name == "a-second-pending-chain" else 199368)
    mock.bitcoin_transaction = lambda *args: {"vin": [{"txid": "a", "vout": 0}, {"txid": "b", "vout": 1}],
        "vout": [{"n": 0, "value": "0.00199368"}]}
    core_replies = {"withdrawal-initial-mempool": [record["parent_txid"]], "withdrawal-parent-entry": {"depends": [], "fees": {"base": "0.00000632"}},
        "withdrawal-destination": "test-owned-address", "withdrawal-validate-destination": {
            "isvalid": True, "witness_version": 0, "witness_program": "22" * 20,
            "scriptPubKey": record["destination_script"]}}
    mock.core_value = lambda label, *args, **kwargs: core_replies[label]
    def mock_cli(client, label, *args, **kwargs):
        if label == "withdrawal-send-fee":
            return 456, b""
        if label == "withdrawal-before-notes":
            return {"28": 1}, b""
        require(label == "withdrawal-send-result", "self-test-withdraw-command")
        require(saved[-1][0] == "withdrawal_reserved" and saved[-1][1]["withdrawal"]["amount_sat"] == 50000,
            "self-test-withdraw-reserved-before-send")
        raise DriverError("injected-send-ambiguity")
    mock.cli = mock_cli
    with patch(__name__ + ".verify_artifact"):
        try:
            mock.withdraw_pending_change()
        except DriverError as error:
            require(str(error) == "injected-send-ambiguity", "self-test-withdraw-failure")
        else:
            raise DriverError("self-test-withdraw-did-not-stop")
        try:
            mock.resume()
        except DriverError as error:
            require(str(error) == "reviewed-resume-not-implemented", "self-test-withdraw-no-repeat")
        else:
            raise DriverError("self-test-withdraw-repeated")
        mock.phase = "withdrawal_pending"
        mock.finance["withdrawal"]["child_txid"] = "55" * 32
        def confirm_core(label, *args, **kwargs):
            if label == "confirmation-initial-mempool":
                return [record["parent_txid"], "55" * 32]
            if label == "confirmation-mining-address":
                return "test-owned-mining-address"
            require(label == "confirmation-mine", "self-test-confirm-command")
            require(saved[-1][0] == "confirmation_reserved" and saved[-1][1]["mined_blocks_reserved"] == 21,
                "self-test-confirm-reserved-before-mine")
            raise DriverError("injected-mining-ambiguity")
        mock.core_value = confirm_core
        try:
            mock.confirm_monetary()
        except DriverError as error:
            require(str(error) == "injected-mining-ambiguity", "self-test-confirm-failure")
        else:
            raise DriverError("self-test-confirm-did-not-stop")
        try:
            mock.resume()
        except DriverError as error:
            require(str(error) == "reviewed-resume-not-implemented", "self-test-confirm-no-repeat")
        else:
            raise DriverError("self-test-confirm-repeated")
    # Increased mining allowance is unavailable unless the original run opts in.
    scenario_budget = Driver.__new__(Driver)
    scenario_budget.survivors = True
    scenario_budget.finance = {"mined_blocks_reserved": 21}
    reservations = []
    scenario_budget.save_state = lambda: reservations.append(scenario_budget.finance["mined_blocks_reserved"])
    for _ in range(4):
        scenario_budget.reserve_mining(7)
    require(reservations == [28, 35, 42, 49], "self-test-survivor-mining-prefix")
    try:
        scenario_budget.reserve_mining(1)
    except DriverError:
        pass
    else:
        raise DriverError("self-test-survivor-mining-cap")
    with tempfile.TemporaryDirectory() as temporary:
        control = Driver.__new__(Driver)
        control.root = Path(temporary)
        control.end = time.monotonic() + 30
        control.survivors = True
        control.finance = {"survivor_cases": [{}]}
        writes = []
        control.save_state = lambda: writes.append(control.phase)
        real_atomic = atomic_json
        def acknowledge(path, request):
            require(writes[-1] == "survivor_0_stop_reserved", "self-test-stop-reserved")
            real_atomic(path, request)
            real_atomic(control.root / "guardian-ack-0.json", dict(request, exit=0))
        with patch(__name__ + ".atomic_json", side_effect=acknowledge):
            control.guardian_control(0, "stop")
        require(control.finance["survivor_cases"][0]["stop_ack"]["exit"] == 0, "self-test-joined-stop")
        try:
            control.guardian_control(0, "stop")
        except DriverError as error:
            require(str(error) == "guardian-control-already-issued", "self-test-control-no-repeat")
        else:
            raise DriverError("self-test-control-repeated")
        (control.root / "guardian-control.json").unlink()
        def wrong_ack(path, request):
            real_atomic(path, request)
            real_atomic(control.root / "guardian-ack-1.json", dict(request, peer=1, exit=None))
        with patch(__name__ + ".atomic_json", side_effect=wrong_ack):
            try:
                control.guardian_control(0, "restart")
            except DriverError as error:
                require(str(error) == "guardian-ack-mismatch", "self-test-control-wrong-peer")
            else:
                raise DriverError("self-test-wrong-ack-accepted")
    # Exercise every monetary mutation boundary through the real case method.
    for fail_at in ("private-token", "receive-result", "send-result", "mine"):
        case = Driver.__new__(Driver)
        case.survivors = True
        case.end = time.monotonic() + 3600
        case.phase = "monetary_observed"
        case.handoff = {"federation_id": "00" * 32}
        case.finance = {"funded_sat": 200000, "deposits": [{}, {}], "mined_blocks_reserved": 21,
            "withdrawal": {"child_txid": "11" * 32, "transaction_blocks": {"11" * 32: "aa" * 32}}}
        reserved = []
        case.save_state = lambda: reserved.append(case.phase)
        def joined(peer, action):
            require(peer == 0 and action == "stop", "self-test-survivor-stop-order")
            case.finance["survivor_cases"][0]["stop_ack"] = {"exit": 0}
        case.guardian_control = joined
        case.prior = lambda _: "private-fixture-token"
        def case_cli(client, label, *args, **kwargs):
            require("stop_ack" in case.finance["survivor_cases"][0], "self-test-money-before-stop")
            if label.endswith(fail_at):
                expected = {"private-token": "survivor_0_export_reserved", "receive-result": "survivor_0_receipt_reserved",
                    "send-result": "survivor_0_withdrawal_reserved"}[fail_at]
                require(reserved[-1] == expected, "self-test-survivor-money-reservation")
                raise DriverError("injected-survivor-ambiguity")
            if label.endswith("before-a"):
                return {"28": 1}, b""
            if label.endswith("before-b"):
                return {"20": 1}, b""
            if label.endswith("after-export-a"):
                return {"27": 1}, b""
            if label.endswith("after-reissue-b"):
                return {"21": 1}, b""
            if label.endswith("wallet-before"):
                return 148912, b""
            if label.endswith("chain-before"):
                return [{"txid": "11" * 32}], b""
            if label.endswith("send-fee"):
                return 456, b""
            if label.endswith("post-broadcast-count"):
                return {"count": 5}, b""
            return "Success", b""
        case.cli = case_cli
        def case_core(label, *args, **kwargs):
            if label.endswith("initial-mempool"):
                return []
            if label.endswith("validate-destination"):
                return {"isvalid": True, "witness_version": 0, "witness_program": "22" * 20,
                    "scriptPubKey": "0014" + "22" * 20}
            if label.endswith("destination") or label.endswith("mining-address"):
                return "test-owned-address"
            if "mempool-" in label or label.endswith("premine-mempool"):
                return ["55" * 32]
            if label.endswith("child-entry"):
                return {"depends": [], "fees": {"base": "0.00000456"}}
            require(label.endswith("-mine") and fail_at == "mine", "self-test-survivor-core-command")
            require(reserved[-1] == "survivor_0_mining_reserved" and case.finance["mined_blocks_reserved"] == 28,
                "self-test-survivor-reserved-before-mining")
            raise DriverError("injected-survivor-ambiguity")
        case.core_value = case_core
        def case_bitcoin(label, *args):
            if label.endswith("confirmed-parent"):
                return {"confirmations": 7, "vout": [{"value": "0.00148912"}]}
            return {"vin": [{"txid": "11" * 32, "vout": 0}], "vout": [
                {"n": 0, "value": "0.00138456", "scriptPubKey": {"hex": "0020" + "33" * 32}},
                {"n": 1, "value": "0.00010000", "scriptPubKey": {"hex": "0014" + "22" * 20}}]}
        case.bitcoin_transaction = case_bitcoin
        def mock_summary(token, federation, correlation):
            correlation.extend({"denomination": 9 + index, "signature_sha256": str(index) * 64} for index in range(3))
            return 5000192, 3
        with patch(__name__ + ".verify_artifact"), patch(__name__ + ".exported_note_summary", side_effect=mock_summary):
            try:
                case.survivor_case(0)
            except DriverError as error:
                require(str(error) == "injected-survivor-ambiguity", "self-test-survivor-mutation-error")
            else:
                raise DriverError("self-test-survivor-did-not-stop")
        try:
            case.resume()
        except DriverError as error:
            require(str(error) == "reviewed-resume-not-implemented", "self-test-survivor-no-retry")
        else:
            raise DriverError("self-test-survivor-repeated")
    for peer in range(4):
        for suffix in ("stop_reserved", "export_reserved", "receipt_reserved", "withdrawal_reserved", "mining_reserved", "confirmed", "restart_reserved"):
            scenario_budget.phase = f"survivor_{peer}_{suffix}"
            try:
                scenario_budget.resume()
            except DriverError as error:
                require(str(error) == "reviewed-resume-not-implemented", "self-test-survivor-reserved-dispatch")
            else:
                raise DriverError("self-test-survivor-ambiguous-dispatch")
    require(btc_satoshis("0.00100000") == 100000, "self-test-btc-units")
    for invalid in ("-1", "0.000000001", "Infinity"):
        try:
            btc_satoshis(invalid)
        except DriverError:
            pass
        else:
            raise DriverError("self-test-invalid-btc")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        atomic_json(root / "handoff.json", {"schema": 1, "api_urls": ["ws://127.0.0.1/"] * 4,
            "invite_codes": ["fixture"], "federation_id": "00" * 32,
            "progress_path": str(root / "progress.json"), "result_path": str(root / "result.json")})
        driver = Driver(root)
        value, _ = driver.command("decimal", [sys.executable, "-c", 'print("{\\\"n\\\":0.00000001}")'])
        require(value["n"] == Decimal("0.00000001"), "self-test-decimal")
        try:
            driver.command("blocked", [sys.executable, "-c", "import time;time.sleep(30)"], 0.1)
        except DriverError as error:
            require(str(error) == "command-timeout-blocked", "self-test-timeout")
        else:
            raise DriverError("self-test-child-not-timed-out")
        atomic_json(root / "driver-control.json", {"schema": 1, "action": "finish-diagnostics"})
        driver.checks.append("self-test")
        driver.await_control()
        require(read_json(root / "result.json")["monetary_workflow"] is False, "self-test-result")
        resumed = Driver(root, resume=True, original_deadline=driver.end)
        require(resumed.end == driver.end, "self-test-resume-deadline")
        require(resumed.sequence == driver.sequence, "self-test-output-sequence")
        original_handoff = read_json(root / "handoff.json")
        wrong_federation = dict(original_handoff, federation_id="11" * 32)
        atomic_json(root / "handoff.json", wrong_federation)
        try:
            Driver(root, resume=True, original_deadline=driver.end)
        except DriverError as error:
            require(str(error) == "resume-federation-mismatch", "self-test-federation-boundary")
        else:
            raise DriverError("self-test-wrong-federation-accepted")
        atomic_json(root / "handoff.json", original_handoff)
        try:
            Driver(root, resume=True, original_deadline=driver.end + 1)
        except DriverError as error:
            require(str(error) == "resume-deadline-mismatch", "self-test-resume-extension")
        else:
            raise DriverError("self-test-extended-deadline")
        atomic_json(root / "driver-control.json", {"schema": 1, "action": "resume-reviewed", "script_sha256": "00"})
        try:
            driver.await_control()
        except DriverError as error:
            require(str(error) == "resume-script-digest", "self-test-unreviewed-script")
        else:
            raise DriverError("self-test-unreviewed-script-accepted")
        atomic_json(root / "driver-control.json", {"schema": 1, "action": "resume-reviewed", "script_sha256": driver.script_digest})
        with patch.object(os, "execv", side_effect=RuntimeError("self-test-exec")) as execute:
            try:
                driver.await_control()
            except RuntimeError as error:
                require(str(error) == "self-test-exec", "self-test-exec-error")
            snapshot = root / "driver-sources" / (driver.script_digest + ".py")
            require(execute.call_args.args[1] == [sys.executable, str(snapshot),
                "--handoff", str(root), "--resume", "--original-deadline", repr(driver.end),
                "--snapshot-sha", driver.script_digest, "--entry-script", str(driver.script)], "self-test-exec-boundary")
            require(snapshot.read_bytes() == driver.script.read_bytes(), "self-test-snapshot-bytes")
            require(stat.S_IMODE(snapshot.stat().st_mode) == 0o400, "self-test-snapshot-mode")
        initial = root / "initial-bootstrap"
        initial.mkdir(mode=0o700)
        atomic_json(initial / "handoff.json", dict(original_handoff,
            progress_path=str(initial / "progress.json"), result_path=str(initial / "result.json")))
        with patch.object(sys, "argv", [str(driver.script), "--handoff", str(initial)]):
            with patch.object(os, "execv", side_effect=RuntimeError("self-test-initial-exec")) as execute:
                try:
                    main()
                except RuntimeError as error:
                    require(str(error) == "self-test-initial-exec", "self-test-initial-error")
                copied = Path(execute.call_args.args[1][1])
                require(copied.parent == initial / "driver-sources", "self-test-initial-path")
                require(copied.read_bytes() == driver.script.read_bytes(), "self-test-initial-bytes")
                require(read_json(initial / "driver-initial-manifest.json")["initial_script_sha256"] == copied.stem, "self-test-initial-digest")
    print("local driver checks passed; no federation or monetary commands executed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--resume", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--original-deadline", type=float, help=argparse.SUPPRESS)
    parser.add_argument("--snapshot-sha", help=argparse.SUPPRESS)
    parser.add_argument("--entry-script", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args.self_test:
        self_test()
        return 0
    require(args.handoff is not None, "handoff-required")
    if args.snapshot_sha is None:
        require(not args.resume, "resume-requires-reviewed-snapshot")
        root = Path(args.handoff).resolve()
        require(stat.S_ISDIR(root.stat().st_mode) and root.stat().st_mode & 0o077 == 0, "handoff-directory-permissions")
        handoff = root / "handoff.json"
        require(stat.S_ISREG(handoff.stat().st_mode) and handoff.stat().st_mode & 0o077 == 0, "handoff-file-permissions")
        seconds = int(os.environ.get("MINIMINT_MIXED_DRIVER_TIMEOUT_SECS", "1200"))
        require(1 <= seconds <= 3600, "driver-deadline")
        end = time.monotonic() + seconds
        entry_script = Path(__file__).resolve()
        snapshot, digest = source_snapshot(root, entry_script)
        write_initial_manifest(root, entry_script, digest, end, read_json(handoff)["federation_id"])
        os.execv(sys.executable, [sys.executable, str(snapshot), "--handoff", str(root),
            "--original-deadline", repr(end), "--snapshot-sha", digest, "--entry-script", str(entry_script)])
    driver = Driver(args.handoff, args.resume, args.original_deadline, args.snapshot_sha, args.entry_script)
    try:
        if args.resume:
            driver.resume()
        else:
            driver.diagnostics()
        driver.await_control()
    except (DriverError, ValueError, TypeError, KeyError, OSError) as error:
        code = str(error) if isinstance(error, DriverError) else type(error).__name__
        driver.progress("failed", error=code, monetary_workflow=False)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
