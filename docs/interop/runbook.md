# Guardian interoperability runbook

Use the exact spec/reference identities in [profile.json](../../tests/interop/profile.json). Read numbered specification documents, public fixtures and the operator handoff. Reference binaries may be built and used as black boxes; do not inspect Fedimint implementation or vector-bridge source. A compatible existing CLI supplies monetary test operations; this project has no client product.

## Build and offline evidence

Run from the repository root:

```sh
nix-shell --run 'cargo build --locked --bin fedimintd'
nix-shell --run 'cargo test --locked --test mixed_history_capture'
nix-shell --run 'cargo test --locked --test four_daemon_process -- --ignored --nocapture'
```

The capture test authenticates preserved public signed histories. The four-process test creates a fresh local federation and exercises ordinary session timing and restart. Allow several minutes. These checks do not exercise guardian monetary workflows.

## Fresh mixed federation

Provision the verified reference daemon and a running, verified Bitcoin Core regtest node outside initial block download, following [artifact-handoff.md](artifact-handoff.md). Rehash binaries before reuse; temporary paths in the profile are local observations and may expire. Core must be accessible over loopback HTTP with its credentials in a protected file. Empty-transaction mode does not mine or manage the Core process; the opt-in monetary driver below explicitly mines.

Set the following environment variables to the actual local artifact/socket/file paths; the credential variable contains a filename, never the cookie value:

```sh
export MINIMINT_REFERENCE_DAEMON=/path/to/verified/fedimintd
export MINIMINT_BITCOIN_RPC=127.0.0.1:42257
export MINIMINT_BITCOIN_CREDENTIALS_FILE=/private/regtest/.cookie
unset MINIMINT_MIXED_SETUP_ONLY MINIMINT_MIXED_DRIVER MINIMINT_MIXED_MONETARY_SURVIVORS
unset FM_IN_DEVIMINT NEXTEST FM_BACKWARDS_COMPATIBILITY_TEST
nix-shell --run 'cargo test --locked --test mixed_daemon_process -- --ignored --nocapture'
```

Replace illustrative paths with verified local paths. The test enforces the recorded reference digest, creates private fresh guardian directories, chooses loopback ports, configures only Mint v2 and Wallet v2, runs all-four setup, submits distinct empty transactions, waits for ordinary session completion and verifies all signed histories. It owns and joins its guardian children, preserves public evidence under the printed `/tmp/minimint-mixed-evidence-*` directory, and removes its private fixture state. Its failure paths also reap children. Do not run scenarios sharing a Bitcoin node concurrently with mining or wallet mutation.

`MINIMINT_MIXED_SETUP_ONLY=1` explicitly limits the invocation to setup/configuration evidence. Such a run must never be reported as completed-session evidence. The current test's reference SIGTERM exit 255 is separately recorded; unexpected runtime exit remains a failure.

Set `MINIMINT_MIXED_FAILURES=1` for the implemented single-peer stop/rejoin and two-peer fresh-work barrier scenario. It requires two ordinary session boundaries and passed in about 394 seconds. Its checks cover matching signed histories and retained Wallet state; monetary survivor-set evidence is documented separately below; inverse nonmonetary assignment is recorded in the results ledger. Leave `MINIMINT_MIXED_SETUP_ONLY` unset for this run.

Choose the stopped peer with `MINIMINT_MIXED_OUTAGE_PEER=0`, `1`, `2` or `3` (default 1). Set `MINIMINT_MIXED_ONE_OUTAGE_ONLY=1` to stop after that peer's restart and matching session-0 history, skipping the separate fixed two-peer barrier. Both options require failure mode. All four nonmonetary survivor sets have passed; monetary work under every outage is established by the separate corrected run below.

Select implementation assignments with `MINIMINT_MIXED_NEW_PEERS=0,1` (default) or another pair of distinct ascending IDs from 0 through 3. The inverse is `2,3`; the other two IDs use the reference artifact. `MINIMINT_MIXED_OUTAGE_PEER` always names the actual peer ID. The pair barrier keeps the lowest new ID and lowest reference ID alive, stops the other two, and inspects only the stopped new guardian's database. Assignment validation runs before child launch. The recorded artifact metadata states each peer's implementation; do not infer it from an ID alone.

Set `MINIMINT_MIXED_RECOVERY_CHECKS=1` to check signed synthetic opaque backups, timestamp replacement/rejection and five empty Mint queries, then stop/join/restart all four guardians and verify retained recovery. Combine with `MINIMINT_MIXED_SETUP_ONLY=1` for the short setup/recovery scenario. This branch does not establish signed-session or monetary success. The helper retains only public synthetic requests/replies; its backup signing secret stays in memory.

## Monetary and failure gates

The ignored `wallet_live_accepts_threshold_consolidation_and_withdrawal` test provides a separate direct Wallet/Core check with fixed test keys. It mutates the exclusively owned regtest node: two 100,000-satoshi funding outputs, one 50,000-satoshi withdrawal, at most 50,000 sats in total fees and 21 mined blocks. It has a 300-second owned process-group deadline and records signed bytes/budget intent before broadcast. Review its verified artifact, RPC and wallet prerequisites before invoking it; do not include it in ordinary offline validation or repeat it after an uncertain funding outcome. Its reported pass does not close mixed Mint/core monetary gates.

Retain live evidence outside Nix's `TMPDIR`, which is deleted on shell exit. The Wallet test defaults to `/tmp`; `MINIMINT_WALLET_LIVE_EVIDENCE_ROOT` may select an existing absolute directory. Copy reviewed public captures and their checksums into the fixture inventory before temporary machine state disappears. Preserve failure/loss provenance explicitly; reconstructed confirmed-chain facts are not original mempool or prebroadcast observations.

## Paused external monetary driver

The implemented test driver is [monetary_driver.py](../../tests/interop/monetary_driver.py). The profile records its reviewed SHA-256 and the exact external CLI digest. It uses the existing CLI rather than implementing a client. The preserved healthy mixed workflow has separate offline evidence. **The corrected four-case monetary survivor run passed on 2026-09-11**, including all eight joined stop/restart controls and independent per-case verification. This is bounded regtest evidence, not resolution of the six remaining definition gates.

External-driver mode is exclusive with setup-only and ordinary failure mode. The harness invokes `driver --handoff PRIVATE_DIRECTORY` after fresh setup and genuine, matching Wallet fee observations. `handoff.json` contains public endpoints, returned invite codes, client configuration, federation ID and result/progress paths. Driver state, client databases, tokens, stdout and stderr remain private; never echo those files into reports. The harness owns the driver process group, monitors guardians and joins its children on completion or failure. No daemonization is allowed.

For a new coordinated run, reuse the verified reference/Core environment described above, set the Core data directory used by the driver to the same node, and run:

```sh
export MINIMINT_MIXED_DRIVER="$PWD/tests/interop/monetary_driver.py"
export MINIMINT_DRIVER_CORE_DATADIR=/private/verified-regtest-datadir
export MINIMINT_MIXED_DRIVER_TIMEOUT_SECS=3600
export MINIMINT_MIXED_NEW_PEERS=0,1
unset MINIMINT_MIXED_SETUP_ONLY MINIMINT_MIXED_FAILURES MINIMINT_MIXED_OUTAGE_PEER
unset MINIMINT_MIXED_ONE_OUTAGE_ONLY MINIMINT_MIXED_RECOVERY_CHECKS
# Include this only for the reviewed four-case monetary survivor run:
export MINIMINT_MIXED_MONETARY_SURVIVORS=1
nix-shell --run 'cargo test --locked --test mixed_daemon_process two_independent_two_reference_fresh_setup_and_empty_history -- --ignored --exact --nocapture'
```

The historical test name says `empty_history`, but the external-driver branch submits no harness empty transactions. It uses ephemeral guardian ports, ordinary R=3600/delay=50ms and fresh private state. Do not attach old client databases to a new federation. The default driver deadline is 1,200 seconds, with a 3,600-second maximum; survivor mode requires exactly 3,600 seconds from the original launch. Every command and each at-most-600-second survivor case clips to that original remaining time. Keep exclusive ownership of Core mutations throughout the run.

### Diagnostic and reviewed-resume controls

Initial execution copies the source into `driver-sources/<sha256>.py` and executes that owner-read-only snapshot. The initial manifest binds the entry script, federation, boot ID, original monotonic deadline and survivor opt-in. A reviewed resume copies and executes only bytes matching its supplied digest; it cannot extend the deadline or switch federation/mode. Mode 0400 is an operational safeguard, not protection against the owning OS account.

Wait for `driver-progress.json` stage `diagnostics_ready`. Inspect only the required private command outputs: two successful joins, empty initial Mint counts, actual fee quotes, and the event cursor captured before the deposit address. In survivor mode, `CLI dev session-count` must return an object containing only the unsigned 64-bit integer `count`, observed initially as `{"count":0}`; the parser rejects extra fields, booleans, strings, negatives and overflow. An earlier diagnostic rejected the unexpected object before funding; its funded amount and Bitcoin fees remained zero. Do not proceed until the observed command schemas are understood.

To advance one reviewed stage, atomically create mode-0600 `driver-control.json` in the handoff directory with:

```json
{"schema":1,"action":"resume-reviewed","script_sha256":"a58a5fe44651c40eb5beac0d59d759468998e0fe70c6fa07a9cb4633308205b1"}
```

That literal identifies the currently reviewed source; if the source changes, review it and use its new exact digest rather than silently substituting a computed hash. The driver consumes the control and pauses again after the next stage. Healthy phase order is `diagnostics_ready`, `first_deposit_observed`, `second_deposit_observed`, `transfer_exported`, `transfer_reissued`, `withdrawal_pending`, then `monetary_observed`.

The verified CLI's `mintv2 receive` may return `"Success"` before its asynchronous reissuance finishes. The driver runs that same client's `dev wait-complete` and then checks increased inventory; it never resubmits the token to make progress. Before mining a withdrawal, it uses bounded `dev wait 5` calls instead: waiting for all operations to finish could otherwise block on the deliberately unmined transaction. Explicit amount arguments use the observed `sat` suffix, and withdrawal fees come from real quotes.

The healthy workflow funds two 100,000-satoshi deposits: **200,000 sat planned external funding**. It mines seven blocks for each deposit and seven for confirmation, **21 blocks total**. The broader safety caps remain 1,000,000 sat funded and 100,000 sat in external Bitcoin transaction fees; these caps do not authorize extra deposits. Export, reissuance, withdrawal and mining reservations are saved before the respective irreversible operation. Ambiguous reserved/preparing/mined phases cannot be resumed automatically. Do not re-fund or retry a possibly accepted mutation after a timeout.

### Monetary survivor cases and independent gates

With the original opt-in enabled, each reviewed resume after healthy `monetary_observed` runs one case in peer order 0, 1, 2, 3. The driver issues exactly eight private guardian requests:

```json
{"schema":1,"id":0,"action":"stop","peer":0}
```

IDs then advance through restart0 (1), stop1 (2), restart1 (3), stop2 (4), restart2 (5), stop3 (6), restart3 (7). The harness consumes `guardian-control.json` and writes numbered `guardian-ack-ID.json`. A stop acknowledgement is issued only after the child is joined and records its actual exit code; restart has `exit:null` and includes the verified completed count. The driver writes these requests itself; the operator should not bypass its phase/reservation protocol.

Only after joined-stop acknowledgement does the case export 5,000 sat from A, reissue it once to B, and withdraw 10,000 sat from A to a fresh Core-owned address. B's existing balance is preserved and its increase checked. The withdrawal spends the current confirmed Wallet change, uses a real quoted fee no greater than 5,000 sat, and requires the expected single mempool transaction, exact destination/change/fee and confirmed-parent linkage. Each case reserves and mines exactly seven blocks, then waits for pending-chain clearance and a completed session later than the post-broadcast count. There are **no new Bitcoin deposits**. Only this manifest-bound opt-in raises the cumulative mining cap to **49 = 21 + 4×7 blocks**.

Before restarting, the harness requires actual certified inclusion of both the reissuance and withdrawal with signatures from the three surviving guardians. A later session count alone is insufficient. The public case marker correlates the withdrawal by unique destination/value/fee and reissuance by denomination plus SHA-256 of each exported TBS signature, published only after successful reissuance. It contains no token or secret scalar. The reissuance must consume **every exported marker exactly once**, but its complete input set need not equal the exported set: valid additional Mint inputs owned by the recipient are permitted. Require bounded valid Mint inputs/outputs, one globally unique target transaction and the survivor-only certificate; matching denominations alone is insufficient. After restart the harness verifies matching histories, Wallet state, discoveries, chains and Mint recovery state, plus the restored guardian's output signature shares, before acknowledging catch-up.

[PIT-035](../spec-pitfalls.md#pit-035--a-reissuance-can-include-notes-already-owned-by-the-recipient) records the diagnosed matcher error: the prior case 3 transaction consumed all six exported notes plus eight existing recipient notes. Its fourteen-input reissuance was certified in session 8; the exact-set matcher rejected valid behavior. The corrected matcher permits those additional authorized inputs without weakening exported-note uniqueness or signer requirements. The retained interrupted case is not evidence of that guardian's later restart or catch-up. The separate corrected run completed all four per-case gates and terminal cleanup; the prior interrupted evidence remains separate.

After each acknowledgement, the driver pauses at `monetary_survivor_0_observed`, `monetary_survivor_1_observed`, `monetary_survivor_2_observed`, or finally `monetary_survivors_observed`. **Before advancing the next case, and before finishing after case 3**, preserve and independently verify that case. For case 0, using the actual evidence directory:

```sh
export MINIMINT_SURVIVOR_FIXTURE_ROOT="$PWD/tests/fixtures/interop/mixed-monetary-survivors-UNIQUE_RUN"
nix-shell --run 'python3 tests/interop/capture_survivor.py --evidence /tmp/minimint-mixed-evidence-REPLACE --case 0 --destination "$MINIMINT_SURVIVOR_FIXTURE_ROOT" --core-datadir /private/verified-regtest-datadir'
nix-shell --run 'cargo test --locked --test mixed_monetary_survivors_capture survivor_case0 -- --include-ignored --exact --nocapture'
```

Replace `UNIQUE_RUN` with a fresh capture name and use the same absolute destination for all four cases from this federation. `--destination` selects the capture directory; exported `MINIMINT_SURVIVOR_FIXTURE_ROOT` selects that same directory for the offline tests. Without the override, tests now read the completed corrected-run fixture `tests/fixtures/interop/mixed-monetary-survivors-retry-2026-09-11`. That proves the preserved run, not a future fresh federation. Use the corresponding case number and test name for cases 1–3. The capture helper performs only a known-block read from Core and copies allowlisted public evidence; it does not copy driver state or tokens. All four preserved corrected-run cases are now ordinary, unignored tests. `--include-ignored` remains suitable for a future case while its capture gate is still marked ignored. Require the named test to execute and pass, not a zero-test success. An ordinary suite that skips a case is not evidence of success. Preserve a fresh fixture directory for a different federation rather than mixing old and new captures. Healthy accounting and Bitcoin evidence use `mixed_monetary_history_capture` and `mixed_wallet_spends_capture` respectively.

At a reviewed stopping point, atomically write `{"schema":1,"action":"finish-diagnostics"}`. It produces `{"schema":1,"status":"passed","checks":[...],"monetary_workflow":false}` and lets the harness finish capture and join guardians. In survivor mode the harness additionally requires all eight stop/restart requests to have completed and no peer to remain offline; an early finish fails that gate. **The flag remains false even after monetary observations**: independently reviewed captures and test results establish the specific evidence claims. `{"schema":1,"action":"abort"}` instead fails the run. Neither an exit-zero callback nor an early diagnostic finish establishes all monetary or survivor gates.

The [external-driver handoff](driver-handoff.md) and [monetary assertions](monetary-assertions.md) explain units, accounting and provenance. Keep all client keys, tokens and raw client state private. The corrected run reached `monetary_survivors_observed`; parent handle 12006 exited 0 after 1,219.20 seconds, with six matching signed sessions and all eight controls complete. All four API ports were closed after joined exits `[0,0,255,255]`. Reference exit 255 is an observed shutdown result, not a claim of a clean exit. The final offline target (handle 65109) ran four tests with zero ignored and zero failures in 0.44 seconds. The driver result still records `monetary_workflow:false`; the independent evidence supports the survivor/recovery claims and the D13.4/D13.7 gates. Six definition gates remain open; this run does not establish full-spec completion.

Replay the preserved corrected-run survivor evidence without a live federation:

```sh
unset MINIMINT_SURVIVOR_FIXTURE_ROOT
nix-shell --run 'cargo test --locked --test mixed_monetary_survivors_capture'
```

Required monetary scenarios are first deposit/issuance, second-deposit consolidation, transfer/reissuance, withdrawal and pending-change spending, with actual Bitcoin bytes, fees, balances and confirmations checked. A successful Core wallet self-transfer is only backend evidence. An absent Core fee estimate must not be replaced with invented success; resolve the proposer policy in writer question Q16 or obtain a genuine usable observation.

Then run each one-guardian outage and module-bearing restart/catch-up; establish a two-peer outage barrier before proposing unique fresh work, excluding pre-barrier signatures and old accepted responses; restore quorum and repeat with peer-ID permutations. These scenarios remain acceptance requirements even when initial mixed consensus passes.

After each run record exact commands, binary hashes, spec/profile identities, public histories, Bitcoin txids, failure timing and failed/unrun cases in [results.md](results.md). Retain public evidence with checksums. Never copy private setup material, raw client state, credentials or ecash into the repository. The full implementation is complete only when the plan's API, monetary, durability and mixed failure gates all have evidence.
