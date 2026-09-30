# Exact-baseline external transaction driver candidate

Status on 2026-09-10: the exact upstream `fedimint-cli` artifact is verified and two private clients completed live diagnostic calls. A real first deposit was funded, mined and discovered by all four mixed guardians. The coordinator intentionally stopped the run at the WAL-016 discovery-outpoint JSON contradiction; no claim or issuance was observed. **The end-to-end monetary workflow has not passed.** `external_transaction_driver` remains null until usable workflow evidence exists. This project adds no client product.

## Artifact provenance

| Item | Evidence |
| --- | --- |
| Source repository | `https://github.com/fedimint/fedimint.git` |
| Exact source revision / successful `version-hash` output | `0c316439d60b5a08eea26fab216780eb893c45bf` |
| Build metadata | `cargo metadata --no-deps --format-version 1` reported package `fedimint-cli`, binary target `fedimint-cli`; processing emitted only these names |
| Build command | `nix develop -c cargo build --locked --release --bin fedimint-cli` |
| Build result | Exit 0; terminal execution handle 96044 |
| Executable | `/tmp/minimint-upstream-build.2Clk9R/checkout/target-nix/release/fedimint-cli` |
| Executable SHA-256 | `4c93df5a0cd6633ac7add340d7089b712b14b6a48655df89f9bfbb8a2d7eed23` |
| Executable size | 155861527 bytes |
| Cargo.lock SHA-256 | `78d538f1d031156de1ac74039467e93fad52fe3558da1437bab1b253fd3dbf72` |
| flake.lock SHA-256 | `fb4553899cb56f234b3cf639855d9e7c90ec1bf7f9961c19b16a58393167dba5` |
| Build environment | Linux x86_64; Nix 2.34.8; pinned upstream development environment |
| Post-build checks | Both lockfiles unchanged, tracked checkout clean, `version-hash` exit 0 and exact revision match |

Private metadata, build logs, help captures and local client state remain under `/tmp/minimint-upstream-build.2Clk9R`. Rehash the temporary executable before reuse or transfer. Neither compiler/build-log contents nor Fedimint implementation or bridge source were inspected. No bridge was invoked. See [reference artifact provenance](artifact-handoff.md) for the authorized source/build boundary and output-path correction.

## Initialization and help discovery

The verified executable exposes `join <INVITE_CODE>` with global `--data-dir <DATA_DIR>`. Its `help module` documents a module selector accepting either an instance ID or a module kind. Top-level `module --help` is rejected; the displayed argument guidance requires passing the module help through the argument separator.

Without a client directory, module help returned a missing-data-directory error. With an empty private directory it returned `Encoded client secret not present in DB`. Therefore merely having the executable was insufficient to discover the module command contract.

With coordinator authorization, a public `invite_code` response was fetched from the live disposable mixed federation and saved privately. There was no transport access secret. The following documented join shape succeeded with exit 0:

```sh
fedimint-cli --data-dir CLIENT_DIR join INVITE_CODE
```

The disposable federation ID was `8cc8c2595372f0fe5ac9327bad80fd5a96eadcaffd28688bd7d2223b780fc142`. The private initialized directory is `/tmp/minimint-upstream-build.2Clk9R/driver-help-client`. Its keys and invite are not copied into this document. This was joining/configuration initialization, not a payment. Test peers may subsequently stop; these endpoint addresses are not permanent infrastructure.

Both of these commands then returned module help with exit 0:

```sh
fedimint-cli --data-dir CLIENT_DIR module mintv2 -- --help
fedimint-cli --data-dir CLIENT_DIR module walletv2 -- --help
```

## Help-supported command shapes

In this table, `CLI` means the verified executable with `--data-dir CLIENT_DIR`. Names in capitals are argument placeholders. These are observed help contracts, not assertions about successful monetary execution or JSON response schemas.

| Purpose | Command shape observed in help | Remaining qualification |
| --- | --- | --- |
| Count local Mint notes | `CLI module mintv2 -- count` | Documented as counts by denomination; output schema not yet observed |
| Produce transferable ecash | `CLI module mintv2 -- send AMOUNT [--include-invite]` | Amount grammar/units, output encoding and retry semantics need validation |
| Reissue received ecash | `CLI module mintv2 -- receive ECASH` | Help says it reissues notes and returns amount; success/retry and output schema unverified |
| Withdrawal fee | `CLI module walletv2 -- send-fee` | Actual response schema and unavailable-fee behavior unverified |
| Deposit fee | `CLI module walletv2 -- receive-fee` | Actual response schema and unavailable-fee behavior unverified |
| Withdrawal | `CLI module walletv2 -- send ADDRESS VALUE [--fee FEE]` | `VALUE` may be `all`; numeric units and fee grammar not stated in help |
| Deposit destination | `CLI module walletv2 -- receive` | Returns the next unused receive address; actual response schema unverified |
| Await deposit | `CLI module walletv2 -- await-receive POSITION` | Help promises final receive state and the next event position; schema and timeout/retry semantics unverified |
| Event cursor before deposit destination | `CLI dev next-event-log-id` | Explicitly recommended by WalletV2 receive help; only its help was invoked |
| Public Wallet state | `CLI module walletv2 -- info total-value`, `block-count`, `feerate`, `pending-tx-chain`, `tx-chain` | Subcommand names observed; no state queries run during this task |
| Operation history | `CLI list-operations [--limit LIMIT]` | Default limit 10; output schema and module operation coverage unverified |

The `dev next-event-log-id` name above is an existing black-box client event-log query explicitly referenced by its Wallet help. It is not a source/vector bridge; no `dev` operation was executed during discovery. The prescribed cursor order is to obtain the position **before** `walletv2 receive`, then pass it to `await-receive`, and use the returned cursor for later waits.

Top-level restore help also exposes `restore --invite-code INVITE_CODE [--mnemonic MNEMONIC]`, falling back to global `--federation-secret-hex` when no mnemonic is supplied. No secret-export, backup, restore or recovery workflow was run. Restore help alone does not prove MintV2/WalletV2 recovery coverage.

## Remaining acceptance gates

A usable driver must still establish exact amount/fee units, JSON stdout and error contracts, private ecash handling, operation identifiers, retries/idempotency, and progress waiting. Then test deposit/issuance, second-deposit consolidation, transfer/reissuance between two separate durable client states, withdrawal and pending-change spending against real Core, plus restart/recovery. Fee observations must come from the specified real backend path; no fabricated fee votes or module-state edits are permitted to make the test pass.

The initialized candidate can support the next black-box experiments once the coordinator selects a live test federation and authorizes the concrete monetary operations. Preserve raw secrets/tokens in protected files and report only public transaction/session evidence. Do not mark the external driver functional merely because module help and joining succeeded.

## 2026-09-10 preparation after the mixed session run

The old help-discovery federation has stopped. Its initialized client database must not be reused as a client of a different fresh federation. The next driver lane needs a coordinator-owned, preserved live federation; public invite and endpoint paths; a private access-secret file when configured; two separate durable CLI directories; and the verified Core miner wallet/datadir. Keep the federation alive through driver completion and preserve its private state for restart tests. No new federation or monetary commands were launched during this preparation.

A fresh read-only check of the verified Core 31.1 executable found the existing regtest node available at height 101, out of initial block download. Its `estimatesmartfee 6` response still had an `errors` array and `blocks: 0`, without `feerate`. This is a current observation, not a permanent liveness guarantee.

Genuine estimator conditioning is a feasible experiment, rather than treating regtest as categorically unsupported. The [official RPC contract](https://bitcoincore.org/en/doc/31.0.0/rpc/util/estimatesmartfee/) ties missing estimates to insufficient observed transactions and blocks; the installed 31.1 help agrees. A [Bitcoin Core contributor's public guidance](https://github.com/bitcoin/bitcoin/issues/27415#issuecomment-1571967192) recommends real chain activity with transactions mined at varied fee rates for tests concerned with estimator behavior. That discussion also distinguishes the wallet-only fallback fee from an estimator result. Neither source specifies an exact bounded training workload that guarantees success.

Proposed coordinator-authorized experiment: use a dedicated Core wallet, establish a pool of confirmed self-owned outputs, then submit batches of independent confirmed-input self-transfers at explicit 1, 2 and 4 sat/vB. The public `fundrawtransaction` help supports `minconf: 1` and `fee_rate` in sat/vB; retain exact decimal strings. Confirm mempool admission before mining each batch, and poll the unchanged `estimatesmartfee 6` after each block. Stop on an actual positive estimate; otherwise stop after at most 60 batches, 1,200 transactions, or ten minutes, with a separately checked total fee budget. Any wallet/RPC/validation failure stops the experiment. This is a proposal only: do not run it while another mixed test owns the chain. Do not import estimator state, substitute a static JSON estimate, or change the daemon's absent-estimate policy to make this test succeed.

The reference help exposes `FM_WALLET_FEERATE_SOURCES` as JSON URLs with optional filters, but does not establish the numeric units, fallback/aggregation rules, or matching independent-adapter contract. It therefore does not yet identify a documented common alternative source. Q16 remains separate from whether real Core conditioning succeeds.

Read-only schema observations from the later mixed run are privately retained in `/tmp/minimint-schema-evidence-48267`. Reference guardians 2 and 3 returned identical raw chain-ID strings, public configuration objects, and Initial status encodings for requested indices 1 and 9 at capture time. These samples can support precise writer fixtures; they do not define all empty-current, future, or restored-state behavior.

### Prepared conditioning helper and diagnostic JSON comparison

The private executable `/tmp/minimint-estimator-conditioning.py` implements the proposed opt-in experiment with a 1,000,000-satoshi total fee ceiling. Syntax/help and exact decimal-to-satoshi checks passed; it has not been executed at this handoff. It verifies the Core CLI digest, uses the existing owned `interop` wallet, and counts its confirmed-output bootstrap against the transaction and mined-batch limits. Before broadcast it independently checks confirmed inputs and the signed transaction's exact input-minus-output fee, reserving that fee even if broadcast later times out. It verifies actual mempool fees and transaction inclusion in mined blocks. Any unexpected mempool contents stop mining. Execution requires `--execute` and coordinator confirmation that the concurrent mixed run is terminal.

Observed `client_config_json` is not the existing `client_config` serialization with another method name. In this one captured two-module profile:

- Top level has `global` and `modules`. `global` contains `api_endpoints`, `broadcast_public_keys`, `consensus_version`, and `meta`, whose observed shapes match those corresponding flattened fields in the covered client-config endpoint.
- Mint module `0` has direct fields `kind`, integer `amount_unit`, `fee_consensus` with integer `base`/`parts_per_million`, `tbs_agg_pks` mapping denomination-index strings to strings, and `tbs_pks` mapping denomination-index strings to peer-ID-string maps of strings.
- Wallet module `1` has direct fields `kind`, `bitcoin_pks` (peer-ID-string map of strings), string `descriptor`/`network`, integer `dust_limit`/`feerate_base`/`receive_tx_vbytes`/`send_tx_vbytes`, and `fee_consensus` with integer `base`/`parts_per_million`.
- The existing covered `client_config` API instead flattens the global fields at top level and uses module entries containing `kind`, `version`, and encoded `config` hex. The diagnostic sample has neither that per-module version wrapper nor opaque config hex.

The writer still needs to specify exact string encodings and meaning, integer ranges, optional/default fields, unknown-module treatment and whether the module diagnostic fields are stable API commitments. Two matching reference replies establish a useful literal fixture, not the complete normative contract. The observed opaque `chain_id` string is likewise not assigned an inferred hash algorithm here.

### Completed genuine estimator conditioning

After mixed run 48267 passed and every guardian process joined, the coordinator reviewed the helper and authorized its bounded execution. Live handle 37375 completed with exit 0 on 2026-09-10. The first positive `estimatesmartfee 6` result was `feerate: 0.00001000` BTC/kvB, `blocks: 2` (a genuine 1,000 sat/kvB estimate). The script stopped immediately; a separate read-only CLI call confirmed the same result.

The experiment accounted for 62 transactions and 28,695 regtest satoshis in total fees, including the previously owned pending transaction with its 1,000-satoshi fee. Five blocks were mined, advancing the live Core node from height 101 to 106. The final mempool was empty. The initial known pending transaction was mined separately before constructing the confirmed-input fanout because the original wallet had no confirmed spendable outputs left. All bootstrap transactions and blocks counted against the existing caps.

Private evidence is `/tmp/minimint-estimator-evidence-approved-20260910`. `events.jsonl` records the reserved exact fees, transaction IDs, mined inclusion and estimator observations; its SHA-256 is `fdad6cc50b0390337c13ea657625beacd8fcd45ff08c7cf002efec4352a203ea`. Summing its reserved/preexisting fee records independently reproduces 28,695 satoshis. `estimatesmartfee-cli-raw.json` preserves the actual CLI JSON with a numeric decimal rate; the Python event records serialize Decimal observations as strings to avoid rounding. The final block hash is `32f69d623f84c8ab5132ae7e7d12f4ebe958d79e2ae086f8e90db76e9121dfb6`.

This removes the immediate missing-real-Core-estimate prerequisite for a coordinated monetary run. It does not resolve Q16's behavior when estimates are absent, establish an indefinitely available estimate, or constitute a federation deposit/issuance/transfer/withdrawal test. No daemon vote policy, RPC result, estimator file or replicated module state was substituted.

## First live monetary diagnostic: discovery schema contradiction

A later fresh mixed federation (`0964f0161925d69c3c278b240c0debd949bab0853752644135675b3b1c5dec6a`) successfully ran the verified external CLI diagnostic stage for two separate private clients. Core's actual conservative estimate was 2,000 sat/kvB; the CLI returned numeric send/receive fees of 456/632, matching the configured 228/316 vbytes. Both Mint counts were empty; Wallet value was zero; the event cursor was integer zero, captured before the JSON-string deposit address. No API advertisement override was needed for those successful calls.

After review, the coordinator authorized the bounded first deposit. The signed Core transaction paid exactly 100,000 satoshis to the derived P2WSH address with an independently checked 330-satoshi Bitcoin fee. Its public outpoint is `441127e88b3be8f451e4ce5a82efc2c45efc98e249eda8a5df892d985c9b5c9e:1`, mined at height 107. Seven real blocks advanced Core through height 113. All four guardians subsequently reported consensus count 108, discovery index 0 with value 100,000 and `spent:false`, and no federation wallet. Mint recovery counts remained zero: this establishes discovery, not a successful claim or issuance.

The source-free captures exposed a direct discrepancy with WAL-016. Reference guardians 2 and 3 serialized the discovery `outpoint` as a JSON string `"441127e88b3be8f451e4ce5a82efc2c45efc98e249eda8a5df892d985c9b5c9e:1"`. Our guardians serialized the explicitly specified object `{"txid":"441127e88b3be8f451e4ce5a82efc2c45efc98e249eda8a5df892d985c9b5c9e","vout":1}`. WAL-016 gives the object form both in prose and its discovery example. The external CLI reported failed discovery fetching; its receipt wait was still pending at this observation. The same CLI also logged unavailable `chain_id` responses from our guardians, which is a separate unresolved endpoint gate.

Private raw evidence is under `/tmp/minimint-mixed-evidence-187076-1789046616540766519`: `first-deposit-peer{0,1,2,3}-module_1_output_info_slice.json`, corresponding block-count/wallet/recovery captures, and `driver-private` command output files. The deposit-stage script digest reviewed for execution was `1d002c9480b8c1375dc8a96bad218a0b79f99acf36e39b90de74d0e68bc659c6`; the original diagnostic digest was `282451ab6b4cbec9d5e18c8afba97cc4a87fe50a33acfb89424a2bfb884cf58f`. No raw client keys, tokens, private shares or invites are copied here. Resolve the endpoint contradiction explicitly; these observations do not justify changing Bitcoin consensus encoding, transaction validation or module storage.

### Intentional stop and recovery limits

The coordinator intentionally terminated the harness-owned driver process group at the WAL-016 conflict. Harness handle 88649 finished with exit 101 after 817.63 seconds; guardian cleanup completed and all API listeners closed. The final observed state remains an unclaimed discovered deposit and zero Mint recovery records, not issuance. The destroyed guardian fixtures cannot be resumed merely by reopening the retained client databases. No new funding or JSON schema change was made while the written-rule versus observed-baseline decision remained unresolved.

Execution-time source snapshots were missing in that run. After the stop, the still-current deposit-stage source was rehashed as `1d002c9480b8c1375dc8a96bad218a0b79f99acf36e39b90de74d0e68bc659c6` and copied into the private evidence directory's `retrospective-driver-source` folder. This is a **retrospective** exact-digest capture, not an execution-time snapshot. The original `282451ab6b4cbec9d5e18c8afba97cc4a87fe50a33acfb89424a2bfb884cf58f` diagnostic source snapshot was not preserved and is not claimed recoverable from its digest.

Future driver executions now copy the initial source bytes into private `driver-sources/<sha256>.py` and execute that verified, owner-read-only snapshot. A reviewed resume checks the control's exact digest, copies those same bytes and executes only the copy. The exclusive initial manifest binds the original owned entry path, federation ID, Linux boot ID and initial monotonic deadline; a resume cannot change federation, extend that deadline, or reinterpret it after a host reboot. Snapshot paths and digests are retained in private progress evidence. File mode 0400 is an owner-read-only operational safeguard, not a tamper-proof filesystem claim against the same OS account.

The driver also persists command sequence reservations before child launch, so an interrupted receipt wait cannot overwrite partial output files when later retried. Deposit amount and Bitcoin fee budgets are reserved durably before broadcast; a timeout with an ambiguous broadcast result must never cause automatic re-funding. The script still has no accepted resume path for `first_deposit_reserved` or `first_deposit_mined`: these fail closed until an await-only path is separately reviewed.

Proposed future await-only recovery requires preserved guardian and client state for the **same** federation, the same manifest/remaining deadline, and the saved deposit outpoint, script, value, canonical block hash/height and event cursor. Recheck real Core canonical inclusion and burial, then run only the verified external CLI's `await-receive` with the saved cursor and collect read-only state. It must contain no funding, broadcast or mining command. A `first_deposit_reserved` ambiguity needs separate evidence reconciliation before it can enter this path. An expired deadline or a new harness requires an explicit, separately reviewed state-import contract with fresh limits; do not silently extend the old deadline. None of these proposals recovers the intentionally destroyed mixed fixture described above.
