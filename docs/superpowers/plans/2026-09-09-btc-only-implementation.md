# BTC-only minimint-ng Implementation Plan

> **Superseded on 2026-09-10.** Use the [daemon-only implementation plan](2026-09-10-fedimintd-implementation.md). Client implementation tasks below are historical and are no longer authorized scope.

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This document is the staged implementation roadmap; tasks blocked on missing protocol definitions must be expanded into code-level test-first plans after the spec writer supplies those definitions. Do not fill gaps using Fedimint code.

**Goal:** Independently implement the BTC-only guardian/client subset needed to run two minimint-ng and two pinned fedimintd guardians as a 3-of-4 regtest federation.

**Architecture:** A single guardian process combines fixed Mint/Wallet dispatch, a transactional ordered executor, the exactly pinned AlephBFT engine, mutual TLS peer transport, and WebSocket APIs. A narrow independent client exercises deposits, e-cash issuance/reissuance, withdrawals, and recovery. The engine reuse decision is approved; adapter, recovery and mixed-setup verification remain required.

**Tech Stack:** Proposed Rust single package, transactional embedded storage, async networking, ordinary Bitcoin/secp256k1/BLS12-381/TLS/WebSocket libraries, Python standard-library process harness, Bitcoin Core regtest, and a pinned fedimintd executable used only as a black box. Library selection and exact versions remain an implementation preflight decision; the authorized exact AlephBFT dependency is the sole Fedimint implementation exception; no external protocol modules.

---

## Inputs, boundaries and decisions

Read the [design](../specs/2026-09-09-btc-only-design.md) and [spec-writer handoff](../../spec-writer-questions.md). Protocol links below refer to the supplied [spec](../../../spec/README.md). Its reviewed repository revision is `06277f7e8e2c5cde5b1fe9b768f37f987e3c0c4c` (updated from `be0a339c812e099d74064e02e22b9616929ac6e3`); its implementation baseline is `0c316439d60b5a08eea26fab216780eb893c45bf`.

The original planning turn produced documents only. Implementation began on 2026-09-10; current completed and pending scope is tracked in [implementation status](../../conformance.md). No federation has been run. The user's later mixed-federation experiment is the acceptance target. Preserve the existing `spec/` checkout and do not read its implementation bridge or follow implementation source links. Published vector JSON may be consumed as data during implementation; retain provenance and do not regenerate it through Fedimint code.

Approved 2026-09-10: use the exact baseline AlephBFT crate. Keep built-in `mintv2` + `walletv2` only. Implement small utilities locally; select maintained ordinary libraries with preference for implementations absent from the baseline lockfile, checking native and transitive overlap. Record unavoidable shared failure points and conditional impact rather than fabricated bug probabilities. The baseline Cargo.lock may be fetched; implementation source remains excluded. Exactly two module kinds are allowed in generated configuration; configured instance IDs still drive parsing/routing. Under ordinary ascending generation for this selected set, Mint is ID 0 and Wallet ID 1; test decoding with reassigned IDs rather than hard-code them.

Core consensus is 2.1; both module consensus versions are 1.0. No claim of all-four-module profile conformance. No Lightning, Meta module, gateways, asset extension, Iroh, generic plugins, live upgrade framework, general UI, or guardian archive interchange. The core metadata map and Mint amount-unit field remain mandatory.

Use ordinary setup and consensus parameters initially, including R=3600; do not assume R=200 or the Wallet test-only block advance cap can be enabled independently on one implementation. Any accelerated profile must be explicitly documented and identical across peers. Setup needs all four; steady-state thresholds require three distinct IDs.

## Review update: 06277f7

The spec writer supplied definitions and small independently calculated fixtures, not an executed mixed federation. The local spec checkout now pins the requested commit. The [question review](../../spec-writer-questions.md#review-of-spec-update-06277f7) is the current disposition.

Concrete corrections for implementation:

- Setup uses normalized release 0.13.0, explicit TCP selection, R=3600 and local round delay 50 ms. The operator recipe leaves test-environment switches unset; regtest does not imply test consensus parameters.
- Mint uses 42 serial G2 DKGs, Wallet one separate key exchange. Disabling Mint base fees does not disable Wallet's ordinary 100000-msat base fee.
- Four-peer Wallet stored sizes are 228/316 vB, retained after signatures. Native module JSON is distinct from core RPC_HEX wrappers. Bitcoin outpoint vout and Fedimint out_idx are distinct fields.
- Wallet checks low-S but not low-R. Witnesses use the first q accepted guardian lists, sorted by each input's tweaked keys. Do not choose local signers after the fact.
- Fee calculation asserts pending count <=32 before checking the rate; accepting a transaction at 32 can create 33. Do not invent a graceful consensus rejection. Keep tests of this boundary isolated.
- Audit formulas apply within their intended signed-64-bit domain; only aggregate addition has the stated portable checked-overflow contract. Update any broader overflow assumptions accordingly.
- NET-009 requires durable exact-byte backup appends before acknowledging success and concatenated committed bytes on read. CON-010 explicitly treats phase, cursor and signature/proposal maps as reconstructed application state. Internal agreement recovery remains delegated to NET-014.
- VER-008 forbids advertising 0.9 while omitting earlier endpoints. The relationship between the minimal harness method list and omitted 0.0 endpoints remains a writer question; a reduced harness is not automatically a conforming API server.

## Approved dependency and evidence policy (2026-09-10)

Use [dependency review](../../dependency-review.md), [machine-readable inventory](../../dependency-inventory.json), and [spec pitfalls](../../spec-pitfalls.md) throughout implementation. Dependency identity checks are executable in `tools/dependencies.py`; they do not substitute for advisory, feature, native-code or build-script review. Add each new suspected spec issue or easy-to-misread rule with evidence and an explicit status.

## Proposed file map

All paths below are relative to the workspace root; the status document distinguishes existing foundation files from proposed files. Tests use integration targets named after their file stems. Keep implementations split when a responsibility becomes large.

| Files | Responsibility |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `src/bin/minimint-ng.rs`, `src/bin/minimint-ng-client.rs` | Package, pinned dependencies, daemon and test-client entry points |
| `src/codec/{mod,bigsize,common,scale,legacy,rpc}.rs` | Separate binary dialects, bounded decoding, API wrappers |
| `src/crypto/{mod,secp,bls,seeded,derive}.rs` | Standard primitive adapters and specified Fedimint constructions |
| `src/config/{mod,identity,versions}.rs` | Config/commitments, invites, version records/discovery |
| `src/storage/{mod,schema}.rs` | Transactions, state namespaces, snapshots, durable outbox |
| `src/core/{mod,transaction,session,audit}.rs` | Ordered validation, atomic execution, replay, history/signatures |
| `src/modules/{mod,mint,wallet}.rs` | Closed dispatch and payload/config/state definitions |
| `src/modules/mint/{issuance,recovery}.rs` | Notes, spent tracking, share/recovery indexing |
| `src/modules/wallet/{chain,fees,bitcoin,signatures}.rs` | Discovery, votes/package fees, deterministic construction, witness assembly |
| `src/net/{mod,tls,peer,envelope}.rs` | Authenticated peers, reconnect policy and frame codecs |
| `src/setup/{mod,admin,dkg,generate}.rs` | Setup code exchange, state, common DKG, module invocation sequencing |
| `src/agreement/{mod,config,network,data,keychain,backup,runtime}.rs` | Pinned-engine interfaces, durable restart boundary and finalization adapter |
| `src/api/{mod,core,modules,setup}.rs` | WebSocket transport, authentication, scoped methods and long polls |
| `src/client/{mod,join,operations,secrets,recovery}.rs` | Quorum reads, issuance, BTC operations and durable uncertainty handling |
| `src/bitcoin/{mod,rpc}.rs` | Bitcoin backend adapter and post-commit rebroadcast |
| `tests/*.rs`, `tests/fixtures/*` | Independent byte vectors, transition traces, crypto and crash checks |
| `tests/interop/{run,control,client,assertions}.py`, `tests/interop/profile.json` | Four-process regtest harness and its explicit deployment profile |
| `docs/interop/{runbook,results}.md`, `docs/conformance.md`, `docs/dependencies.md` | Reproduction, evidence, exclusions and dependency decisions |

Avoid a general framework: two concrete module arms share transaction context and typed amount/fee/error results. Storage schema is local; protocol encodings are not the database encoding by default. External observers/broadcast retries cannot mutate consensus state outside the ordered executor.

## Dependency and readiness graph

```text
P0 provenance/profile → P1 codecs → P2 crypto/config
                                     ├→ P3 storage/core → P5 Mint ──────┐
                                     │                 → P6 Wallet ───┤
                                     ├→ P4 TLS/setup                  │
                                     └→ P7 agreement → P8 sessions ──┤
                                                                      ↓
                                                        P9 API/client → P10 mixed test
```

Spec update 06277f7 supplies the ordinary-domain definitions for Q03–Q07 and launch/version/legacy-hash answers for Q11. P2–P6 and endpoint schema work can now proceed using MINT-012–015, WAL-011–017, API-009 and VER-008. Their full comparison evidence remains open. Q06 retains an extreme-arithmetic boundary; Q11 retains a minimal-API conformance question. P7/P8 use the user-approved pinned engine; internal protocol restatement is no longer a blocker. Public API documentation may guide adapters without consulting implementation source. P10 requires the actual built baseline artifact and completed prior gates. See the current status and focused follow-ups in the handoff; original task references to writer answers now mean the supplied amendments except for these remaining gaps.

For each implementation slice below: introduce one named fixture/test, run the named target and verify the intended failure, implement the smallest matching behavior, rerun to pass, and commit only its affected files after repository setup. Add independent expected bytes/state, not assertions computed by the same encoder under test. Commands below are future checks, not checks run during planning. The current workspace root has no Git repository; decide/init its implementation repository during P0, keeping `spec/` separate.

## P0 — Freeze provenance, subset and executable profile

**Files:** `docs/conformance.md`, `docs/dependencies.md`, `tests/interop/profile.json`, `Cargo.toml`, `src/lib.rs`, `src/bin/minimint-ng.rs`, `src/bin/minimint-ng-client.rs`.

- [ ] Record the two pinned revisions, the selected two-module subset, all exclusions, and requirement-to-test status. Keep proposed, implemented, compared, and mixed-tested as distinct statuses.
- [ ] Provision and pin the development environment before running build/test commands. At planning time, `cargo`, `rustc`, `python3`, `bitcoind`, and `bitcoin-cli` are absent from PATH; Nix is available. Record tool versions and the reproducible environment entry command in the runbook. Do not treat the future commands below as runnable in the current shell yet.
- [ ] Obtain Q11's executable identity, checksum, release string and launch recipe. Record four guardian identities, endpoint scheme, network, module set, ordinary round parameters and whether base fees are disabled. Do not fabricate fedimintd flags.
- [ ] Select ordinary libraries by checking needed primitive/serialization support; reject dependencies supplying Fedimint modules; permit only the approved exact agreement engine and its pinned closure. Pin the resulting lockfile and explain each dependency. Verify secret arithmetic uses suitable library operations rather than test-only arithmetic code.
- [ ] Create the package with two initially diagnostic executables and explicit unsupported-configuration errors. Set up the implementation repository without changing the spec repository.
- [ ] Verify `cargo check --locked` builds only the new package; review `cargo tree --locked` for prohibited implementation dependencies. This gate establishes a build, not protocol compatibility.

## P1 — Exact codec boundaries

**Files:** `src/codec/*.rs`, `tests/codec.rs`, `tests/fixtures/codec.json`.

**Authority:** ENC-001–014, NET-003/005–007, API-001/003, TX-001–003.

- [ ] Add `bigsize_boundaries`: 252→`fc`, 253→`fd00fd`, 65536→`fe00010000`; reject `fd00fc`, truncated suffixes and field-width overflow. Add independent Bitcoin CompactSize and SCALE cases proving they differ from BigSize.
- [ ] Add enum, option, result, strict map/set, fixed-array and dynamic-module vectors. Reject duplicate/descending keys and trailing bytes at whole-value boundaries; preserve unknown variants only where explicitly allowed.
- [ ] Add RPC_HEX/RPC_BASE64 length-prefix/one-element-array tests and direct dynamic config tests. Parse u64 JSON values without floating-point rounding. Include the eight-byte nonce and signature-excluded transaction commitment.
- [ ] Add empty transaction encoded bytes `00000000000000000000000100`; its ID hashes the first ten zero bytes. Assert witness changes preserve the ID, and nonce/input/output routing changes affect it.
- [ ] Implement legacy-send/common-first-receive priority and SCALE's separate trailing-byte policy using Q10 fixtures. Exercise the 8,388,608-byte TLS body limit and the 50,000-byte attached batch limit independently.
- [ ] Run `cargo test --locked --test codec`; accept only exact expected bytes plus intentional negative outcomes. The baseline empty transaction is a serialization case, not a funded transaction scenario.

## P2 — Crypto, identities and configuration

**Files:** `src/crypto/*.rs`, `src/config/*.rs`, `tests/crypto.rs`, `tests/config.rs`, `tests/fixtures/{crypto,config}.json`.

**Authority:** CRY-001–008, CFG-001–007 as applicable, VER-001–007, REC-001–004.

- [ ] Add scalar/point decoding and BIP340 signature cases; distinguish compressed keys from x-only verification and little-endian BLS scalars from big-endian secp scalars.
- [ ] Implement the specified ChaCha20-driven G1 sampling, root/sign consumption and cofactor clearing. Verify the Mint SHA-256 mapping against supplied vectors; do not replace it with a generic hash-to-curve call.
- [ ] Verify valid shares and aggregate/unblind for each 3-of-4 subset; reject duplicate IDs, wrong keys, insufficient shares and altered signatures. Respect specified zero/infinity decoding rather than inventing consensus restrictions; Q12 supplies broader evidence.
- [ ] Encode client/server configs with nested module IDs, amount unit zero, endpoint-map federation ID, optional broadcast keys and separate full-config/setup commitments. Gate Wallet config layout on Q04 and legacy diagnostic hash on Q11.
- [ ] Implement invite Bech32m and custom low-bit-first base32, setup record sorting, unique-major API advertisements and specified version selection. Use simple URLs in first deployment while tracking general URL normalization exclusions.
- [ ] Implement raw-root/default-wallet derivation and compare fixed roots/module IDs to spec vectors. Persist derivation context so later recovery cannot silently choose another hierarchy.
- [ ] Run `cargo test --locked --test crypto --test config`. Require exact config bytes/hashes, independent signature verification, and all selected share subsets. Do not require deterministic Schnorr signature bytes when protocol-valid randomness is permitted.

## P3 — Durable ordered transaction executor

**Files:** `src/storage/*.rs`, `src/core/{mod,transaction,audit}.rs`, `src/modules/mod.rs`, `tests/transactions.rs`, `tests/storage.rs`.

**Authority:** TX-004–009, CON-005/006; Q05/Q06.

- [ ] Define atomic transaction context and separate replicated/local namespaces. Accepted IDs, output module IDs, module mutations and recovery records commit together. APIs use discarded tentative transactions.
- [ ] Add `input_overflow_precedes_signature_check`, `duplicate_keys_require_duplicate_witnesses`, `failed_later_output_rolls_back_all_modules`, and `submission_does_not_commit`. Fixtures contain exact initial/final state and first error; use Q05's actual error enums.
- [ ] Implement the stated stateless/input/signature/output/funding sequence, with checked amounts/fees at the specified points. Accept excess funding at 2.1; reject excess under earlier accounting. Encode overflow imbalance as three zero amounts.
- [ ] Add accepted-ID tests: duplicate consensus execution rejects; API retry returns prior success even with a changed witness. Route arbitrary configured instance IDs through the closed two-kind registry.
- [ ] Implement Mint liabilities and current-wallet assets under MINT-014/WAL-015 and checked signed-64-bit aggregate addition with fatal total-negative/aggregate-overflow behavior. Do not claim portable per-module overflow handling outside the specified intended domain. Do not proceed to monetary integration with a placeholder or disabled audit.
- [ ] Crash after writes but before commit and after commit before notification; reopening must show either complete old or complete new state. Persist post-commit Bitcoin work through an outbox.
- [ ] Run `cargo test --locked --test transactions --test storage`. Once modules exist, run the rollback tests with real Mint/Wallet transitions, not only fake test modules.

## P4 — Authenticated transport and fresh setup

**Files:** `src/net/*.rs`, `src/setup/*.rs`, `tests/transport.rs`, `tests/setup.rs`, `tests/dkg.rs`.

**Authority:** NET-001/003/004, SET-001–008; Q03/Q04/Q10/Q11.

- [ ] Implement TLS framing, exact configured certificate-to-peer mapping, requested-peer verification, and lower-ID reconnect initiation. Test wrong certificate, wrong expected peer, invalid frame and replacement connection. Use Q10's valid certificate profile.
- [ ] Implement setup admin states/authentication, code encoding, duplicate code idempotence, typed record ordering and release normalization. Put federation-wide optional parameters on only one guardian; repeated supplied fields are rejected even if equal.
- [ ] Assign peer IDs only after collecting all codes, then compare the initial map checksum. Use separate broadcast and transport keys. Exchange broadcast public keys with the exact setup envelope.
- [ ] Implement common DKG hash→commitments→private-share transitions, q=3 degree-two coefficients, coordinates peer+1 and all-n completion. Test duplicate/out-of-order data, invalid share and missing peer; never finish with only three participants during setup.
- [ ] Execute 42 sequential G2 DKGs for denominations 0–41, then one independent Wallet compressed-public-key exchange, with no intervening module messages. Use WAL-011/012 defaults (four-peer send=228 vB and receive=316 vB; Wallet fees remain ordinary even if Mint base fees are disabled), then compare final server consensus checksums on all four peers. Do not infer module invocation sequencing from the generic DKG rules.
- [ ] Run `cargo test --locked --test transport --test setup --test dkg`. Compare full public transcripts and config hashes; exclude private production keys from artifacts. A start_dkg RPC acknowledgement alone is not completion.

## P5 — Mint issuance, spending and recovery data

**Files:** `src/modules/mint.rs`, `src/modules/mint/*.rs`, `tests/mint.rs`, `tests/fixtures/mint.json`.

**Authority:** MINT-001–011; Q03/Q05/Q06/Q07/Q12.

- [ ] Encode configured denominations 0–41 and amount_unit zero; select keys by configuration membership. Verify notes under the Mint SHA-256 seeded mapping and distinct denomination keys.
- [ ] Add `nonce_spent_across_denominations`, `duplicate_blinded_message_overwrites_lookup`, `fee_saturates_before_division`, and `failed_transaction_leaves_no_share_or_recovery_entry`.
- [ ] Implement issuance counters, spend set, output-location and blinded-message share indexes, ordered recovery records and snapshot queries. Preserve omission behavior for missing issuance shares and errors for missing recovery shares.
- [ ] Add recovery range/hash/count tests, hash verification before single-peer slice use, and matching-count/hash quorum tests. Use Q07's actual JSON representation in endpoint tests.
- [ ] Run `cargo test --locked --test mint`. Require state and audit agreement with independent nonempty fixtures; do not treat mapping/interpolation tests alone as issuance validation.

## P6 — Wallet chain state and Bitcoin spending

**Files:** `src/modules/wallet.rs`, `src/modules/wallet/*.rs`, `src/bitcoin/*.rs`, `tests/wallet.rs`, `tests/bitcoin_transactions.rs`.

**Authority:** WAL-001–010; Q04/Q05/Q06/Q08/Q09.

- [ ] Add block-vote cases (third-highest count) and fee-vote cases (third-lowest present rate), with fewer than three votes, absent votes, decreasing fee rates, and duplicate/non-increasing rejection. Keep proposer floor/cap separate from received-item validation.
- [ ] Add initial regtest scan and `[a,b)` cursor fixtures, backend wait at b+6, matching block-hash validation, filter matches and non-P2WSH discovery gaps. Use Q09's explicit height/count timeline.
- [ ] Implement package-fee arithmetic over pending unsigned and signed-unconfirmed transactions, rounding and saturation, quote changes and Q09's pending-bound behavior. Use the agreed vsize definition from Q04.
- [ ] Implement claimant/change tweaks, sorting of tweaked keys, 3-of-4 P2WSH, first-deposit initialization, consolidation and withdrawal. Assert exact unsigned bytes/txids and first-deposit fee accounting from Q08/Q06.
- [ ] Verify each input's ECDSA share, distinct guardian lists and script-key-order witness assembly; advance pending change on construction. Broadcast only after commit and retain rebroadcast work across failures/restarts.
- [ ] Test missing/claimed deposit, bad claimant authorization, dust destination/change, stale mining fee and arithmetic errors, including rollback with Mint inputs/outputs.
- [ ] Run `cargo test --locked --test wallet --test bitcoin_transactions`. Then use a regtest backend for actual transaction acceptance; fixture-only success does not establish Bitcoin validity.

## P7 — Pinned AlephBFT adapters

**Files:** `src/agreement/{mod,config,network,data,keychain,backup,runtime}.rs`, `tests/agreement_adapter.rs`, `tests/agreement_restart.rs`.

**Authority:** NET-005–014, CON-010; user authorization on 2026-09-10. Use `fedimint-aleph-bft = "=0.36.0"`, default features disabled, with active baseline package/source/version/checksum identities. Do not port or rewrite its internals and do not inspect Fedimint implementation source.

- [x] Seed and check the exact active dependency resolution from the allowed baseline lockfile; retain metadata provenance. Cargo may prune unused baseline features, not change versions of active dependencies.
- [ ] Read public API signatures/documentation to implement the network, data-provider/finalizer, hash/keychain, spawn and backup interfaces. If the public contract is insufficient, ask for that specific interface contract rather than read implementation internals.
- [ ] Supply the specified common-byte-prefixed hashes and broadcast-key-tagged signatures, authenticated peer mapping, legacy transport envelope, and included-data limits.
- [ ] Map agreed n/local ID/session/R+1000 and exact delay/retry parameters. Exercise lifecycle cancellation and await termination before backup cleanup.
- [ ] Implement exact-byte durable backup append acknowledgement and ordered replay reads using the selected storage adapter. Never reconstruct agreement backup from accepted application records.
- [ ] Forward every finalized unit including absent data, creator and round in engine order. Exercise session boundary, malformed adapter payload and backpressure behavior.
- [ ] Run four in-process engines with independent adapters and deterministic test inputs, including dropped/reordered transport and one-node restart; compare emitted order and resumed history. Tests remain isolated local simulations until the mixed-process harness exists.
- [ ] Run `cargo test --locked --test agreement_adapter --test agreement_restart`; importing/compiling the crate alone does not satisfy this task.

## P8 — Sessions, history, catch-up and crash replay

**Files:** `src/core/session.rs`, `tests/sessions.rs`, `tests/session_restart.rs`.

**Authority:** CON-001–009, NET-009; Q02.

- [ ] Wire every finalized unit to the session engine in emitted order. At first unit round >=R, stop before processing its data. Reject an entire undecodable batch but continue after an individual validly decoded item rejects.
- [ ] Add exact accepted-item Merkle/header/signing vectors, including empty, singleton and odd leaf count. Preserve accepted creator attribution.
- [ ] Implement signature phase, three distinct signatures and exactly-q guardian completion/adoption. Separately test generic verifier with four valid signatures and with an invalid extra signature.
- [ ] Add prefix replay and adoption cases: identical stored items skip execution; mismatch during local replay does not advance index; divergent/shorter adopted history is fatal. Retrieve module-bearing history through the configured-decoder federation API.
- [ ] Stop agreement before atomic completed-outcome persistence/recovery cleanup. Test restart at each transaction boundary and session transition. Never wait for the baseline's inactive direct signature/index broadcasts.
- [ ] Run `cargo test --locked --test sessions --test session_restart`; compare state, accepted sequence, header and replay side-effect counts.

## P9 — APIs and narrow independent client

**Files:** `src/api/*.rs`, `src/client/*.rs`, `tests/api.rs`, `tests/client.rs`, `tests/recovery.rs`.

**Authority:** API-001/003–008, CFG-005, VER-001–007, MINT-006–011, WAL-010, REC-001–004/010; Q05/Q07/Q11.

- [ ] Implement required setup/config/version, submission/acceptance, output and signed-session endpoints plus all Mint/Wallet endpoints. Use WebSocket JSON-RPC's single auth/params envelope and exact dynamic wrappers. Separate transport Basic auth from administrator auth.
- [ ] Define a capability/endpoint table from Q11; do not advertise unsupported minor-level behavior. Record omitted backup/metadata/diagnostic methods explicitly and test that baseline startup does not require them.
- [ ] Test submission waits for accepted state, validation errors inside successful outer responses, malformed transactions as outer errors, and absent generic outcomes (single-query error versus batch null).
- [ ] Implement invite joining with authenticated endpoint-map hash followed by three matching full configurations. Test changing responses, duplicate peer identity and insufficient agreement. Verify complete signed history from one peer only using authenticated keys.
- [ ] Implement durable client operations: fresh raw root → filtered deposit address → deposit claim with Mint change → three verified share lists → spendable notes. Mint outputs use specified tweak grinding and derivation. Client-generated transactions respect 49,968-byte limit without imposing it as an extra consensus rule.
- [ ] Implement portable-token export/import and recipient reissuance before receipt finality; preserve unknown token fields and actual instance selection. Implement withdrawals with explicit fee/change calculation and separate acceptance/broadcast/confirmation statuses.
- [ ] Recover Mint from agreed recovery counts/hashes/shares and Wallet by matching derived filtered addresses. Test false-positive filters, spent notes and fresh database restoration; distinguish unresolved operations from zero balance. BIP39 UI and encrypted backup are deferred.
- [ ] Run `cargo test --locked --test api --test client --test recovery`. Verify persisted transaction IDs survive timeouts/restarts and retries do not create a second payment.

## P10 — Four-process mixed federation acceptance

**Files:** `tests/interop/*.py`, `tests/interop/profile.json`, `docs/interop/runbook.md`, `docs/interop/results.md`.

Implement the harness interface below; it is a proposed command, not an existing script or an invented fedimintd interface. The harness resolves actual daemon arguments from Q11's documented recipe. Use fresh temporary directories and regtest-only funds.

```sh
python3 tests/interop/run.py --profile tests/interop/profile.json --scenario full
```

- [ ] Preflight artifact hashes, normalized release, Bitcoin regtest readiness, all four unique peer endpoints, selected module kinds and transport. Persist a public manifest. Keep authentication secrets and private setup material out of logs.
- [ ] Launch one Bitcoin Core regtest backend and four separate guardians, initially two of each implementation. Use unique names yielding alternating implementation types in peer-ID order. Exchange setup codes through each daemon's actual API; only one code supplies global options. Require four-way DKG and identical final checksum/client configs before proceeding.
- [ ] Advance through at least two completed sessions. Compare accepted-item lists with creators and signed headers across all four; verify each certificate independently. Transaction acceptance can precede session completion, so wait for the correct event at each assertion.
- [ ] Create client A's filtered deposit address, send regtest BTC, mine until the specified consensus scan includes it, and claim into verified Mint notes. Assert first deposit creates no consolidation. Repeat a deposit to exercise consolidation and pending change.
- [ ] Transfer A→B via portable token and reissuance, then B→A. Check balances including every fee. Attempt a repeat spend through the normal client API and require rejection without state change. Retrying an accepted transaction must report the same acceptance.
- [ ] Withdraw to a regtest destination, verify unsigned txid and resulting Bitcoin transaction, require three valid input signatures and actual confirmation. Exercise a second withdrawal spending pending change where the documented fee/chain rules allow it.
- [ ] Stop one guardian at a time, covering all four IDs across separate restored test states. Require new Mint issuance, a withdrawal signature quorum and completed-session progress from the other three. Thus both 2 minimint-ng + 1 fedimintd and 1 minimint-ng + 2 fedimintd subsets must work.
- [ ] Restart each stopped guardian and require signed API catch-up, equal completed headers/state and no duplicate execution. Inject local process termination at pending-item/signature/completion checkpoints where supported; verify resumed nodes do not fork their own coordinates.
- [ ] Stop two guardians; over a documented observation window require no new session certificate, completed three-share issuance, or newly threshold-signed withdrawal. Two peers may still observe old accepted state or broadcast an already signed transaction; those do not violate the assertion.
- [ ] Restore all four, verify progress resumes, and restore a client into a fresh database from its raw root. Confirm recovered spend authority and pending-operation distinctions. Repeat the profile with peer ordering permuted so IDs are not coupled to implementation.
- [ ] Export redacted per-step request/response records, artifact identity, public config hashes, signed histories, Bitcoin txids, initial/final balances and fees, timeout settings, process-stop/restart schedule and pass/fail outcomes. Do not compare local database bytes across implementations.

A single cooperative mixed run is a useful milestone, not Byzantine conformance evidence. Complete isolated agreement/admission tests remain required. This harness must never paper over checksum/order differences, silently reduce thresholds, substitute a sequencer, or start a different module profile when the intended one fails.

## Review and acceptance checklist

- [ ] Every in-scope requirement in documents 01–11 (excluding Lightning) and applicable derivation/recovery requirements in 14 maps to a fixture, test, or explicit exclusion in `docs/conformance.md`.
- [ ] Apply the supplied Q03–Q07 amendments and Q11 operator recipe. Verify Q01/Q02 adapters/recovery, resolve Q06 numeric-domain limits and Q11 minimal-API obligations before dependent claims; complete comparison evidence remains required.
- [ ] Codec/crypto/setup/state/admission/restart tests pass against independent expectations; supplied comparison vectors retain provenance.
- [ ] All four mixed participants agree on setup and completed-session commitments and complete the BTC workflow with exactly the selected two modules.
- [ ] Each three-node survivor set progresses; two-node remainder does not create new quorum results; both implementations restart/catch up successfully.
- [ ] `docs/interop/results.md` states exactly which scenarios ran and which did not, with reproducible commands and public artifacts.

Setup and ordinary module definitions are now supplied. The agreement dependency policy is resolved; adapter and mixed-federation validation remain substantial work. Track progress by these gates. Codec-only success, an all-minimint-ng run, or three identical responses from incorrectly mapped peer identities does not satisfy the user's mixed-federation target.
