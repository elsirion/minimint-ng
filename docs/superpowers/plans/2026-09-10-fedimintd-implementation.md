# BTC-only fedimintd Implementation Plan

> **For agentic workers:** Use Superpowers subagent-driven development. Run independent tasks in parallel as explicitly requested by the user, with one coordinator and at most three workers. Complete the scope and interface gate before implementation, then integrate and review each bounded task. Checked boxes record accepted implementation evidence. Unchecked boxes require reconciliation against the current conformance ledger; they do not imply that no component code exists.

**Goal:** Build a new guardian daemon in this workspace that implements the supplied BTC-only Fedimint specification and can participate in a fresh 3-of-4 federation alongside the pinned upstream fedimintd.

**Architecture:** One Rust package and one product executable, `fedimintd`, with statically registered Mint v2 and Wallet v2. A single ordered executor owns replicated changes; an exactly pinned AlephBFT engine supplies ordering through independent adapters; persistent storage, Bitcoin RPC, TLS peers and WebSocket APIs supply the surrounding daemon.

**Tech stack:** Existing Rust/Nix foundation, exact `fedimint-aleph-bft = 0.36.0` with default features off and baseline transitive identities, dependency-free small codecs/utilities, and reviewed libraries for substantial crypto, TLS, storage and async/JSON needs. Specific ordinary library candidates are not selected merely by appearing in the dependency review.

---

## Scope, source boundary and current state

This is the **current guardian-only plan**, superseding the [2026-09-09 guardian/client roadmap](2026-09-09-btc-only-implementation.md). This revision answers the user's request for a plan and summary. Existing implementation work is preserved; this planning handoff does not assert that the daemon is finished. Current component evidence is maintained in [the conformance ledger](../../conformance.md).

Authority is specification revision `06277f7e8e2c5cde5b1fe9b768f37f987e3c0c4c`, describing implementation baseline `0c316439d60b5a08eea26fab216780eb893c45bf`. Read numbered specification documents, public test-vector data, [the operator handoff](../../../spec/verification/two-module-handoff.md), and public library interfaces. Do not inspect Fedimint implementation source or the spec's implementation-vector bridge. The baseline Cargo.lock is explicitly allowed for dependency comparison. Exact AlephBFT reuse is approved; its internal protocol does not need to be reimplemented.

The workspace already contains the new guardian executable and substantial protocol, storage, module, setup, networking and server implementations. Preserve these components; complete remaining schema and evidence gaps. The latest assembled validation and exact test counts are recorded in the conformance ledger.

Four-new-daemon and mixed 2+2 tests have passed. Healthy monetary evidence independently verifies deposits, consolidation, reissuance and confirmed pending-change withdrawal. A fresh mixed process run passed in 1219.20 seconds with every monetary survivor set and restarted guardian verified. Q17’s outpoint authority decision is implemented and tested. Full core API 0.9 remains unadvertised pending required schemas. See the [results ledger](../../interop/results.md), [endpoint ledger](../../api-capabilities.md) and [D1–D6 audit](../../plan-audit-d1-d6.md). Checkboxes are reconciled against the [D1–D6 audit](../../plan-audit-d1-d6.md) and [D7–D13 audit](../../plan-audit-d7-d13.md). Checked items refer to bounded evidence; partial or definition-gated requirements remain unchecked.

In scope:

- Exactly `mintv2` and `walletv2`, core consensus 2.1, each module consensus 1.0; BTC amount unit zero. Keep dynamic instance IDs and the core metadata map.
- TCP mutual TLS for guardian traffic, WebSocket JSON-RPC for APIs, fresh setup, all-four key generation, session execution/history, daemon restart and module-bearing API catch-up.
- Bitcoin regtest as the first verified deployment profile. Four guardians, f=1 and q=3. Ordinary R=3600 and round delay 50 ms; no implicit test-mode changes.
- A guardian-facing administrative/configuration interface and the client-facing **server** endpoints required by the advertised versions.
- Durable Mint/Wallet state, mandatory audits, locally stored opaque client backups, Bitcoin broadcast retry and process lifecycle.

Out of scope:

- A new client executable/library, mnemonic/root-secret derivation, client note selection, token import/export workflows, wallet UI, client backup encryption/decryption or reconstruction of client balances.
- Lightning, Meta module, gateways, arbitrary assets, external module/plugin loading, Iroh, general live upgrades and importing upstream guardian databases/archives.
- A claim of all-four-module profile conformance or production readiness from a regtest run.

The daemon must still serve `client_config`, `invite_code`, Mint recovery/share endpoints, Wallet discovery/chain endpoints, and `backup`/`recover`. These are guardian responsibilities; removing a client does not remove them. The daemon may query peers for signed history and configuration using internal RPC transport; that is daemon synchronization, not a new wallet client.

## Dependency and risk rules

The coordinator alone changes `Cargo.toml`, `Cargo.lock`, `shell.nix`, shared registration and dependency inventories. Every worker proposes a library with the exact features, minimum API needed, current primary maintenance evidence, baseline package/native-engine overlap, and an alternative considered.

Implement small codecs, framing helpers, fixed conversions and narrow CLI parsing locally. Use substantial libraries for secret arithmetic, TLS, durable storage and general parsers rather than expanding a small helper into a bespoke security subsystem. Prefer maintained implementations absent from the baseline lockfile; name or version differences alone do not establish independence.

The existing substantial-library choices are `blst`, `k256`, OpenSSL, `fjall` and `sonic-rs`, with `zeroize`, `futures` and the narrow SCALE adapter supporting their boundaries. Their exact selections and limitations are recorded in the dependency review and lockfile. Investigate public APIs and actual resolved graphs before any further addition. If a raw FFI adapter is required, justify its scope, isolate unsafe code and review pointer/length/lifetime invariants; do not silently relax the package-wide unsafe-code rule.

Preserve the mandated active Aleph package versions, source identities and checksums. Replacing an ordinary dependency must not upgrade the agreement closure. Retain the [dependency risk review](../../dependency-review.md), [resolved inventory](../../dependency-inventory.json) and executable policy gate. Record build scripts, procedural macros, native libraries, compiler/OS assumptions and maintenance/advisory checks.

Classify consequences conditionally: a triggered agreement-safety, authorization, secret-leak or build-compromise bug can be critical; parser/runtime/storage faults can range from one-node failure to correlated high/critical impact. Do not invent numeric bug probabilities. Both new guardians share our code and can exceed f=1 together; AlephBFT is shared across all four. Record local implementation mistakes as common failure risks too.

Keep [the pitfalls log](../../spec-pitfalls.md) current with stable IDs, requirement references, observed/expected behavior and a status: documented trap, suspected spec bug, known baseline limitation or resolved clarification. Send unresolved definitions to the [writer handoff](../../spec-writer-questions.md), not into guessed consensus rules.

## Shared interfaces and ownership

Freeze these contracts in `docs/daemon-interfaces.md` before dependent workers begin. The coordinator chooses exact Rust signatures as a small design task, rather than having several workers invent incompatible types.

| Contract | Required boundary |
|---|---|
| Wire types | Peer/instance IDs, version, amount and outpoint types; consensus encoding separated from Bitcoin/SCALE/legacy; bounded decoding and whole-value consumption |
| Crypto | Typed validated keys/points/signatures; exact bytes/domains; public versus secret operations; explicit invalid-object results and non-secret error reporting |
| Validated configuration | Immutable peer identities, module map, public keys and consensus parameters; private guardian material stored separately |
| Store | Read snapshots; one atomic transaction lifetime for module writes plus acceptance records; rollback; replicated/local namespaces; post-commit outbox; exact-byte durable agreement appends |
| Module execution | Closed Mint/Wallet dispatch; stateless/input/output/consensus transitions; item location, creator and transaction context; amount/fee/authorization/error results; audit contributions |
| Agreement/session | Proposal bytes, finalized unit `(creator, round, data)`, durable backup callbacks and awaited termination; session owns application replay and completion |
| Bitcoin backend | Typed block/fee observations, canonical block retrieval and post-commit broadcasts; local observations become proposals rather than arbitrary replicated writes |
| API | Snapshot reads, accepted-state notifications, submission/revalidation queue, explicit capability/endpoint table, peer RPC and setup driver interfaces |

Workers own directories and their dedicated test targets/fixture subdirectories. Coordinator-owned files: package/lock/shell, `src/lib.rs`, top-level module registration, `src/modules/mod.rs`, `src/bin/fedimintd.rs`, shared interfaces, conformance and risk ledgers. Workers send proposed changes to those files instead of editing them concurrently. Any contract change pauses only its dependents until reviewed and integrated.

## Parallel schedule

Three workers plus the coordinator fit the available four-agent limit. Use fresh, bounded worker tasks with explicit inputs, owned files and expected test results. A lane is a scheduling slot, not a permanent agent that accumulates an entire subsystem without review.

| Wave | Worker A | Worker B | Worker C | Coordinator's gate |
|---|---|---|---|---|
| 0 — Contracts | Rule/fixture inventory | Crypto and dependency feasibility | Storage/transport/API contracts | Freeze scope, interfaces, dependency decisions and evidence gaps |
| 1 — Foundations | Remaining codecs and wire records | Crypto adapters and Mint message mapping | Transactional storage and durable agreement stream | Exact vectors and crash durability; integrate shared types |
| 2 — Protocol base | Configuration, identity and versions | TLS peers, envelopes and reconnects | Ordered executor and audit using explicit test transitions | Stable config/transport/transition contracts; no runtime module stubs counted as complete |
| 3 — State and ordering | Mint module | Wallet module plus Bitcoin adapter | Pinned AlephBFT adapters | Real cross-module rollback/audit and four-engine ordering checks |
| 4 — Lifecycle | Setup/DKG | Sessions/history/restart | Server API surface | Fresh four-daemon setup, accepted-state APIs and replay correctness |
| 5 — Integration | Process/RPC harness and external fixture driver | Independent history/Bitcoin assertions | Conformance/security review and regression cases | Daemon wiring, black-box mixed validation and recorded evidence |

Tasks can start as soon as their named inputs are integrated; an unrelated unfinished lane need not hold an entire wave. For example, setup work can start when validated config, crypto, TLS and module-generation contracts exist. It must not guess module layouts to get ahead.

The critical path is crypto/configuration → correct module setup/state → executor and sessions → daemon integration → mixed-process evidence. Storage and transport are prerequisites that can develop alongside crypto. Independent-review work may use an idle lane; do not launch more workers than available slots or merge unreviewed interfaces merely to keep all slots busy.

## Current checkpoint and next parallel assignments

Updated 2026-09-11. D13’s healthy monetary workflow, all four monetary survivor/restart cases and final evidence are complete at the documented regtest scope. The final mixed process run passed in 1219.20 seconds, retained six matching signed session outcomes and joined all four guardians. Separate offline tests authenticate actual Bitcoin signers, every survivor’s monetary certificates, restored Mint shares and matching history/state. The four cases run by default. Earlier failed runs and their regression fixtures retain distinct provenance in [the results ledger](../../interop/results.md).

The requested Superpowers skill is unavailable in this environment; its instructions have not been loaded. The explicit bounded worker schedule above was used, with one coordinator and at most three workers, independently reviewed changes and serialized mutation of the shared Bitcoin node.

[Six remaining clauses](../../remaining-gates.md) require normative definitions. Q17 is resolved for implementation but still requests a written spec correction. Q11’s missing native administrative/diagnostic contracts, Q14’s session-status selection, Q15’s nonnormalized timestamp handling and Q16’s reachable-backend/no-estimate policy remain open in [the writer handoff](../../spec-writer-questions.md). Core API 0.9 remains unadvertised.

Once those definitions arrive, the next bounded assignments can run in parallel:

| Lane | Owned work | Acceptance gate |
| --- | --- | --- |
| A — Native APIs | Assigned `src/api/**` handlers and dedicated socket tests for the newly specified operational/admin routes. | Exact schemas, authorization, errors and lifecycle behavior; update the endpoint ledger before advertisement. |
| B — Edge semantics | Assigned session/backup/Bitcoin-policy boundary and its dedicated tests, using the writer’s Q14/Q15/Q16 answers. | Literal normative vectors, persisted restart behavior and no fabricated backend observation. |
| C — Independent review | Review each change against numbered requirements, public vectors and the existing evidence. | Identify affected regressions and require only the relevant fresh live checks; preserve separate run identities. |

The coordinator owns manifests, shared interfaces and ledgers, integrates reviewed changes and runs the assembled checks. No new client, optional modules, unused generic utilities or invented native API contracts are needed to fill these definition gaps. Existing durability, inverse-assignment, two-peer fresh-work barrier and opaque-backup evidence remains valid at its recorded scope.

Deliverables remain one guardian executable; endpoint/conformance ledgers; runbook, results and public evidence; dependency common-failure risk review; and separate spec questions/pitfalls. Passing regtest monetary interoperability does not establish full API conformance, generic Bitcoin chain behavior, host power-loss durability or production readiness.

## Task D0 — Confirm executable/profile and freeze contracts

### Execution contract

Use the current three-lane schedule above; the wave table describes prerequisites, not additional concurrent agents. Reconcile the D1–D6 audit and audit D7–D13 before checking broad requirements complete. Every task needs exact files, numbered rules, accepted interfaces, meaningful validation and independent review.

Retain established lifecycle invariants: private configuration persists before runtime publication; transaction success follows committed acceptance; agreement shutdown is joined and failures retain recovery bytes; resolver helpers are bounded; profile validation applies during setup and reopen. Use actual test targets through `nix-shell`, and preserve the exact Aleph dependency closure.

**Owner:** coordinator, with the three wave-0 review tasks. **Files:** `docs/daemon-interfaces.md`, `docs/conformance.md`, `docs/dependency-review.md`, `tests/interop/profile.json`, package/shell files.

- [x] Reconcile current foundation and interrupted drafts; retain only tested/reviewed work as completed. Record baseline/spec pins and test evidence.
- [x] Freeze the contracts above and ownership assignments. Select ordinary dependencies through feasibility tests; regenerate and verify the resolved graph after each addition.
- [x] Define the independent daemon executable as `src/bin/fedimintd.rs`, retaining package name `minimint-ng`. Give it its own build identity; setup release compatibility uses normalized `0.13.0` without pretending its source revision is upstream. Evidence: actual executable subprocess tests in `tests/daemon_process.rs` pass.
- [x] Record the reference-daemon artifact/build handoff and the external transaction-driver requirement. CLI, database and archive identity with upstream are not implied by protocol compatibility.
- [x] Create a full endpoint/capability inventory. Target core API 0.9 and module API 0.1, including earlier endpoints. Mark every missing normative schema as a gate rather than returning invented results.

Evidence for D0: [five-requirement audit](../../plan-audit-d0.md), including a fresh 202-package dependency-policy check matching the recorded inventory. Completion of the handoff/inventory does not complete downstream APIs or monetary execution.

**Exit:** interface document, reviewed dependency choices, fixture inventory and actionable missing-schema requests. The existing six-call test-harness subset is not a complete server API profile.

## Task D1 — Complete codecs and protocol records

**Owner/files:** worker A; `src/codec/**`, `src/protocol/**`, `tests/codec.rs`, `tests/protocol.rs`, `tests/fixtures/protocol/**`. **Inputs:** frozen wire types. **Rules:** ENC-001–014, TX-001–003/009, NET-003/005–007, API-003.

- [x] Reuse the tested BigSize/text code; finish sequences, sets, result/enum bodies, known/opaque routing, Bitcoin CompactSize and SCALE/legacy boundaries required by adapters.
- [x] Add transaction, consensus item, accepted item, outpoint and error schemas. Enforce configured instance IDs when decoding for execution and exact known-payload consumption.
- [x] Add core RPC_HEX/RPC_BASE64 wrappers, direct config blobs and native module JSON tests. Preserve u64 JSON values exactly.
- [x] Use literal byte fixtures for nonminimal/truncated integers, sorted maps, unknown variants, double envelopes, transaction witness exclusion, legacy receive priority and independent size limits.

**Check:** `cargo test --locked --test codec --test protocol`; compare new expected bytes to independent fixtures, not the same encoder under test.

## Task D2 — Guardian cryptography

**Owner/files:** worker B; `src/crypto/**`, `tests/crypto.rs`, `tests/fixtures/crypto/**`. **Inputs:** chosen crypto libraries and wire types. **Rules:** CRY-001–008, MINT-002/012, WAL-002/008/014, SET-007/008, CON-003, CFG-006/007.

- [x] Implement hash/HMAC, OS-backed randomness, secp256k1 key generation/tweaks, BIP340 exact-message verification/signing, and compact/DER low-S ECDSA handling needed by the guardian.
- [x] Implement canonical BLS scalar/G1/G2 representations, subgroup checks, permitted infinity behavior, G2 DKG polynomial/share operations and Mint pairing validation/signing.
- [x] Reproduce Mint's exact seeded ChaCha20/G1 mapping, including field-byte significance, root/sign-word consumption and cofactor clearing. Standard hash-to-curve is not a substitute.
- [x] Test fixed public keys, bad encodings, distinct signer thresholds and all four 3-of-4 share subsets. Test-only aggregation/blinding helpers may validate guardian outputs; do not grow them into a client product.

**Check:** `cargo test --locked --test crypto`; positive independent vectors plus negative object validation. Secret arithmetic and unsafe/native boundaries receive explicit review. Client derivation and Lightning TPE are excluded.

Evidence: 11 crypto tests passed in worker and coordinator integration runs; mapping and native boundaries reviewed as recorded in [foundation evidence](../../foundation-review.md). Distributed DKG, module initialization and process interoperability remain dependent tasks.

## Task D3 — Storage and durable effects

**Owner/files:** worker C; `src/storage/**`, `tests/storage.rs`, `tests/storage_crash.rs`. **Inputs:** store contract and reviewed engine. **Rules:** TX-008, CON-005/006/008/010, NET-009, REC-008.

- [x] Implement atomic transactions and snapshots; separate replicated state, local keys/configuration, agreement recovery bytes, client backup objects and post-commit Bitcoin jobs.
- [x] Commit module transitions, accepted IDs/output IDs and recovery records together. Submission checks always roll back.
- [x] Acknowledge agreement append only after exact bytes are durable; replay concatenates committed chunks in order. Preserve prior data on append failure and test partial-write/crash behavior.
- [x] Test crash before/after application commit and before/after broadcast-job persistence. Protect local secret material and avoid secret-bearing diagnostics.

**Check:** `cargo test --locked --test storage --test storage_crash`; process termination/reopen tests must verify atomic and durable behavior, not only mocks.

## Task D4 — Identity, configuration and version contracts

**Owner/files:** worker A; `src/config/**`, `tests/config.rs`. **Inputs:** D1/D2. **Rules:** CFG-001–007, VER-001–008, SET-001–006, MINT-001/012, WAL-011/012, API-009.

- [x] Implement setup records, typed sorting, current client/server config layouts, exact nested instance IDs, public/private separation, endpoint-map federation ID and distinct config commitments.
- [ ] Generate invite responses and signed endpoint/guardian metadata objects as required by server APIs. Retain core metadata while omitting the Meta module.
- [x] Encode supported versions and enforce startup compatibility. Four-peer Wallet estimates are send 228/receive 316 vB; Mint unit zero remains encoded.
- [x] Test raw network magic, module ordering, release normalization, optional setup parameters and four distinct commitments: federation ID, full client configuration, current setup/server checksum and legacy server hash. Use simple URLs in first deployment; track general URL-normalization coverage separately.

**Check:** `cargo test --locked --test config`; exact supplied config bytes/hashes and arbitrary configured instance-ID tests.

## Task D5 — Authenticated networking

**Owner/files:** worker B; `src/net/**`, `tests/transport.rs`, `tests/envelopes.rs`. **Inputs:** D1/D2/D4 interface contract. **Rules:** NET-001/003/004/005/009.

- [x] Implement mutual TLS with configured direct trust anchors, exact leaf-to-peer mapping, required name verification and one compatible TLS suite/group. Verify outgoing requested-peer identity.
- [x] Implement BE64 framing/body cap, legacy send and common-first receive, reconnect initiation by lower ID, connection replacement and specified error behavior.
- [x] Provide the bounded network interface to setup and Aleph adapters. Include tests for fragmentation, coalesced frames, malformed lengths, wrong peers and reconnect/termination.

**Check:** `cargo test --locked --test transport --test envelopes`; real loopback TLS plus independent envelope vectors. A live upstream handshake remains a later evidence gate.

## Task D6 — Transaction executor and audit

**Owner/files:** worker C; `src/core/transaction.rs`, `src/core/audit.rs`, `tests/transactions.rs`. Coordinator owns `src/modules/mod.rs`. **Inputs:** D1/D2/D3 and frozen transition contracts. **Rules:** TX-004–009, CON-005, MINT-013/014, WAL-013/015.

- [x] Implement exact stateless/input/signature/output/funding order, checked u64 totals at the specified points, first-error encoding and 2.1 excess funding.
- [x] Distinguish API idempotent accepted-ID success from consensus duplicate rejection; API validation commits no module state.
- [x] Audit Mint liabilities and the current Wallet UTXO once per accepted item, with the specified checked signed aggregate and fatal negative total. Log the unresolved out-of-domain per-module arithmetic limitation.
- [x] Test early-input overflow, duplicate authorization keys, invalid note before witness count, later-output failure and exact zero-total overflow error. Repeat rollback tests with real modules after D7/D8.

**Check:** `cargo test --locked --test transactions`; synthetic transition tests alone do not clear real cross-module integration.

## Task D7 — Mint module

**Owner/files:** worker A; `src/modules/mint/**`, `tests/mint.rs`. **Inputs:** D1/D2/D3/D6. **Rules:** guardian portions of MINT-001–007/012–015.

- [x] Implement note verification, globally spent nonces per instance, denomination liabilities, blind-signature generation and output-location/blinded-message lookup indexes.
- [x] Append issuance/spent recovery records atomically. Preserve overwritten repeated blinded-message lookups and omitted missing signature shares.
- [x] Implement all server share/recovery queries and exact native JSON, counts, slices and slice hashes; add no client-side tweak-grinding or infinity restrictions to consensus.
- [x] Test denomination separation, repeated spend, fee arithmetic, absent/incomplete requests and full rollback of shares/counters/recovery records.

**Check:** `cargo test --locked --test mint`; include nonempty cryptographically valid state transitions.

## Task D8 — Wallet module and Bitcoin backend

**Owner/files:** worker B; `src/modules/wallet/**`, `src/bitcoin/**`, `tests/wallet.rs`, `tests/bitcoin_transactions.rs`. **Inputs:** D1/D2/D3/D6. **Rules:** WAL-001–017.

- [ ] Implement block and optional fee votes, distinct order statistics, proposer policies, buried canonical block scans and sparse discovery indexes.
- [x] Implement configured immutable fee/vsize estimates, pending package accounting, first-deposit initialization, consolidation and withdrawal with exact input/output order.
- [x] Construct tweaked sorted-key P2WSH scripts and Bitcoin transactions; validate per-input signatures and choose the first q accepted lists in script-key order. Persist pending change and post-commit rebroadcast work.
- [x] Implement Wallet server queries and their satoshi units, hash order and null behavior. Test actual Bitcoin transaction acceptance on regtest.
- [x] Test stale fee, wrong claimant, dust/change, missing wallet, arithmetic, pending-chain boundaries, confirmation and restart. Preserve documented reorg and 33rd-pending-transaction limitations rather than invent new consensus behavior.

**Check:** `cargo test --locked --test wallet --test bitcoin_transactions`; require exact unsigned bytes/txids/sighashes plus Bitcoin Core acceptance for constructed transactions.

## Task D9 — Pinned AlephBFT integration

**Owner/files:** worker C; `src/agreement/**`, `tests/agreement_adapter.rs`, `tests/agreement_restart.rs`. **Inputs:** D1/D2/D3/D5. **Rules:** NET-005–014, CON-010.

- [x] Implement public data/finalization, hash/keychain, network, runtime and backup interfaces around the approved engine. Do not reimplement its election/fork/RMC internals.
- [x] Set n/local ID/session/R+1000 and exact integration delays. Validate included-data limits and authentication/signature boundaries.
- [x] Forward every finalized unit with creator/round/data; preserve order and await engine termination before cleanup.
- [x] Exercise four in-process engines with dropped/reordered messages, absent data, repeated submissions and one-node restart using durable backups.

**Check:** `cargo test --locked --test agreement_adapter --test agreement_restart`; compiling the dependency is not integration completion.

## Task D10 — Fresh setup and DKG

**Owner/files:** worker A; `src/setup/**`, `tests/setup.rs`, `tests/dkg.rs`. **Inputs:** D2/D3/D4/D5 and module-generation contracts from D7/D8. **Rules:** SET-001–008, MINT-012, WAL-011.

- [x] Implement authenticated setup state/parameter/code RPC behavior; deterministic IDs, repeated-code idempotence and global optional-field uniqueness.
- [x] Require all four peers for initial checksum, broadcast-key exchange and module generation. Execute 42 sequential G2 DKGs in denomination order, then one independent Wallet key exchange, then final config checksum.
- [x] Persist generated configuration/private material safely and switch to running consensus only after agreement and validation. No per-module delimiter/checksum or threshold-only setup shortcut.
- [x] Test duplicate/out-of-order/invalid shares, mismatched code/config maps and missing peer; compare full public transcripts when supplied.

**Check:** `cargo test --locked --test setup --test dkg`; four-way matching final commitments and durable reopen, not only successful start RPCs.

## Task D11 — Sessions and history

**Owner/files:** worker B; `src/core/session.rs`, `tests/sessions.rs`, `tests/session_restart.rs`. **Inputs:** D6/D7/D8/D9. **Rules:** CON-001–010.

- [x] Process finalized batches in exact order; discard an undecodable batch but only the invalid individual item after successful batch decoding. Stop before data on the first unit whose round reaches R.
- [x] Build accepted-item history, Merkle root/header and tagged signatures; collect q distinct valid signatures. Separate generic >=q verification from exactly-q guardian adoption.
- [x] Replay committed prefixes without duplicate effects, adopt valid remaining items, and halt on fatal prefix/header disagreement. Catch up through APIs with Mint/Wallet decoders.
- [x] Stop engine then atomically complete history/cleanup; test restart at item, boundary, signature and completion checkpoints.

**Check:** `cargo test --locked --test sessions --test session_restart`; headers/order/state and execution counts must match after restart.

## Task D12 — Complete server API and daemon lifecycle

**Owner/files:** worker C owns `src/api/**`, `tests/api.rs`, `tests/backup_api.rs`; coordinator owns `src/bin/fedimintd.rs` and runtime wiring. **Inputs:** D4/D6–D11 contracts. **Rules:** API-001/003–009, CFG-006/007, VER-008, SET administrative interface, REC-007/008, module endpoint tables.

- [ ] Implement WebSocket JSON-RPC, transport access authentication and separate admin auth, exact wrappers/native payloads and long-poll retry behavior.
- [ ] Cover all versioned core endpoints through 0.9, both module endpoint tables and required setup/admin operations. Include server-side signed opaque backup upload/retrieval: signature, 131072-byte limit and strict timestamp increase. Never decrypt or derive client secrets.
- [ ] Maintain a per-endpoint schema/implemented/tested table. Obtain missing required diagnostic/chain-ID/metadata schemas before claiming full API conformance. A six-method harness is insufficient evidence for an advertisement.
- [x] Ensure submit success follows observed acceptance, single absent output differs from batch null, pending status is not finality, and broadcast failure does not undo acceptance.
- [ ] Wire CLI configuration, setup/running transitions, persisted reopen, shutdown/awaited termination, operational status and secret-safe logging. Reject unsupported module profiles explicitly.

**Check:** `cargo test --locked --test api --test backup_api`; launch the new executable through fresh setup, acceptance waits and restart. Diagnostics with missing definitions remain explicit gates, not arbitrary mock replies.

## Task D13 — Daemon and mixed-federation validation

**Owner/files:** interop worker `tests/mixed_daemon_process.rs`, `tests/interop/monetary_driver.py`, `tests/interop/profile.json`; independent reviewer `tests/mixed_history_capture.rs` and dedicated public fixtures. Retain the existing Rust process harness rather than adding redundant Python entrypoints. Coordinator owns `docs/interop/runbook.md` and `results.md`. **Inputs:** integrated daemon, Bitcoin Core, reference daemon artifact and a compatible external test driver.

Use a pinned existing client/transaction driver as a black box for monetary workflows, or writer-supplied signed transaction fixtures plus a process/RPC harness. Record the driver's identity and limitations; do not implement a new wallet client. Missing fixtures or binaries are integration prerequisites, not reasons to substitute an in-project client silently. Test-only crypto checks may verify returned shares independently.

Signed transaction fixtures must match the fresh run's generated federation keys, outpoints and current state. Static fixtures for unrelated keys cannot replace the external driver in fresh mixed setup. Verify real Bitcoin fee observations or an explicitly documented compatible fee configuration; do not silently synthesize successful estimates to make the monetary test pass.

- [x] Run all-new four-process setup first; compare public configs, completed histories and nonempty module state. This is an integration checkpoint, not cross-implementation evidence.
- [x] Run fresh **2 new daemons + 2 baseline fedimintd**, with identical two-module/regtest/TLS configuration and ordinary parameters. Compare initial/final setup commitments and accepted-item creators/order/session headers.
- [x] Through the external driver, perform first deposit/issuance, a second-deposit consolidation, reissuance, withdrawal and spending pending change where valid. Verify balances/fees, signatures, Bitcoin bytes and actual confirmation.
- [x] Stop each guardian in turn. Every three-node survivor set must issue, sign withdrawals and complete sessions; restore it through durable restart and API catch-up with no duplicate execution.
- [x] Stop two peers, establish a partition barrier and test fresh work proposed afterward with no pre-partition quorum evidence. The remaining pair must not complete that work. Exclude legitimate late completion using votes/signatures produced before the barrier, old accepted responses and rebroadcasts of already-signed transactions. Restore progress, and repeat with peer-ID permutation.
- [x] Exercise server recovery queries and opaque backup fixtures. Existing-client recovery can optionally add coverage; implementing a replacement client is excluded.
- [x] Record artifact hashes, public profiles/transcripts, redacted requests, signed histories, Bitcoin txids, balances, failure schedules and exact passed/unrun scenarios.

**Existing harness command**, with required artifact paths and mode variables from the runbook:

```sh
nix-shell --run 'cargo test --locked --test mixed_daemon_process -- --ignored --nocapture'
```

The [runbook](../../interop/runbook.md) defines reference-daemon, Bitcoin RPC/credential-file and external-driver handoffs. `MINIMINT_MIXED_NEW_PEERS=2,3` selects the inverse assignment; its nonmonetary live run has passed; the default new0/1 assignment also passed all four monetary survivor/recovery cases. Local default tests exclude live runs. Record exact artifacts, environment choices and cleanup outcomes without publishing credentials or client secrets.

## Review and completion gates

For every bounded worker task: specify files/interfaces/rules/tests, write meaningful failing tests, implement, run relevant tests, then have another agent review spec compliance and code quality. Integrate through the coordinator after fixes. New dependencies additionally run the policy/inventory review. Shared interfaces and crash/crypto boundaries always get explicit cross-worker review.

Routine validation: `nix-shell`, `cargo fmt --check`, targeted `cargo test --locked`, library Clippy, and `python3 tools/dependencies.py check` after dependency changes. The full suite runs at integration gates; do not repeatedly run unrelated tests instead of advancing implementation. No percentage completion or dates are inferred from the number of passing codec tests.

The daemon is complete for the agreed subset only when D0–D13 deliverables exist, required schema gaps are resolved, the new executable runs fresh setup and durable consensus, all required APIs/modules are implemented, and the recorded mixed tests meet the acceptance conditions. Until then report the specific completed components and remaining work. Do not end implementation merely because a foundation milestone passes.

Remaining gates are the six normative API/proposer clauses enumerated in [the current ledger](../../remaining-gates.md). Required independent setup/crypto, durability, external Bitcoin, populated recovery and monetary survivor/catch-up evidence is integrated at its stated scope. Broader arithmetic domains, optional clients and unrequested deployment profiles are not implicit completion requirements. Existing evidence must not be reassigned wholesale as unfinished work; newly supplied definitions should trigger only their dependent implementation and verification.
