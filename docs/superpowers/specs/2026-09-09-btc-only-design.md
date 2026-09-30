# Minimal BTC-only minimint-ng design

> **Historical guardian/client design.** The [2026-09-10 daemon-only plan](../plans/2026-09-10-fedimintd-implementation.md) supersedes client implementation scope and defines current architecture, server responsibilities and parallel execution.

Date: 2026-09-09. Status: proposed design for implementation planning; no implementation or interoperability claim.

## Objective and evidence boundary

Build an independent guardian that can participate in a fresh federation containing two minimint-ng guardians and two fedimintd guardians, with three distinct guardians required for agreement, Mint issuance, and Bitcoin spending. All four must cooperate during setup. Use Bitcoin regtest for the first experiment.

Protocol authority is the supplied [specification](../../../spec/README.md), spec repository revision `06277f7e8e2c5cde5b1fe9b768f37f987e3c0c4c` (review updated from `be0a339c812e099d74064e02e22b9616929ac6e3`), describing Fedimint baseline `0c316439d60b5a08eea26fab216780eb893c45bf`. Only specification prose and its verification report were consulted. Fedimint source, dependency implementation source, evidence source links, and the implementation-vector bridge were not inspected or executed. Later tests may treat a pinned fedimintd executable as a black box; obtain missing rules from the spec writer, never infer a normative rule by reading its implementation.

The workspace initially contains only the separate `spec/` repository. Proposed implementation files and tooling do not yet exist. Keep the supplied spec unchanged; documents under `docs/` are outside its Git repository.

## Spec update decision boundary

Update 06277f7 explicitly supports this two-module TLS/WebSocket subset and supplies module setup, errors, audits, sizing and JSON definitions. Small fixtures remain spec-calculated rather than baseline-compared. NET-014 now incorporates the pinned AlephBFT engine as normative, overriding its explanatory summaries. This does not supply standalone internal rules under our no-source constraint. On 2026-09-10 the user approved exact pinned-engine reuse. Agreement internals need not be independently restated; adapter and restart correctness still need verification. See the [current question disposition](../../spec-writer-questions.md#review-of-spec-update-06277f7).

## Scope assumptions

Interpret “no external modules” as exactly two statically registered protocol kinds: `mintv2` and `walletv2`. Use the approved Fedimint AlephBFT fork at exactly 0.36.0 with pinned active transitives. For ordinary libraries, implement small utility needs locally and prefer maintained alternatives absent from the baseline lockfile. Record transitive/native overlap and common failure impact in the dependency review. No other Fedimint implementation crate is permitted.

Keep the core's module instance envelopes and dispatch because they are on the wire. Reject an unsupported configured kind at startup. No plugin loader, module SDK, arbitrary assets, Lightning, gateway, or Meta module. The core configuration's `meta` map still exists and includes `federation_name`; it is distinct from the omitted Meta module. Mint's `amount_unit=0` remains encoded. Millisatoshis remain the internal monetary unit; Bitcoin transactions use satoshis.

This is an explicit guardian/client subset under OV-002/OV-003, not the four-module Bitcoin-profile conformance claim. The fedimintd peers must use the same two-module configuration. A full default federation containing omitted kinds is outside scope.

Support mutual TLS over TCP for guardian traffic and WebSocket JSON-RPC for APIs. Use simple credential-free, query-free URLs and unique ASCII guardian names in the first harness. Iroh and dynamic endpoint migration are deferred. These deployment restrictions do not permit changing protocol decoding, hashing, or consensus rules.

Use core consensus 2.1 and module consensus 1.0, as specified. Advertise only API capabilities actually implemented. Release-string normalization used by setup is a separate compatibility field: obtain the baseline's required value and expose independent minimint-ng build identity separately. Do not invent a release version from a Git hash.

## Alternatives considered

| Approach | Tradeoff | Decision |
|---|---|---|
| Independent two-module guardian with TLS and a narrow test client | Smallest end-to-end BTC subset; still needs complete agreement and setup | Recommended |
| Implement all four profile modules | Broader client compatibility, but adds Lightning, gateways, and unrelated state machines | Defer |
| Client-only implementation or externally ordered guardian simulation | Useful early codec/state-machine checkpoints; cannot contribute the two necessary independent guardian votes | Use only as development checkpoints |

A trusted imported configuration could isolate steady-state debugging later, but cannot replace the mixed distributed-setup acceptance test and currently lacks a specified cross-implementation guardian archive format.

## Architecture and data flow

Proposed implementation language is Rust, with one package and two executables: `minimint-ng` guardian and `minimint-ng-client` test client. Rust is a local engineering choice, not a wire requirement. Select and pin ordinary libraries during the first implementation task after compatibility checks; no package versions or compatibility are asserted by this design. Use a transactional embedded database, an asynchronous runtime, standard Bitcoin/secp256k1 primitives, BLS12-381 arithmetic/pairings, and TLS/WebSocket support behind small adapters. Reimplement protocol serialization and state machines from the spec. Do not substitute a library's standard hash-to-curve for the specified seeded mapping.

A single ordered executor owns consensus writes. Transport authenticates peers and decodes envelopes; agreement admits signed units and emits their specified order; the session engine applies module transitions in that order inside database transactions. Client submissions use discarded tentative writes, then enter the proposal queue. Only consensus commits spend state. APIs read snapshots and wait on committed-state notifications.

Separate replicated state (module accounting, accepted items/transactions, completed histories) from local state (secret keys, setup progress, agreement recovery, submission queues, Bitcoin observations, broadcast retry jobs). Module transitions receive a transaction context, item location, submitting peer where applicable, and consensus version. They return amount, fee, authorization key for inputs, or a precisely encoded protocol error. No generic user-extensible module abstraction is needed.

Bitcoin queries form a narrow adapter: block count, canonical hashes/blocks, fee estimate, transaction broadcast. Backend observations become wallet proposals. Scanning on an agreed count follows WAL-003, including waiting for backend height; do not let wall-clock/backend-local choices alter replicated results. Bitcoin broadcast happens after commit through a persistent outbox. A failed broadcast cannot reverse an accepted withdrawal.

Persist a locally created agreement unit before sending it, subject to the writer-supplied recovery contract. Atomic module writes include acceptance and recovery records. Stop the old agreement session before clearing its recovery state and committing completion. Retrying a client payment preserves its transaction ID; a timeout is an unresolved operation.

## Minimum client and API surface

The test client joins using an invite and three matching complete configurations; it does not trust one guardian's module keys. It derives keys using the documented raw-root default-wallet profile, generates filtered deposit addresses, claims deposits into Mint outputs, verifies and aggregates three distinct signature shares, transfers tokens by reissuance, and withdraws to a regtest Bitcoin destination. Persist note secrets and operation IDs before submission. Root-secret interoperability and module recovery endpoints are in scope; BIP39 UI, general wallet UI, and encrypted backup upload are deferred.

Implement setup RPCs from SET-001–SET-006; core configuration/version, transaction, output, and session/history endpoints; all Mint and Wallet endpoints in documents 10 and 11. Resolve the exact API advertisement and endpoint schema questions before claiming stock-client compatibility. Fixed endpoints suffice for the controlled first harness only if the pinned peer/client startup trace confirms that omitted endpoint-discovery APIs are unnecessary.

## Invariants and failure behavior

- For n=4: f=1, q=3. Count distinct authenticated peer IDs, never duplicate shares.
- Canonical byte encodings, module IDs, parent ordering, signature domains, and rejection order are part of interoperability.
- Rejected transactions leave no writes, including Mint issuance/recovery and Wallet pending-chain changes.
- Checked signed-64-bit aggregate audit overflow or negative aggregate net assets is fatal. MINT-014/WAL-015 now define ordinary-domain contributions; their unchecked internal arithmetic outside the intended signed-64-bit domain has no portable fatal guarantee.
- Generic signed-history validation accepts at least q valid signatures and rejects invalid extras; guardian adoption requires exactly q.
- API success after acceptance, Mint share availability, Bitcoin construction, broadcast, and confirmation remain separate events.
- On fatal prefix disagreement or invariant failure, halt consensus, preserve diagnosis/state, and avoid emitting further signatures.
- Deep reorganization of already processed wallet state has no specified rollback. Record the limitation; do not fabricate rollback semantics.

## Completion gates

The [implementation plan](../plans/2026-09-09-btc-only-implementation.md) decomposes codec, setup, deterministic state, agreement, API/client, and mixed-process work. The [spec-writer handoff](../../spec-writer-questions.md) separates missing definitions from missing verification.

A four-node minimint-ng simulation is development evidence only. The final target requires a real four-process mixed setup; identical configuration commitments; matching completed-session headers and accepted-item order; deposits, reissuance and withdrawals; progress with each possible single guardian offline; and restart/catch-up of both implementations. A two-peer remainder must not finalize new work. Cooperative agreement can be debugged earlier, but guardian conformance requires correct pinned-engine adapters and associated Q01/Q02 restart/integration fixtures.
