# Questions for the Fedimint spec writer

Opened 2026-09-09; current disposition updated 2026-09-11. Target: independent BTC-only `mintv2` + `walletv2` guardians, TCP/TLS + WebSocket, mixed 2 minimint-ng + 2 fedimintd, n=4/f=1/q=3 on regtest.

Original review revision: `be0a339c812e099d74064e02e22b9616929ac6e3`; documented implementation baseline: `0c316439d60b5a08eea26fab216780eb893c45bf`. Findings are based on specification prose, not inspection of Fedimint implementation code. Please return language-independent normative amendments and public test vectors. Implementation source links alone do not resolve these questions.

“Blocker” means a rule or byte format cannot safely be invented. “Verification gap” means prose exists, but comparison evidence is missing. The existing OPEN ledger already acknowledges several items; this document narrows them to the planned two-module federation and adds specific deliverables.

## Current writer action list — 2026-09-11

The current spec pin is `06277f7e8e2c5cde5b1fe9b768f37f987e3c0c4c`; a read-only remote HEAD check on this date found no newer default-branch revision. The original review below remains historical context.

- **Required native APIs (Q11):** define requests, results, authorization and errors for the remaining operational/admin routes listed in [the endpoint ledger](api-capabilities.md), including chain identity, status, signing and guardian backup operations. Explicitly exclude any diagnostic that is outside the required profile.
- **Empty and future session status (Q14):** specify the status of an empty current session, especially after restart with agreement backup but no accepted items. The captured future-index result alone does not settle it.
- **Backup timestamp edge cases (Q15):** state how a receiver handles nonnormalized nanoseconds, including signature verification and ordering.
- **Missing Bitcoin fee estimates (Q16):** distinguish a reachable Core with no estimate from a failed backend; specify the optional proposer vote and any permitted fallback source.
- **Bitcoin outpoint JSON (Q17):** amend WAL-016 to the observed display `txid:vout` string, including populated Wallet responses. The user authorized this implementation choice and fresh mixed captures confirm it; the written spec still needs correction.

Please also consider literal examples for the first absent fee vote and the implementation traps recorded in [the pitfalls log](spec-pitfalls.md). External-client acknowledgement and coin-selection traps are identified there as test-driver findings, not newly established consensus-spec defects.

## Current scope: guardian daemon only

The 2026-09-10 implementation plan excludes a new wallet client. Guardian share/recovery/configuration APIs and signed opaque backup storage remain required. We plan core API 0.9 and both module APIs 0.1 with all earlier endpoints, so Q11’s proposed omission question no longer seeks a shortcut. Please supply exact schemas/semantics for required results not fully defined in document 07—particularly `chain_id`, diagnostic configuration and the operational/admin endpoints needed by the daemon. Where a diagnostic is outside the protocol conformance profile, explicitly identify that exclusion. This is a dependent API-completion gate, not a reason to defer codecs, crypto, modules, setup or agreement adapters.

The monetary interoperability driver will be an existing compatible binary or supplied signed fixtures; no new client implementation will be used to fill a missing test-artifact handoff.

## User decision: 2026-09-10

Execution check Q13 — resolved from existing prose, no writer action: WAL-009 explicitly says Wallet generic output status is always absent; document 10 says the same for Mint. Thus after acceptance a single generic outcome query follows API-006's missing-outcome error behavior, while a valid batch entry is null. Wallet's separate `transaction_id` endpoint is not a generic outcome. This was found by checking “status” as well as “outcome”; no new specification amendment is needed.

Exact pinned AlephBFT reuse is approved. Q01 and the internal protocol portion of Q02 are no longer implementation blockers. The no-source restriction remains; only the baseline Cargo.lock is additionally allowed for dependency analysis. The historical review below records the previous decision state; the current action list above identifies the remaining definitions. Adapter, recovery and mixed monetary execution now have the evidence recorded in the conformance/results ledgers.

## Historical review of spec update 06277f7 — 2026-09-09

Reviewed [commit 06277f7](https://github.com/elsirion/fedimint-spec/commit/06277f7e8e2c5cde5b1fe9b768f37f987e3c0c4c) on 2026-09-09. The local spec checkout was fast-forwarded cleanly to that exact commit; the Fedimint implementation baseline is unchanged. Read the numbered-document amendments, [writer disposition](../spec/verification/spec-writer-answers.md), [operator handoff](../spec/verification/two-module-handoff.md), and new JSON fixture data. No Fedimint/Aleph implementation source or bridge was inspected or executed.

This table and its focused follow-up record the 2026-09-09 review before the user approved exact AlephBFT reuse and before implementation testing. They superseded the original blocker labels at that time; the current action list, user decisions and conformance ledger now supersede their pending-work statements. A supplied rule is distinguished from executed comparison evidence.

| Question | Disposition on 2026-09-09 | Work outstanding at that checkpoint |
|---|---|---|
| Q01 | Incorporated by reference, not supplied as a standalone algorithm: NET-014 makes the exact Fedimint AlephBFT fork and locked dependencies normative; NET-010–013 become explanatory. | Our independent-agreement plan remains blocked under the no-source boundary. Reusing the engine would change that plan; the user has been asked and no change is assumed. Full adapter/port/network comparison traces remain absent. |
| Q02 | Adapter/app boundary clarified: NET-009 durable exact-byte append/read; CON-010 distinguishes persisted state from in-memory phase/cursors. Internal newest/salt/replay behavior is delegated to NET-014. | Engine-policy decision as in Q01; crash-injection and module-bearing catch-up evidence still needed. |
| Q03 | Definition supplied: SET-006/MINT-012/WAL-011 specify 42 sequential G2 DKGs (denominations 0–41), then one independent Wallet key exchange, with no intervening module delimiters/checksums. | Full four-peer fixed-coefficient transcript, final setup checksum and malformed-DKG comparisons. |
| Q04 | Definition supplied: WAL-011/012 specify field widths, raw network magic, JSON and size formulas. n=4/q=3 send=228 vB, receive=316 vB; stored estimates never change after signing. | New n=1/n=4 config fixtures are spec-calculated, not baseline serializer comparisons. |
| Q05 | Definition supplied: MINT-013/WAL-013 enumerate error tags/payloads, no-op hooks and precedence. Ten wrapped error fixtures added. | Combined-failure transactions and rollback have not been executed against both implementations. |
| Q06 | Normal-domain formulas supplied: MINT-014 liabilities and WAL-015 current-wallet assets; CON-005 checked signed-64-bit aggregate. | Per-module casts/multiplication outside the intended signed-64-bit domain remain nonportable. Arithmetic ledger is not an executed rollback trace. |
| Q07 | Definition supplied: MINT-015/WAL-016 provide native JSON, point hex, tagged recovery objects, nulls, nested outpoints and omissions. Seventeen literal pairs added. | Full populated endpoint comparison against baseline; fixtures' state labels are assumptions rather than executions. |
| Q08 | Construction questions clarified: fixed stored sizes, low-S, no low-R admission, first q accepted lists and deterministic witness ordering. | Full Bitcoin bytes/sighashes/signatures, destination/dust and real-chain comparison pack remains absent. |
| Q09 | Boundaries clarified: count includes genesis, scan examples, discovery gaps, confirmation removal, and a possible 33rd pending transaction followed by a fatal fee-calculation assertion. | Real-chain/reorg traces remain absent. No deep-reorg rollback or portable graceful pending cap is specified. |
| Q10 | Certificate profile supplied: self-signed P-256, sanitized DNS SAN, configured certificates as direct trust anchors; one common TLS 1.3 suite/group suffices. | Live handshake/replacement and decoder-priority differential fixtures still needed. |
| Q11 | Source/build and launch recipe supplied; two-module support confirmed; normalized release 0.13.0, ordinary R=3600/delay=50 ms, explicit TCP selection. API-009 supplies the legacy hash; VER-008 clarifies advertisements. | No built artifact digest or executed mixed launch. See the remaining minimal-API question below; the build recipe is not permission to inspect Fedimint code. |
| Q12 | Infinity behavior clarified: Mint adds no extra nonidentity predicate after shared decoding. | Four 3-of-4 signer-subset issuance and independent negative pairing/subgroup packs remain absent. |

### Historical focused follow-up — before implementation approval

Local verification of this review: document links/fences/whitespace passed; an independent Node check reproduced both Wallet config encodings/hashes and size formulas, checked all ten nested error wrappers, eight audit rows and three funding equations. These checks establish internal consistency only. Python is absent from PATH, so the supplied Python checker was not run. No baseline serializer, pairing, setup, Bitcoin or mixed-federation comparison was executed. The spec checkout remains clean.

1. **Agreement boundary:** NET-014 deliberately makes a standalone Aleph restatement out of scope. Under a no-implementation-source independent-port constraint, Q01 and the internal part of Q02 therefore remain unavailable. If the user permits reuse, provide a source-free adapter/interface contract and lock-resolution manifest so implementation can consume the exact engine without reading its implementation. Keep integration/restart evidence separate from dependency pinning.
2. **Minimal API conformance:** VER-008 says a supported maximum minor obligates earlier endpoints, but its small harness list uses core 0.0 while document 07's endpoint table includes backup/recover and diagnostic configuration methods at 0.0. Does the two-module subset permit explicit endpoint omissions under a 0.0 advertisement, or must those endpoints be implemented? Please distinguish a harness that uses only six methods from a guardian conforming to the advertised API. Our plan will not silently advertise 0.9 or 0.5 while dropping older endpoints.
3. **Extreme audits:** Confirm the supported numeric-domain claim for minimint-ng. The update explicitly declines a portable fatal rule for unchecked module arithmetic, so the plan must not claim exact behavior outside that domain from prose alone.
4. **Evidence delivery:** Prioritize full setup/config commitments, nonempty cross-module state/rollback, four-peer Bitcoin bytes, and crash/API catch-up traces. Then supply the remaining TLS/codec and full issuance negative/subset comparisons. Label spec-calculated versus baseline-compared fixtures explicitly.

## Q01 — Complete agreement admission and reliable multicast

**Blocker for guardian conformance.** [06, NET-008/010/013 and NET-G1](../spec/06-guardian-network.md); existing OPEN-01.

Specify fork-proof validity, identity/session/round checks on both proof units, alert sender constraints, legitimized-unit validity/admission, duplicate/conflicting alerts, reliable-multicast signature-map acceptance and completion thresholds, retransmission, alert retrieval, and how completion releases units. Define the exact checks on explicit-parent responses: count, ordering, coordinates, signatures, duplicate entries, forked parents, and correlation to requested unit hash. Describe handling of responses received before a request or before dependencies.

Deliver complete state-transition tables and event traces covering ordinary admission, missing parents, fork detection, alert/RMC completion, and malformed responses. Each trace should include received bytes, state before/after, outgoing messages, admitted hashes, elected heads, and exact emitted order. Include mixed-parent-vote and frozen-candidate-set cases. NET-010–012 alone cannot justify a substitute agreement protocol.

## Q02 — Agreement crash and recovery contract

**Blocker for safe restarts.** [06, NET-009/010 and NET-G1](../spec/06-guardian-network.md), [05, CON-006/008](../spec/05-consensus.md); OPEN-01/04.

Define persisted protocol state and the required ordering between persistence, unit signing, sending, receiving/admission, election/emission, and application commits. Explain newest-request salts, request/response authentication/correlation, newest-unit selection, backup replay, resumed local round selection, and transition across completed sessions. A local file format may remain implementation-specific; externally visible restart behavior cannot.

Deliver crash traces before/after local-unit persistence/send, accepted-item commit, first boundary unit, signature quorum, and session-completion commit. State which messages are retransmitted and how an implementation avoids a second unit at the same coordinate. Include identical/shorter/divergent history prefixes and catch-up of histories containing both Mint and Wallet payloads through the federation API.

## Q03 — Per-module configuration generation

**Blocker for fresh mixed setup.** [09, SET-006/008](../spec/09-setup.md), [10, MINT-001](../spec/10-mint-v2.md), [11, WAL-001](../spec/11-wallet-v2.md); relates to OPEN-07.

SET-006 specifies ascending module-kind order but delegates each module's generation sequence to its own document. Those documents do not supply that sequence. Specify Mint's group, number and order of DKG invocations, denomination traversal, aggregate/public-share construction, and private-key validation. Specify Wallet's secret generation, public-key exchange payload and message order, and local/private versus shared configuration validation. Clarify whether any other setup messages occur between invocations. Do not rely on assumptions such as “42 independent G2 invocations” without making them normative.

Deliver one fixed-secret four-guardian transcript for enabled kinds exactly `{mintv2,walletv2}`: every setup-exchange/DKG payload, its sender/recipient and order, module instance IDs, resulting public configs, initial checksum, and final checksum. Supply expected failure for duplicate, out-of-order, wrong-group, and invalid-share messages. Use public test secrets only.

## Q04 — Wallet configuration schema and virtual sizes

**Blocker for matching setup checksums and transaction admission.** [11, WAL-001/004](../spec/11-wallet-v2.md), [01, ENC-013](../spec/01-encoding.md), [09, SET-006](../spec/09-setup.md); OPEN-05/07.

Specify exact integer widths and binary layouts for virtual-size estimates and fee fields, and explicitly select current raw network magic versus the legacy network wrapper for walletv2. Give generated send/receive virtual sizes and their formulas for n=4/q=3, including signature-size and witness assumptions. Distinguish those config estimates from actual pending transaction `vbytes`, which enters package fee computation.

Deliver the complete Wallet config encoding, JSON, and hash, plus n=1 and n=4 derivations. State exactly how `vbytes` is assigned before signatures exist and after final witnesses, and whether signature length variability can affect agreed fees or only diagnostics.

## Q05 — Module errors and validation hooks

**Blocker for exact rejection replies; potential execution ambiguity.** [04, TX-004/009](../spec/04-transactions.md), [10, MINT-003/004](../spec/10-mint-v2.md), [11, WAL-005/006/008](../spec/11-wallet-v2.md).

TX-009 routes Input/Output errors to module encodings, but Mint/Wallet do not enumerate those error tags and payloads. Supply complete error enum tables, field types/order, unknown-tag handling, and examples of RPC-wrapped submission errors. Define each module's stateless verification and submission-only validation, explicitly saying when either is a no-op. Define first-error precedence where wallet checks can fail simultaneously and the signature-share item rejection order.

Deliver cases combining invalid note, duplicate spend, wrong signature count, missing fee rate, stale quote, arithmetic failure, unknown destination/version, and invalid Wallet signature list. Each case needs exact returned bytes and whether any state changed.

## Q06 — Audit and accounting state

**Blocker for the mandatory audit invariant.** [05, CON-005](../spec/05-consensus.md), [10, MINT-003/004/005](../spec/10-mint-v2.md), [11, WAL-005–009](../spec/11-wallet-v2.md).

Define each module's audit contribution, signed intermediate arithmetic and bounds, and treatment of fees, excess input value under core 2.1, unclaimed deposits, first-deposit mining-fee withholding, and pending wallet chains. Specify initialization and fatal overflow/underflow conditions. A requirement to audit every module after accepted items needs reproducible formulas.

Deliver a state ledger through first deposit, issuance, second-deposit consolidation, reissuance, withdrawal, signature completion and confirmation, including exact module and aggregate audit totals. Include a later-output failure proving all earlier changes and audit effects roll back.

## Q07 — Concrete module endpoint JSON schemas

**Blocker for interoperable clients; needed for reliable diagnostics.** [07, API-003](../spec/07-core-api.md), [10, module RPC table](../spec/10-mint-v2.md), [11, RPC section](../spec/11-wallet-v2.md).

Specify whether Mint signature-share lists and recovery records are native JSON, direct point hex, or RPC_HEX-wrapped consensus objects; likewise blinded-message requests. Give full schemas for optional federation-wallet records, discovery entries, and transaction-chain records, including nested outpoints, script representation, integer units/bounds, null versus omitted fields, and hash byte/display order. “List of shares” does not identify an interoperable JSON representation.

Deliver literal request/response pairs for every Mint/Wallet endpoint, with empty, missing, partial-range and error cases. Include multi-output issuance with missing entries so clients can confirm their interpretation of omitted shares.

## Q08 — Wallet Bitcoin transaction and signature determinism

**Verification gap with some unspecified construction details.** [11, WAL-002/005–008](../spec/11-wallet-v2.md); OPEN-05.

Provide byte-exact n=4/q=3 vectors for first deposit, consolidation, withdrawal, and withdrawal spending unconfirmed change. Include original UTXOs, tweaks, sorted keys, scripts, unsigned bytes/txids, per-input sighashes, compact shares, DER conversion, final witness stacks, weight/vsize, fee state, and expected acceptance/state changes. Clarify ECDSA low-S requirements, nonce/low-R requirements if they influence agreed values, and which q signatures form a witness when more arrive. Clarify whether witness differences across peers are allowed when txids remain equal.

Do not replace the specified three-signature P2WSH scheme with a different multisig construction. Include destinations of all five supported types and the dust/change boundaries.

## Q09 — Wallet block scanning, pending chain and reorganization boundaries

**Stateful verification gap and boundary questions.** [11, WAL-003/004/007–010](../spec/11-wallet-v2.md); OPEN-04/05.

Define block-count versus height indexing with an explicit regtest timeline (including genesis), initial cursor/recovery indices, confirmation/removal behavior for multiple chained transactions in one block, and exactly what happens at the assumed 32-pending-transaction bound. Clarify discovery index assignment for filter matches that are not P2WSH, and semantics of spent/outpoint in API records. Explain any admission effect of locally unavailable blocks and fees.

Deliver a real-chain trace with filter gaps, fee-vote changes, first scan, buried deposits, confirmations, and a shallow reorg before scanning. For a deep reorg after processing, explicitly document the baseline's behavior/unsupported guarantee; no request here to invent a rollback protocol.

## Q10 — TLS identity and envelope comparison fixtures

**Verification gap; certificate provisioning needs clarification.** [06, NET-001/003/004 and NET-G2](../spec/06-guardian-network.md); OPEN-02/08.

Supply a valid generated certificate profile (issuer/trust-anchor treatment, SAN construction, key type, usage constraints) and the expected mutual-authentication transcript for four named guardians. Confirm a common TLS 1.3 suite/group suffices without implementing every advertised optional suite/group. State duplicate-connection replacement behavior during simultaneous transport events.

Deliver legacy/common receive-priority fixtures for all used variants, including a frame interpretable by both decoders, legacy trailing bytes, malformed common payload fallback, signed-history double wrapping, DKG messages, and SCALE payload trailing bytes. Include complete TLS frame bytes independently of encryption. Iroh details are deferred because this target selects TCP.

## Q11 — Reproducible two-module baseline launch and API capability profile

**Operational prerequisite, plus an advertisement question.** [00, OV-002/003](../spec/00-overview.md), [07](../spec/07-core-api.md), [08](../spec/08-versioning.md), [09, SET-003/006](../spec/09-setup.md).

Provide a reproducible pinned fedimintd artifact or build handoff, artifact checksum, normalized setup release string, and documented invocation/configuration for regtest, TCP transport, exactly the two module kinds, four peers, Bitcoin backend, and ordinary rounds per session. Confirm the baseline supports this subset without implicitly requiring Meta/Lightning. Identify any startup/client APIs required even with fixed endpoints. CLI syntax is outside normative scope, so a separate operator recipe is sufficient.

List minimum core API advertisement needed for the harness and which endpoints a supported minor obligates. Explain Wallet endpoints declared 0.0 versus advertisement 0.1. Supply the `server_config_consensus_hash` legacy field layout if baseline clients/guardians call it; SET-006's current setup checksum must not be substituted.

## Q12 — Independent cryptographic conformance pack

**Verification gap.** [02, CRY-004–008](../spec/02-cryptography.md), [09, SET-008](../spec/09-setup.md), [10, MINT-002/006](../spec/10-mint-v2.md); OPEN-03/07.

Supply nonempty Mint issuance vectors for all four possible 3-of-4 signer subsets, with fixed public test keys, seeded message point, blinding, shares, aggregate, and final pairing verification. Include bad subgroup/canonical encodings, zero/infinity behavior, wrong denomination/key set, altered share, repeated guardian ID, and too few shares. Shared point decoding permits infinity; clarify any module-specific rejection before introducing extra constraints.

Classify each fixture as hand-derived, independently computed, or compared with the pinned executable. Existing point mapping/interpolation examples do not establish complete independent pairing and DKG correctness.

## Requested return format and priorities

First return Q01–Q07 normative additions plus Q11's launch/profile answer. Then provide the fixtures requested by Q08–Q10/Q12 and the state/restart traces; these may arrive incrementally. Each response should name stable requirement IDs, exact schemas or transitions, input/output bytes, expected accept/reject behavior, and the verification method/baseline. Keep unknowns explicitly open instead of replacing them with source pointers.

Out of scope for this iteration: Iroh negotiation, Lightning/gateway behavior, arbitrary asset units, Meta key registries, generic guardian archive import/export, BIP39 UI and encrypted client backup compatibility. These remain exclusions, not claims that the wider spec is complete.

## Q14 — Empty-current and future session-status selection

**Endpoint state-selection ambiguity; wire layouts are specified.** [05, CON-001/010](../spec/05-consensus.md) and [07, API-003/008](../spec/07-core-api.md).

CON-001 specifies Initial tag 0 with an empty body, Pending tag 1 with a list of accepted items, and Complete tag 2 with the original or signed outcome. It does not state which status to return for the current session with zero accepted items, or for an index beyond the current session. Please give exact original/v2 results for: an empty new database queried at indices 0 and 1; current session s immediately after completing s−1; a restarted current session with no accepted records but nonempty native agreement backup; and future index s+1. Confirm whether a collection/signature phase difference changes an empty current status despite those phases not being persisted.

Implementation disposition: the status codecs implement the documented envelopes and legacy conversion. `core::session::persisted_status` returns Complete for a stored completed outcome, Pending for nonempty current accepted records, and no observation for empty-current/future requests. The native API must resolve this selection rule before advertising these endpoints; no guessed Initial versus Pending([]) behavior is claimed.

## Q15 — Non-normalized backup timestamps

REC-007 encodes seconds as u64 and nanoseconds as u32 and requires producers to use normalized timestamps. REC-008 requires signature verification and strictly increasing timestamps. For received JSON with nanos_since_epoch >= 1,000,000,000, does the guardian reject it, preserve the exact signed pair, or normalize before signature verification? Is ordering raw-pair lexicographic or represented elapsed time, including values beyond u64 seconds after normalization?

The implementation preserves the signed pair and compares represented time in u128 nanoseconds. This agrees for normalized producer inputs; the non-normalized corner remains an explicitly unverified interpretation pending a normative answer and literal signature/order fixtures.

## Writer feedback — WAL-004 initial optional vote

The first mixed runtime test exposed an implementation trap worth making explicit with an example: no stored fee vote is different from a stored `None` vote. WAL-004's “identical repeat ... stored optional vote” supports accepting the first `None` and rejecting the second, which the pinned reference executable confirmed. Our mistaken default-to-None lookup omitted two accepted items, causing session-header signature rejection despite identical setup/configuration and transaction acceptance.

This is a confirmed implementation defect, not an unresolved normative dispute. Please consider adding an explicit initial-state example or fixture. The source-free public observations are in [first-none-vote.json](../tests/fixtures/interop/first-none-vote.json): the reference pending list has 12 items, the defective implementation has 10, and the two missing accepted-item encodings are recorded. These are pending API observations, not signed completion certificates; fresh-run validation follows the correction. No Merkle rule change is indicated by this evidence.

## Q16 — WAL-004 backend availability versus missing fee estimates

**Normative boundary requiring clarification.** WAL-004 says available backends floor proposer rates at 1,000 sat/kvB and unavailable backends propose absence. The operator handoff says locally unavailable fee data produces null quotes. Neither text explicitly maps a reachable Bitcoin Core response with no `feerate` to proposer policy.

Please specify the emitted optional vote separately for (1) no configured backend, (2) transport/RPC failure, (3) successful `estimatesmartfee` with an `errors` member and no `feerate`, (4) an explicit zero estimate, and (5) a positive estimate below 1,000 sat/kvB. For case 3, is the proposer required to use `Some(1000)`, retain absence, or apply a separately defined backend fallback? If there is a fallback, specify its source, units, configuration, and stale-cache behavior. Clarify whether the operator handoff's null-quote statement refers to absent consensus fee rate without q present votes, rather than raw estimator absence.

Source-free observation: an exact-baseline mixed run contained reference guardians' `FeeRate(Some(1000))` votes while the coordinator observed reachable Core `estimatesmartfee 6` returning no estimate; the independent guardians proposed absence. This establishes the observed optional votes, but does not identify the reference's internal rate source or establish a general fallback rule. The executable's public help lists optional fee-rate-source configuration; no implementation was inspected to infer its behavior.

Implementation disposition: the Core RPC adapter preserves a valid response without `feerate` as `Ok(None)` and preserves failures as errors. Backend failure must withdraw a previous present vote by proposing absence; silently skipping the observation leaves a stale vote and conflicts with WAL-004. Successful `Ok(None)` remains an absent proposer vote pending this clarification. No numeric estimate or consensus vote is fabricated to obtain regtest quotes. Any later fallback must be a documented proposer/backend policy, not an admission floor on received votes or a modification of the honest raw RPC observation.

## Additional public API evidence for Q11/Q14

Read-only calls to both exact-baseline reference guardians during the controlled mixed failure run are preserved with artifact identity and hashes in [reference API fixtures](../tests/fixtures/interop/reference-api-2026-09-10/manifest.json). Both returned original session status `["020000"]` and signed status `["AgAA"]` for indices 1 and 9 before session 0 completed. After the outer byte-vector wrapper, these encode `Initial`. This narrows future-index behavior; it does not settle empty-current/restart phase selection. Please incorporate the future-index rule and the outstanding empty-current cases into CON-001.

Both diagnostic configuration responses have top-level `global` and `modules` objects. Both `chain_id` results are the same 64-character hex string for this particular regtest node. Please define diagnostic module decoding/error behavior and the chain-ID derivation, byte order, backend failure behavior and stability across chain extension/reorganization; a single observed chain ID cannot establish these rules. The fixtures record actual responses rather than guessed schemas.

A subsequent live backend check at height 106 established that the captured `chain_id` (`467b7adb879bfb10f36a292eb1e3d05846446c45a2300d9c65a9ce89484aa6b0`) equals this node's **block-1 display hash**. Its genesis display hash is `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`, which differs. Please confirm whether block 1 is the normative derivation, what happens before it exists, and how reorganization or backend unavailability affects this endpoint. This comparison is an observation supporting that hypothesis, not a portable rule inferred from implementation source.

## Q17 — Confirmed WAL-016 Bitcoin-outpoint JSON contradiction

**Historically blocked deposit claims; implementation authority resolved below, spec correction still requested.** WAL-016 explicitly says a Bitcoin outpoint is `{"txid":"<64 hex>","vout":0}` and repeats that object in both discovery and wallet examples. Exact-baseline reference peers 2/3 instead returned `"441127e88b3be8f451e4ce5a82efc2c45efc98e249eda8a5df892d985c9b5c9e:1"` for discovery index 0. Independent peers 0/1 returned the specified object for the same output. All four had consensus block count 108 and discovered the same 100,000-satoshi output mined at height 107; all wallet results remained null and no Mint issuance had occurred at capture.

[Public conflict fixtures](../tests/fixtures/interop/wal016-outpoint-conflict/manifest.json) retain raw replies and exact artifact identities. The existing CLI could not decode the independent discovery responses. This is a written-spec versus executable contradiction, not evidence of a Bitcoin consensus-encoding or storage defect.

Please amend discovery outpoint JSON to the baseline string format, specifying decimal vout formatting and display-order txid, or explicitly explain a profile/version distinction. Confirm the populated `federation_wallet.outpoint` format separately: its value is null in this capture, so the common string representation there is not yet observed. Fedimint output-location requests remain their distinct `{txid,out_idx}` objects. Update the literal endpoint fixtures along with WAL-016. At this historical checkpoint the coordinator requested an authority decision and retained the written rule. The 2026-09-11 decision and fresh verification below supersede that state.

## Q17 authority decision — 2026-09-11

The user explicitly approved matching the existing daemon and documenting the contradictory written format as a specification bug. Native Bitcoin outpoints now render as `"<display-txid>:<decimal-vout>"` through the shared discovery/federation-wallet renderer; optional absence remains null. Fedimint `{txid,out_idx}` requests and Bitcoin consensus/storage bytes are unchanged.

The discovery regression compares the entire retained reference response and its fixed digest. It also covers leading-zero txids and full-u32 vout. Populated federation-wallet string rendering was initially an authorized common-type inference and is now confirmed by the fresh populated reference capture below; the earlier null wallets did not prove it. This decision resolves the implementation authority gate without pretending that WAL-016 has already been amended. Please correct the normative prose and public fixtures. Other questions retain their existing status.

Fresh verification on 2026-09-11: both implementations in the 2+2 federation returned the identical populated Wallet outpoint string after the existing client completed its first deposit claim. The Wallet held 100,000 satoshis and the external client reported 55 Mint notes. This confirms the shared renderer beyond discovery; the broader consolidation/reissue/withdrawal workflow remains separate.
