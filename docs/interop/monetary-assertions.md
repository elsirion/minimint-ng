# Monetary interoperability assertions

This is a review guide for the external black-box driver and mixed guardian harness, not evidence that the monetary workflow has passed. Normative inputs are [TX-004–008](../../spec/04-transactions.md), [MINT-003–007/014–015](../../spec/10-mint-v2.md), and [WAL-002–017](../../spec/11-wallet-v2.md). The [driver handoff](driver-handoff.md) records executable provenance and observed help. Do not inspect reference implementation or bridge source to fill gaps.

## Identity, units and evidence boundary

Bind every run to the exact daemon/CLI executable digests, fresh federation ID, public configuration and configured module IDs, guardian broadcast keys, Mint denomination keys, Wallet Bitcoin keys, consensus version and fee settings. Preserve separate durable sender/recipient client directories. Notes or initialized clients from an earlier fresh DKG are not transferable fixtures for this federation. Record Core version/network, canonical blocks, real estimator observations and daemon backend settings. The successful estimator-conditioning experiment is a prerequisite observation, not a guarantee that the rate remains available.

Protocol Mint/core amounts and module base fees are **millisatoshis**; Wallet UTXO values, destination amounts and mining fees are **satoshis**; Wallet rates are **sat/kvB**. One satoshi is 1,000 msat. Parse native u64 JSON integers exactly. Core BTC decimals require exact decimal conversion, never floating-point rounding. Existing CLI `AMOUNT`, `VALUE` and `--fee` grammar must be established from its actual help/observed behavior; do not infer their units from these protocol units. `all` is a client operation whose fee/change behavior needs separate observation.

Keep tokens, nonce secrets, client databases and access credentials private. Public evidence can contain transaction IDs, decoded public transactions, scripts, discovery/chain records, configuration, signed session outcomes and arithmetic totals. A CLI exit code or local balance alone does not establish guardian acceptance. `submit_transaction` success is tentative validation; use `await_transaction` and configured-decoder, index-bound, q-signature-verified history to establish acceptance. Mint/Wallet generic output status is absent. API submission can itself succeed at the JSON-RPC layer while carrying an encoded transaction rejection.

## Arithmetic ledger

For module fee parameters `(b,p)`, define `f(a)=b+floor(min(a*p,2^64-1)/1,000,000)` msat. Charge Mint fees separately for **each** input and output, with amount `2^d` msat. Charge Wallet fees separately from mining fees: on deposit credit, or on withdrawal destination plus mining fee, converted to msat. Ordinary generated Mint settings are `(100,0)` and Wallet `(100000,0)`; read actual configuration rather than substituting defaults.

For each accepted core transaction, reconstruct input amount `I`, output amount `O` and all input/output module fees `F`. Check each u64 accumulation and `O+F`. Core 2.1 permits `E=I-O-F >= 0`; older versions require `E=0`. No automatic change is created. Count explicit Mint change outputs and their individual fees. Do not label `E` a Bitcoin mining fee.

Within the intended signed-64-bit accounting domain, reconstruct Wallet assets `A=1000*W` and Mint liabilities `L=sum(2^d*c_d)`, giving net audit `N=A-L`. In an isolated two-module run starting empty, derive `c_d` from every accepted Mint output minus input in signed history; recovery records corroborate transitions but do not replace the complete accepted-input ledger. No public audit endpoint is assumed. Neither pending ancestors nor stored signature shares add separate assets/liabilities. Aggregate negative or overflowing audit is fatal; out-of-domain unchecked baseline casts are not a portable numerical conformance claim.

## Operation assertions

Here `D` is a discovered deposit value, `m` its supplied mining fee, `V` a withdrawal destination value, and `W` the previous Wallet value, all in satoshis. `F` and `E` include the whole core transaction, including Mint change/issuance. The audit deltas below assume only the specified Wallet action plus Mint inputs/outputs.

| Stage | Required accepted state | Arithmetic and audit delta |
| --- | --- | --- |
| First deposit and issuance | Discovery changes `spent:false` to `true`; Wallet becomes the **original full deposit** outpoint/value/tweak; no federation Bitcoin transaction or chain record is created | Wallet input credit `C=1000*(D-m)`; Mint outputs must satisfy funding after all fees. `Delta A=1000*D`, `Delta N=1000*m+F+E` |
| Later deposit / consolidation | Claim discovery; construct two inputs in order old Wallet, deposit; sole output is new Wallet; advance Wallet immediately to unsigned txid output 0 | `W'=W+D-m`, credit `C=1000*(D-m)`, actual Bitcoin input-minus-output fee `m`; `Delta N=F+E` |
| Transfer / reissuance | Recipient submits old notes as inputs and new blinded outputs; validate note signatures before spent checks; each input nonce becomes spent globally in that Mint instance | `I=sum(input 2^d)`, `O=sum(output 2^d)`, `I=O+F+E`; Wallet unchanged; liability falls by `F+E`, so `Delta N=F+E` |
| Withdrawal with explicit Mint change | One old-Wallet input; output 0 change, output 1 exact destination; destination and change each satisfy configured dust | `W'=W-V-m`; Wallet core output amount `1000*(V+m)` plus its module fee; actual Bitcoin fee `m`; `Delta N=F+E` |
| Signing / broadcast / confirmation | Unsigned transitions to signed-unconfirmed after first q valid guardian lists; later canonical scan removes confirmed entries | No Wallet value, Mint liability or audit delta; retained full chain unchanged |

For issuance, fetch `signature_shares` for exact output ranges from q distinct guardians. Responses contain shares without indices and omit missing entries: a shortened list is incomplete, not proof that later shares moved to earlier indices. Verify every share against its requested blinded message, denomination and guardian key; interpolate at `peer_id+1`, unblind and verify the aggregate note. Honest share lists differ. A successful later spend corroborates issuance validity, but does not substitute for the driver's share checks.

For transfer, exporting a token or observing its face value is not final receipt. Require recipient reissuance acceptance and spendable new notes; track sender change independently. Replay of the same accepted transaction ID is API-idempotent and must not mint twice. A distinct transaction attempting the same valid old note must reject as spent. Rejected transactions must leave discoveries, Wallet/chain, Mint counters, shares and recovery records unchanged; a submission-only check also commits none of them.

## Quotes and pending change

At each acceptance boundary record `consensus_feerate`, `receive_fee`/`send_fee`, both chain endpoints and relevant signed history. Present fee votes are sorted ascending and the qth value selected; fewer than q present votes means `null`. A first `None` vote is distinct from an identical repeat of a stored `None`. Do not manufacture a rate when Core has none. Proposer floor 1,000 sat/kvB is not a consensus admission floor.

Let P include unsigned and signed-unconfirmed transactions, `k=|P|`, configured base rate `b_r`, and target configured size `v`. Compute:

```
r = max(consensus_rate, b_r * 2^k)
individual = floor(min(v*r, 2^64-1)/1000)
package = floor(min((v + sum(P.vbytes))*r, 2^64-1)/1000)
quote = max(individual, max(package - sum(P.fees), 0))
```

For ordinary n=4/q=3 configuration, receive size is 316 vB and send size 228 vB; use actual config. With genuine consensus rate 1,000, base 250 and no pending entries, these give 316 and 228 sat. Pending growth can change quotes: recompute, do not assume the initial values. Supplied mining fee may exceed the quote; all accounting uses the **supplied** amount. A stale quote rejects only when now insufficient, not because of age. Quote snapshots can race consensus, so attribute a mismatch using the ordered acceptance state.

To prove pending-change spending, retain the first constructed transaction as unconfirmed while accepting a second funded action. Its input 0 must reference the first unsigned txid's output 0, and the latest Wallet must reference the second txid output 0. Check parent-before-child broadcast/retry evidence and Core mempool/block ancestry. `pending_transaction_chain` is newest first; `transaction_chain` is construction order, oldest first. The first deposit creates no pending entry. Confirming ancestors and descendants removes each signed-unconfirmed entry, preserves chain history and changes subsequent package quotes without changing audit assets.

Keep the monetary smoke run well below the baseline invariant limit. Fee calculation at k=32 can succeed and construction can produce k=33; the next fee calculation asserts before rate availability. This is a separate fatal-boundary test, not expected ordinary backpressure.

## Public API and Bitcoin cross-checks

Use each configured Wallet instance's `consensus_block_count`, `output_info_slice([a,b])`, `federation_wallet`, `transaction_id({txid,out_idx})`, fee and chain methods. Discovery ranges are half-open; missing/non-P2WSH entries are omitted and indices can have gaps. Discovery `spent` means claimed through Wallet, not observed spent on Bitcoin. Bitcoin outpoints use `vout`; Fedimint output locations use `out_idx`. Chain `input` is the previous Wallet value and excludes the second deposit input; `output` is the new Wallet value; `created` is consensus block count, not time.

For a deposit at height h, require consensus count greater than h and actual scan evidence. Backend count includes genesis; advance a to b scans `[a,b)` after backend count reaches at least b+6. Tip height h+6 is the minimum backend depth allowing selection/scanning through h+1; the ordinary plus-five proposal cap and consensus progress may delay it. Local Core confirmation alone does not prove discovery. Confirm filter/script derivation against fresh Wallet keys; a filter match alone proves no ownership.

Decode Core raw transactions with the independent [Bitcoin codec](../../src/bitcoin/mod.rs): require whole-input decoding, compare `encode_without_witness`, `txid`, `encode`, `wtxid` and `weight` against public Core observations. Display txids reverse digest bytes; tweaks and ordinary SHA-256 hashes do not. Bitcoin CompactSize and little-endian transaction fields must not be replaced with Fedimint BigSize. Actual vsize is `ceil(weight/4)` and may differ from stored configured `vbytes`.

Constructed Bitcoin transactions must be version 2, locktime 0, sequence `0xfffffffd`, empty scriptSig, ordered inputs/outputs as above. Derive claimant tweak `SHA256(E(compressed claimant key))`; change tweak `SHA256(E(previous Wallet record))`. Add tweak to each configured guardian key, sort resulting compressed keys and build q-of-n P2WSH. Check exact scripts and satoshi values, not only addresses. Validate SegWit-v0 SIGHASH_ALL with every input's original amount and witness script. Final witness contains empty dummy, first q accepted guardian signatures sorted in that input's tweaked-key order with `01` suffix, and witness script. Low-S is required; low-R is not. A common txid alone cannot prove identical witnesses.

Use Core mempool/raw-transaction observations to distinguish construction, broadcast admission and confirmation. Require exact input-minus-output fees from known previous outputs, not configured vsize times a rounded observed rate. A failed broadcast does not undo accepted state; retry success must retain the same constructed transaction. Compare all guardians at a common accepted-history boundary to avoid treating transient lag as divergence.

## Evidence required before claiming completion

Retain per-stage public snapshots and decoded accepted transactions, exact arithmetic ledger, q-verified history, actual Core raw transactions/block inclusion, private driver success/error captures and bounded child cleanup results. The final report must separately state which of first deposit/issuance, consolidation, recipient reissue, withdrawal, pending-change spending, confirmation and restart/recovery passed. Empty-transaction consensus, CLI joining/help, estimator conditioning and synthetic pre-generated notes do not establish these monetary stages. No upstream CLI amount grammar or unobserved JSON schema is supplied by this guide.
