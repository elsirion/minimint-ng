# Interoperability artifact handoff

Current status (2026-09-10): the exact-baseline reference daemon has now been built in an isolated private checkout, its executable SHA-256 recorded, and its `version-hash` verified against `0c316439d60b5a08eea26fab216780eb893c45bf`. The [interop profile](../../tests/interop/profile.json) records the artifact; [the final build record](#verified-reference-build--2026-09-10) below records provenance and the actual output-path correction. Later verified artifacts support completed mixed setup/nonmonetary sessions and direct Wallet/Core transaction confirmation. Mixed monetary issuance remains blocked at Q17. See the current [results ledger](results.md), [driver handoff](driver-handoff.md) and [retained Wallet/Core provenance](../../tests/fixtures/interop/wallet-core-2026-09-10/PROVENANCE.md). Acquisition instructions below retain their historical context; they are not a claim that those completed steps remain outstanding.

The following metadata checkpoint predates that build on the same date. Its inspected workspace inputs were [the operator handoff](../../spec/verification/two-module-handoff.md) and the interop profile. At that checkpoint no artifact had been downloaded, built, installed or executed, and `bitcoind`, `bitcoin-cli` and `fedimintd` were absent from the ordinary shell PATH (not an exhaustive filesystem/Nix-store search).

## Initial metadata checkpoint: what is obtainable

| Component | Evidence | Required next step |
| --- | --- | --- |
| Exact reference `fedimintd` | Git commit metadata exists for `0c316439d60b5a08eea26fab216780eb893c45bf`, committed 2026-08-14. GitHub marks the commit signature verified; no independent local signature verification was performed. | Obtain an operator-built artifact from this exact revision with build provenance and a measured executable SHA-256. |
| Published reference release | Latest listed release was `v0.12.0`; its resolved tag commit is `2ead392ba22141bbe5898cdb724ec3dbc55387a9`, which differs from the required baseline. The release includes Linux daemon and CLI assets with GitHub asset digests. | Do not substitute it for the specified `0.13.0-alpha` baseline. A release name, asset digest or normalized version alone does not prove the required source commit. |
| Bitcoin Core | Official download page offered Bitcoin Core **31.1**, including an x86_64 Linux archive and checksum/signature files. This is a candidate pin; the current profile specifies no Core release. | Operator selects/pins the version, verifies signed checksums, records the archive and extracted `bitcoind`/`bitcoin-cli` digests, and smoke-tests regtest RPC compatibility. |
| External transaction driver | `external_transaction_driver` is null. Published `fedimint-cli` assets exist for the different release above, but no exact-baseline executable/CLI command contract has been established. | Obtain a compatible external black-box driver, preferably a companion CLI built from the exact baseline; record provenance, actual `--help` output, command templates and machine-readable outputs. No wallet/client implementation is added to this daemon project. |

Primary metadata references: [baseline Git object](https://api.github.com/repos/fedimint/fedimint/git/commits/0c316439d60b5a08eea26fab216780eb893c45bf), [release metadata](https://api.github.com/repos/fedimint/fedimint/releases?per_page=100), [v0.12.0 tag reference](https://api.github.com/repos/fedimint/fedimint/git/ref/tags/v0.12.0), [release page](https://github.com/fedimint/fedimint/releases/tag/v0.12.0), [Bitcoin Core download and verification instructions](https://bitcoincore.org/en/download/).

The first 100 release records contained no release with `target_commitish` equal to the exact baseline. That field can be a branch name, so this is not proof that no exact-commit artifact exists anywhere. The latest release's tag was resolved separately as above. Exact-head Actions metadata listed 350 runs across four pages; routine successful runs examined had no artifact records. None of these searches establishes a reusable binary digest for the baseline.

The two successful exact-head **CI (nix)** runs, [31818768155](https://github.com/fedimint/fedimint/actions/runs/31818768155) and [31815755162](https://github.com/fedimint/fedimint/actions/runs/31815755162), each returned an empty Actions artifact list. The two successful Backwards-Compatibility runs (31818768159 and 31815755192) and Publish docs run (31818768212) also returned empty lists. This is a bounded artifact-metadata check, not inspection of workflow source, job logs, build caches or all historical runs; it does not prove that no privately held or externally published exact-baseline binary exists.

## Reference build supplied by an operator

Use an isolated checkout/build environment, not the minimint-ng workspace. The operator handoff provides the following build recipe; it has not been executed in this review:

```sh
git rev-parse HEAD
git diff --exit-code
nix develop -c cargo build --locked --release --bin fedimintd
sha256sum target/release/fedimintd
target/release/fedimintd version-hash
```

Before running the build, require HEAD to equal `0c316439d60b5a08eea26fab216780eb893c45bf`, a clean working/index state, and unchanged baseline Cargo/Nix lockfiles. Preserve the pinned upstream development environment. Do not apply local dependency or feature substitutions to make a build pass. A failure is an operator/build handoff issue to report with sanitized logs.

The handoff bundle must contain:

- Executable path, platform/architecture, measured SHA-256, and the exact `version-hash` output.
- Source repository and revision, clean-tree evidence, Cargo.lock and Nix lockfile hashes, build command/features, toolchain/native dependency provenance and build log.
- Actual `fedimintd --help` output from the verified artifact and any required runtime library/Nix closure packaging. The current handoff supplies options, not proof that a produced executable starts on this host.
- Producer identity and authenticated transfer/attestation. Recompute the executable digest after transfer; compare against the producer's record. A source SHA is not an executable SHA, and a matching self-reported version hash alone is not binary provenance.

If a matching prebuilt CI artifact is later found, record its workflow/run ID, exact `head_sha`, artifact ID/name, expiration status and archive digest. Verify the extracted executable independently and collect the same version/provenance evidence. Do not substitute a mutable branch, `latest` image tag, or a differently resolved release tag. Leave `reference_artifact` null until this evidence is available.

A companion exact-baseline `fedimint-cli` is a candidate external driver. Its actual build target/options and client operation commands must be supplied or verified from public build metadata and the verified executable's help output; no module command syntax is inferred from implementation source. Do not run upstream test/vector bridges or devimint scenarios as an alternative driver.

## Bitcoin Core operator handoff

Acquisition update, 2026-09-10: Bitcoin Core **31.1** x86_64 Linux is downloaded and verified. Archive SHA-256 is `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`. The checksum list has a valid signature under primary fingerprint `E777299FC265DD04793070EB944D35F9AC3DB76A`, matching the fingerprint in the [official verification instructions](https://bitcoincore.org/en/download/); the public key came from the linked Guix builder-key repository. GPG reported other signatures with unknown public keys: those signatures are not claimed verified. No independent reproduction of the release build or broader trust-web verification is claimed.

The extracted, unchanged `bitcoind` SHA-256 is `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`; `bitcoin-cli` is `4e3a0fde23ec768a61cdd193602be937b29b6e8f21bcb614af87a2786bf86034`. Paths and launcher provenance are recorded in the profile. On this NixOS host the archive's FHS interpreter path is absent, so the verified ELF is launched explicitly through the development environment's pinned glibc loader; the binary is not patched. Version output identifies `v31.1.0`.

At the initial Core smoke checkpoint, a private local node was running with regtest, inbound Bitcoin networking disabled, and loopback RPC. Cookie authentication stays in a protected file. The external Core wallet mined 101 regtest blocks; `getblockchaininfo` reports regtest, height 101 and initial-block-download false. `estimatesmartfee 6` honestly returns insufficient data, without a fee rate. This is live node/RPC smoke evidence, not a monetary federation test or usable fee estimate. Do not substitute a fake estimate to pass Wallet fee tests.

Official artifact and verification URLs:

- [bitcoin-31.1-x86_64-linux-gnu.tar.gz](https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz)
- [SHA256SUMS](https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS)
- [SHA256SUMS.asc](https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS.asc)

Historical acquisition instructions (superseded by the verified digest/signature record above): at the initial metadata checkpoint the checksum link had been identified but its contents and signatures were not yet verified. Follow the official signed-checksum procedure with independently authenticated signer fingerprints; then hash the extracted executables and capture both version outputs. Record a fixed version/path/digest tuple in the eventual run profile rather than resolving the latest release during a test.

The operator must supply a private, disposable regtest data directory, loopback RPC at `127.0.0.1:18443`, isolated credentials/configuration, and the exact startup/shutdown command. Require transaction/block RPC access and a separate funded regtest wallet/mining address for the external driver. Confirm the required calls against the selected binary: block count/hash/raw block retrieval, fee estimate, raw transaction broadcast, wallet creation/address/funding and block generation. Select the exact wallet/mining command syntax from that binary's public help; those commands had not been executed at the initial metadata checkpoint. Subsequent actual commands and outcomes are recorded in the results ledger.

Mine and wait according to the handoff's buried-block scan contract. The backend count includes genesis. A successful response without an estimate remains the unresolved Q16 proposer-policy case; the harness must not fabricate rates or bypass normal proposal generation merely to obtain progress. Record how genuine fee-estimate availability will be obtained or report it as a remaining experiment blocker.

## Guardian launch and setup requirements

The existing profile assigns independent guardians Alice/Bob to IDs 0/1 and reference guardians Carol/Dave to IDs 2/3. Reference P2P/API/UI triplets are 18373/18374/18375 and 18473/18474/18475. Each guardian needs a distinct protected data directory. Follow the exact launch options in the operator handoff, including `--bitcoin-network regtest`, `--enable-iroh false`, advertised `fedimint://` P2P and `ws://` API URLs, Core RPC credentials, and administrator password. These public test credentials are placeholders; private values belong in protected run configuration, not committed logs.

Keep `FM_IN_DEVIMINT`, `NEXTEST` and `FM_BACKWARDS_COMPATIBILITY_TEST` unset. Preserve ordinary R=3600 and 50ms round delay; regtest does not select short test rounds. Harness operation waits must allow ordinary session progress and retry long polls without claiming a different consensus rule.

Before DKG, Alice's `set_local_params` selects federation size 4, name/federation name, base fees enabled, and exactly `mintv2` plus `walletv2`; each other guardian sets its name. Exchange the other three setup codes with every guardian and invoke `start_dkg` on all four. Capture setup status/current checksum, then verify client configuration, normalized release `0.13.0`, core consensus 2.1/API0.9, module consensus1.0/API0.1, Mint ID0/Wallet ID1 and Wallet sizes228/316. The post-setup legacy server commitment is a different hash from the setup checksum.

Module-bearing history recovery must use the federation API with the configured module decoders. The known module-free P2P signed-history path is not a substitute.

## Missing external driver contract

Before filling `external_transaction_driver`, require the operator to provide an executable digest and a complete, tested command/output contract for:

1. Separate durable client states joining the exact two-module federation via the actual invite/configuration mechanism.
2. Deriving a valid WalletV2 deposit destination; funding and awaiting deposit credit through normal Bitcoin/regtest and federation flows.
3. MintV2 issuance, spend/reissue/transfer between two independent client states, with real signatures and operation/transaction identifiers.
4. Withdrawal quote/submission and observation of the resulting Bitcoin transaction and mined confirmation.
5. Recovering client progress after restart and exposing sufficient accepted transaction IDs, output locations, balances and session evidence to assert success independently.

For each operation, specify exact argv, protected credential input, JSON stdout schema, error/exit status, operation identifier, retry/idempotency rules and progress-wait semantics. Keep secret notes, client keys, access/admin secrets and raw private configuration out of shared diagnostics. A CLI being present does not prove it supports the selected MintV2/WalletV2 versions or the required workflows.

Remaining acceptance gates are artifact acquisition/provenance, verified operator CLI behavior, a real external driver smoke test, full daemon configuration/runtime integration and the executed mixed-federation scenarios. This document supplies a concrete handoff, not evidence that those gates have passed.

## Source boundary record — initial metadata review

Only the named spec operator handoff/profile and public release/Git/Actions metadata plus explicit operator download documentation informed this proposal. A broad documentation search unexpectedly emitted implementation-source snippets in its result list; they were treated as an **unconsumed boundary event**, no source links were opened, and no snippet-derived facts or CLI commands were used here. Further retrieval was restricted to metadata endpoints and the allowed handoff. No implementation checkout, source archive, test bridge, binary or transaction driver was downloaded or run.


## Verified reference build — 2026-09-10

The authorized operator build fetched the exact baseline into a new private directory outside this workspace: `/tmp/minimint-upstream-build.2Clk9R/checkout`. Git HEAD matched `0c316439d60b5a08eea26fab216780eb893c45bf`; the checkout was clean before building and tracked files remained unchanged afterward. The host is Linux x86_64 with Nix 2.34.8. The pinned upstream development environment ran this unmodified build command successfully (exit 0):

```sh
nix develop -c cargo build --locked --release --bin fedimintd
```

The actual executable is **`target-nix/release/fedimintd`**, not the operator recipe’s assumed `target/release/fedimintd`. The outer collection script initially exited 21 when its assumed executable path was absent, after the build had already succeeded. A filename-only traversal located the actual executable; no rebuild or source inspection was used to resolve the path.

| Provenance item | Recorded value |
| --- | --- |
| Executable | `/tmp/minimint-upstream-build.2Clk9R/checkout/target-nix/release/fedimintd` |
| Executable bytes | 148072425 |
| Executable SHA-256 | `d51bc18b275ac699c2d20e3ca905bc38f20afdf6b704c14b0524f9eaa20ae8b8` |
| Exact `version-hash` output | `0c316439d60b5a08eea26fab216780eb893c45bf` (exit 0) |
| Cargo.lock SHA-256 | `78d538f1d031156de1ac74039467e93fad52fe3558da1437bab1b253fd3dbf72` |
| flake.lock SHA-256 | `fb4553899cb56f234b3cf639855d9e7c90ec1bf7f9961c19b16a58393167dba5` |
| Input-lock verification after build | Both hashes unchanged |
| Black-box help | [reference-help.txt](reference-help.txt), `--help` exit 0; trailing whitespace normalized, raw capture retained privately |

The private build directory retains the invocation script, complete uninspected logs, input hashes, platform/Nix metadata, artifact digest and exact version output. The executable is usable on this host; relocation/runtime-closure packaging and a second reproducible-build comparison have not been verified. Rehash this temporary-path artifact before each later run or transfer. No complete compiler-log text has been consumed or committed.

This build intentionally fetched and evaluated upstream source through the authorized build tools. The assistant did not inspect Fedimint implementation files, compiler snippets, or bridge source, and did not invoke a bridge. The earlier unconsumed search-snippet event remains historical; the build does not erase it. Only Git/lock/artifact metadata and the verified executable’s public `--help` output informed this update.

The help output describes the daemon and does not establish a companion client build target or monetary command contract. `external_transaction_driver` therefore remains null. It also exposes a default metrics listener on `127.0.0.1:8176`; a same-host mixed harness must assign distinct reference metrics endpoints in addition to P2P/API/UI ports. This observation comes solely from the verified executable help.
