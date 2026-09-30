# minimint-ng

Independent BTC-only Fedimint guardian, under construction from the supplied specification. The `fedimintd` executable connects setup, persistence, consensus and APIs. A mixed 2+2 federation has completed deposits, consolidation, reissuance and a confirmed withdrawal spending pending change, with independent signature and accounting verification. All four monetary survivor sets and guardian restarts passed in a fresh 2+2 run. Inverse peer assignment and opaque backup/restart checks also have evidence. **Full API conformance remains unfinished pending spec definitions.** See the [results and evidence](docs/interop/results.md).

Scope: built-in `mintv2` and `walletv2`, Bitcoin regtest first (signet via Esplora), mutual TLS peer transport with WebSocket APIs or Iroh (guardian P2P over Iroh 1.0.3, client API over Iroh 0.35.0), and the spec-mandated `fedimint-aleph-bft` 0.36.0. Small utilities are local; larger libraries require a dependency review and preference for independent implementations. The target remains two minimint-ng plus two upstream fedimintd guardians, 3-of-4. Current scope is the guardian daemon only; no new client is planned. Existing external tools and fixtures will drive interoperability tests.

Fedimint source is not an implementation reference. The user explicitly permits its pinned Cargo.lock as dependency metadata and use of the exact AlephBFT crate. `vendor-metadata/` records the lock provenance and digest. The separate `spec/` checkout is intentionally excluded from this repository; obtain specification revision `06277f7e8e2c5cde5b1fe9b768f37f987e3c0c4c` from `elsirion/fedimint-spec` when recreating the workspace.

See [implementation plan](docs/superpowers/plans/2026-09-10-fedimintd-implementation.md), [dependency review](docs/dependency-review.md), [resolved inventory](docs/dependency-inventory.json), and [spec issues/pitfalls](docs/spec-pitfalls.md).

With Rust, a C linker and Python 3.11+ available:

```sh
cargo test --locked
python3 tools/dependencies.py check
```

The dependency check verifies the active agreement closure against the approved baseline, including source identity and checksums. It does not claim that packages are free of vulnerabilities or that all transitive dependencies are independent. Cargo may prune unused baseline features; enabled agreement dependency versions must still match. Do not run `cargo update` indiscriminately.

Or enter the content-pinned development environment with `nix-shell`. It supplies Cargo, rustc, rustfmt, Clippy, a linker and Python. Current progress and explicit exclusions are in [implementation status](docs/conformance.md).

Build the development guardian with `nix-shell --run 'cargo build --locked --bin fedimintd'`; `target/debug/fedimintd --help` lists its explicit listener, advertised endpoint, database and credential-file options. The initial process profile is Linux x86_64 with procfs, Bitcoin regtest, plain WebSocket APIs and `fedimint://` peer URLs over mutual TLS. `--bitcoin-network signet` together with `--esplora-url https://mutinynet.com/api` (instead of `--bitcoin-rpc`/`--bitcoin-rpc-credentials-file`) selects the signet profile against an Esplora HTTPS service; see the [dependency review](docs/dependency-review.md) and PIT-036/037 in the [pitfalls](docs/spec-pitfalls.md). `--transport iroh` selects Iroh for a fresh federation: setup codes carry the two endpoint keys instead of URLs, `--api-url`/`--p2p-url` are not used, and `--iroh-discovery`, `--iroh-address-file` and `--iroh-secret-file` control discovery, direct addresses and imported endpoint secrets; see [daemon interfaces](docs/daemon-interfaces.md#transport-selection-and-iroh-profile) and the Iroh section of the [dependency review](docs/dependency-review.md). Secret files must be private regular files; final symlinks are rejected. SIGINT/SIGTERM request joined shutdown. Startup I/O has a 15-second local deadline and shutdown has a 30-second grace period, followed by forced exit code 2 if necessary; neither timer measures agreement progress. OS scheduling can delay enforcement.

Required diagnostic/signing schemas remain open in the writer handoff. Until they are resolved, this development executable advertises no core API minor; it must not be described as satisfying the target core 0.9 profile. Module handlers target 0.1. Stored signed API endpoint updates are selected at startup and polled every second while running. A newly selected destination parks the old endpoint before bounded resolution; unavailable replacements remain parked and are retried without blocking other catch-up peers.

To regenerate the all-target dependency inventory with feature/build-execution metadata:

```sh
cargo metadata --locked --offline --format-version 1 > /tmp/minimint-cargo-metadata.json
python3 tools/dependencies.py check --metadata /tmp/minimint-cargo-metadata.json > docs/dependency-inventory.json
python3 -m unittest discover -s tools -p 'test_*.py'
```
