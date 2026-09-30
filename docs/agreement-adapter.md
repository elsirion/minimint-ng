# Pinned engine adapter contracts

NET-014 fixes fedimint-aleph-bft 0.36.0. Consult its public Rust API documentation; do not inspect the Fedimint application source or reconstruct agreement internals from the explanatory spec summaries.

The [backup writer](https://docs.rs/fedimint-aleph-bft/0.36.0/fedimint_aleph_bft/trait.BackupWriter.html) returns an asynchronous Result; the adapter must finish Store's durable append before returning success. The [reader](https://docs.rs/fedimint-aleph-bft/0.36.0/fedimint_aleph_bft/trait.BackupReader.html) returns the entire exact stream for the current session. Both use the existing store namespace and session index; cleanup belongs to the application completion transaction after engine stop.

Override [unit_finalized](https://docs.rs/fedimint-aleph-bft/0.36.0/fedimint_aleph_bft/trait.FinalizationHandler.html), forwarding creator, round and optional data. The simpler data-only callback loses empty units and thus cannot implement the session boundary. The [spawn interface](https://docs.rs/fedimint-aleph-bft/0.36.0/fedimint_aleph_bft/trait.SpawnHandle.html) must propagate essential-task panic/failure through its completion future.

Direct futures 0.3.32 and parity-scale-codec 3.7.5 expose types/traits already required in the pinned engine graph. They are explicit shared-dependency exceptions, not newly independent library choices. The SCALE dependency has defaults disabled and adds no features; enabling std would change its graph. No new package identity or thread-pool feature is required. Backup callback errors are std::io::Error. A dedicated OS thread can drive each engine task through the existing futures executor, allowing synchronous durable store calls without blocking another engine task. Session termination still must be awaited; detached OS threads are not completion evidence.

Initial adapter tests cover backup and task plumbing. Complete D9 still requires authenticated keychain/multisignatures, exact attached SCALE data, included-data checks, network routing, ordinary delays, finalized ordering and four-engine/restart evidence.
