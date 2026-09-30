# Remaining implementation and acceptance gates

Reconciled on 2026-09-11 against the [guardian-only plan](superpowers/plans/2026-09-10-fedimintd-implementation.md), audits and endpoint/results ledgers. Healthy mixed monetary evidence and the successful 1219.20-second four-survivor run now close D1.3, D8.4, D13.3, D13.4 and D13.7. The four survivor capture tests run by default with no ignores. This document maps the six remaining unchecked clauses; it does not redefine completion around the implemented subset.

Read-only `git -C spec ls-remote origin HEAD` completed successfully and returned `06277f7e8e2c5cde5b1fe9b768f37f987e3c0c4c`, identical to the local pin. No newer default-branch amendment was available at this check. No checkout or implementation-source change was made.

| Remaining plan clause | Required next work and authoritative prerequisite |
| --- | --- |
| D4.2 — signed endpoint/metadata server interfaces | Obtain normative native administrative signing request/result schemas, then implement and test those routes. Typed signing and public storage/verification already exist. |
| D8.1 — Wallet proposer policy | Resolve Q16 for a reachable Core response without a fee estimate. Genuine estimator conditioning allowed subsequent experiments but does not define this branch. Do not substitute a fabricated fee observation. |
| D12.1 — complete native RPC/auth/wrappers/polling | Finish the native schemas and routes listed below, including exact error/auth behavior; retain existing tested WebSocket, long-poll and request-auth boundaries. |
| D12.2 — all target APIs and required admin operations | Obtain missing normative contracts and complete every required route. Q14 session-state selection and Q15 nonnormalized backup timestamp interpretation remain unresolved. Do not advertise core0.9 until its required earlier endpoints and semantics are complete. |
| D12.3 — evidence table and missing definitions | Keep the existing full endpoint ledger current as definitions arrive and handlers pass. The inventory itself is complete; obtaining/implementing required definitions is not. |
| D12.5 — operational lifecycle/status | Implement required native operational/admin interfaces after their contracts are supplied. Process setup, persisted reopen, signals, joined shutdown and secret-safe error boundaries have evidence; they are not substitutes for native API methods. |

The missing operational contracts are enumerated in [the endpoint ledger](api-capabilities.md): `chain_id`, broader diagnostic-config behavior, `status`, `consensus_ord_latency`, `p2p_connection_status`, `shutdown`, `audit`, `download_guardian_backup`, `auth`, `sign_api_announcement`, `sign_guardian_metadata` and `backup_statistics`. Some are unregistered; some return an explicit schema error. Their present behavior is not successful API conformance. The [writer handoff](spec-writer-questions.md) requests normative requests, results, authorization, errors and relevant lifecycle semantics.

Remaining work is substantial but definition-dependent. The independent local implementation/evidence tasks previously listed in the audits are integrated. Generic zero-byte collection support, an unused unbounded-reader API, arbitrary combinations of crash points, a new client and optional client balance restoration must not be introduced merely to keep working while the actual gates remain unresolved. The mixed monetary requirements now have their recorded evidence. Full required server API conformance remains the objective.
