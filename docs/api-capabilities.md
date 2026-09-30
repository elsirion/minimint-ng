# Guardian endpoint implementation and evidence ledger

Reconciled 2026-09-10 against current source and test assertions; **no tests were rerun for this documentation edit**. Authority: numbered specification revision `06277f7`, especially 03, 07–11 and 14. Target remains core API 0.9 and both module APIs 0.1. The running daemon currently advertises **no core minor**; this ledger does not authorize changing advertisements. Existing external CLI joining does not establish complete advertised-version conformance.

Statuses: **Implemented** means a handler exists for the numbered contract, with the specific coverage stated; it is not a claim that every branch has passed an independent test. **Profile-only** restricts an observed schema to its evidenced profile. **Partial / disputed** identifies unresolved selection or conflicting evidence. **Schema unavailable** is a deliberate error boundary; **Unimplemented** means the inventory method has no native handler. Component assertions, literal vectors, live independent/reference comparisons and synthetic history tests are distinguished below. Historical execution results remain in [conformance](conformance.md) and [interop results](interop/results.md).

Public methods still require configured WebSocket transport access authentication. Admin credentials are separate request authorization. Running dispatch is [RunningApi::handle](../src/daemon/service.rs); setup dispatch is [SetupApi](../src/api/setup.rs). Missing methods must not be inferred from broad test-target names or returned as mock successes.

## Core configuration and identity

Source for the implemented rows: [ConfigApi::dispatch and value renderers](../src/api/config.rs). Native config blobs include their dynamic instance encoding, without an extra RPC byte-vector wrapper. Null params are checked before dispatch.

| Method | Minimum API | Status / schema | Specific evidence and remaining limit |
| --- | --- | --- | --- |
| `client_config` | 0.0 | Implemented, CFG native flattened configuration | `tests/config_api.rs::fixed_cfg_json_is_flat_and_contains_entire_dynamic_encoding` checks a literal nested module blob; `legacy_broadcast_null_and_bigsize_nested_instance_are_explicit` covers null and ID300. Fresh mixed `peer0-client_config.json` captures compare complete public configurations. |
| `client_config_json` | 0.0 | Profile-only: known MintV2/WalletV2 consensus1.0, Wallet regtest | `diagnostic_matches_entire_paired_reference_capture` reconstructs the typed client config from the same federation's native capture and compares the entire peer2 reference diagnostic result, including all Mint key maps. `diagnostic_preserves_ids_and_u64_and_rejects_only_unsupported_diagnostic` checks ID300/u64::MAX/unknown or malformed payload isolation. `tests/daemon_api.rs::running_routes_acceptance_concurrent_waits_and_admin_boundary` checks socket routing and invalid params. Unknown kinds/versions/networks have no inferred diagnostic schema; general normative rules remain open. |
| `invite_code` | 0.0 | Implemented, CFG invite string | `fixed_cfg_json_is_flat_and_contains_entire_dynamic_encoding` includes a literal invite; `compact_invite_selects_first_f_plus_one_peers_and_retains_access_secret_only_there` checks endpoints/secret isolation. Verified external CLI joined via actual invite; joining is not payment evidence. |
| `federation_id` | 0.2 | Implemented, endpoint-map hash string | `fixed_cfg_json_is_flat_and_contains_entire_dynamic_encoding` compares fixed commitment fixture; fresh mixed `federation_id.json` is public reference comparison. Distinct from full config hashes. |
| `server_config_consensus_hash` | 0.0 | Implemented, API-009 legacy hash | Same fixed fixture test plus `broadcast_keys_are_compressed_hex_and_iroh_is_excluded_from_legacy_hash`; mixed `server_config_consensus_hash.json` captures. Legacy omission of Iroh differs from current setup/server checksum. |
| `version` | 0.0 | Implemented explicit support summary | `version_summary_uses_decimal_ids_arrays_and_explicit_capabilities` checks shape/order and rejects inconsistent summaries; `local_membership_support_binding_and_null_params_are_checked` binds configured module versions. This does not prove endpoint availability sufficient for API0.9. |
| `fedimintd_version` | 0.4 | Implemented independent software identity | `version_summary_uses_decimal_ids_arrays_and_explicit_capabilities` checks the supplied independent identity. It is not the upstream revision or normalized setup release. |
| `chain_id` | 0.9 | Schema unavailable, explicit service error | Reference fixtures contain a string equal to the observed node's block1 display hash. This is not a normative derivation: pre-block1, reorganization and backend-failure behavior remain undefined. No native successful result is claimed; see Q11/chain-ID follow-up. |

Public paired diagnostic samples: [reference API manifest](../tests/fixtures/interop/reference-api-2026-09-10/manifest.json) and [same-federation native config](../tests/fixtures/interop/mixed-failure-2026-09-10/peer0-client_config.json). A malformed raw diagnostic payload does not prevent constructing the standalone ConfigApi/native response. Running service configurations are separately validated before installation; internal invalid-configuration errors there follow its fatal-state policy.

## Transactions and history

Source: [CoreRequest::decode / CoreOperation::poll](../src/api/core.rs), backed by [session state](../src/core/session.rs). RPC_HEX and RPC_BASE64 include the consensus byte-vector length and one-element JSON array. All numeric u64 values preserve exact integers.

| Method | Minimum API | Status / schema | Specific evidence and remaining limit |
| --- | --- | --- | --- |
| `submit_transaction` | 0.0 | Implemented API-004 / TX | `tests/core_api.rs::queue_ack_is_pending_full_retries_without_revision_and_acceptance_is_idempotent`, `submission_invalid_encoding_is_outer_error_and_validation_is_encoded_with_rollback`, `pending_submission_revalidates_after_another_transaction_spends_deposit` and `signature_phase_refusal_retries_next_session_and_waits_for_durable_acceptance`. The latter uses actual Session/ProposalQueue transitions and reopen, with n1 isolating handler persistence. `tests/daemon_api.rs` socket test checks committed acceptance, not just queue insertion. Mixed evidence covers empty transactions; fresh mixed funded issuance produced external-client notes; complete monetary lifecycle evidence remains open. |
| `await_transaction` | 0.0 | Implemented API-005 | Core pending/accepted test above and socket test's concurrent waits check committed state. Unknown transactions wait; malformed requests reject. Accepted IDs do not reexecute. |
| `await_output_outcome` | 0.0 | Implemented API-006 | `output_ranges_validate_before_wait_empty_ranges_still_wait_and_absent_outcome_is_error` and `accepted_builtin_output_is_null_in_batch_and_missing_in_single_query` distinguish waiting for acceptance from missing generic outcome. Mint and Wallet supply no generic outcome, so a valid accepted output yields the missing-outcome error. |
| `await_outputs_outcomes` | 0.8 | Implemented API-006 | Same two tests check half-open ranges, 1024 limit, index validity, waiting even for empty range, and `null` for each accepted built-in output. This differs from the single-output error. |
| `session_count` | 0.0 | Implemented finished count | `boundary_reproposes_and_history_waits_return_exact_wrappers` asserts count1 after completion; real process/mixed tests poll completed counts. Count does not imply a pending session is finalized. |
| `await_session_outcome` | 0.0 | Implemented original outcome RPC_HEX | `boundary_reproposes_and_history_waits_return_exact_wrappers` checks exact wrapper against completed outcome and contrasts signed form. Local structured comparison, not a new independent binary vector. |
| `await_signed_session_outcome` | 0.0 | Implemented signed outcome RPC_HEX | Same core test checks pending→complete behavior; real mixed signed responses are independently reverified in `tests/mixed_history_capture.rs::captured_mixed_history_authenticates_all_four_certificates_and_rejects_changes`. Fresh artifact identity still matters. |
| `session_status` | 0.1 | Partial, Q14 selection unresolved | Handler serializes original status; `tests/session_status.rs::independent_literal_status_envelopes_and_legacy_conversion` tests literal encoding/conversion. `tests/core_api.rs::persisted_nonempty_status_handlers_preserve_wrappers_and_legacy_completion_after_reopen` checks decoded requests, literal nonempty Pending/legacy Complete envelopes and finished counts across reopen. Empty-current/future states without a persisted observation return explicit policy error. Reference future-index `Initial` captures do not settle all empty-current/restart cases. |
| `signed_session_status` | 0.5 | Partial, Q14 selection unresolved | The persisted-status handler test checks literal nonempty Pending BASE64 and retained completed certificate across reopen; the core history-wrapper test also checks completed RPC_BASE64; `tests/session_status.rs` covers literal variants and malformed bodies. Same missing-state policy as original status. Future-index reference samples are evidence, not implemented full selection semantics. |

`tests/daemon_catchup.rs` verifies configured module decoding, signature/index checks, outer RPC errors, authentication and cancellation. `tests/daemon_endpoint_refresh.rs::rpc_endpoint_move_is_durable_and_restored_process_uses_new_destination` covers a real announcement→store→poll→new-endpoint→restart path with synthetic signed module history. Neither establishes an external monetary history replay.

## Opaque backups and signed updates

Subsequent mixed evidence: [public recovery fixtures](../tests/fixtures/interop/mixed-recovery-2026-09-10/manifest.json) record exact normalized opaque backup recovery, code-400 timestamp rejection, replacement and all-four process restart. `tests/mixed_recovery_capture.rs` verifies those signed requests and replays them through local durable storage. Native error messages differ; code/behavior match.

Sources: [backup handlers](../src/api/backup.rs), [AnnouncementApi](../src/api/announcements.rs). These methods store server-side opaque objects; they do not decrypt backups, derive client secrets, or reconstruct client balances.

| Method | Minimum API | Status / schema | Specific evidence and remaining limit |
| --- | --- | --- | --- |
| `backup` | 0.0 | Implemented normalized REC-007/008 domain | `tests/backup_api.rs::fixed_signing_preimage_and_digest_have_only_legacy_consensus_fields` is a fixed-domain digest; `payload_limit_is_inclusive_and_ciphertext_structure_is_not_checked`, `every_signed_field_and_signature_are_bound_before_any_replacement`, `simultaneous_identical_requests_cannot_both_replace_the_snapshot` test inclusive131072 limit, authentication and atomicity. Socket upload in `tests/daemon_api.rs`. Q15 nonnormalized timestamp interpretation remains unverified. |
| `recover` | 0.0 | Implemented public-key lookup / nullable snapshot | `native_upload_and_public_recovery_are_opaque_and_survive_reopen` checks missing/value/reopen without owner signature; `tests/daemon_api.rs` checks socket retrieval. No actual client restore claim. |
| `api_announcements` | 0.3 | Implemented CFG signed peer map | `tests/announcements.rs::announcement_native_rpc_nonce_checks_and_identity_map_immutability` checks map response; `both_signed_record_types_reopen_and_invalid_stored_signature_is_detected` checks durable verified reads; daemon socket test reads it. |
| `submit_api_announcement` | 0.3 | Implemented CFG authenticated monotonic update | Same announcement RPC test checks identity/nonces; `invalid_keys_signatures_and_parsed_content_leave_local_records_unchanged` rejects bad data; real endpoint-refresh process test traverses this route. Signed operational URLs do not mutate immutable federation identity. |
| `guardian_metadata` | 0.9 | Implemented CFG signed metadata map | `metadata_optional_endpoint_unknown_fields_and_fullwidth_time_are_preserved` and `both_signed_record_types_reopen_and_invalid_stored_signature_is_detected` cover values/reopen. These are component assertions, not a live reference metadata comparison. |
| `submit_guardian_metadata` | 0.9 | Implemented CFG signed content | `independent_literal_domains_and_exact_original_json_bytes` tests domain bytes; `metadata_future_bound_is_inclusive_saturating_and_old_data_has_no_age_rejection`, `metadata_idempotence_uses_bytes_and_replacement_requires_strictly_later_time`, and invalid-data rollback tests cover acceptance. Typed signing exists; native admin signing request shapes remain unavailable below. |

## Setup endpoints

All six methods are registered at API0.0. Sources: [SetupApi::dispatch](../src/api/setup.rs), [SetupState](../src/setup/admin.rs), and running `setup_status` in [service](../src/daemon/service.rs). Server transport authentication remains distinct from the authorization column.

| Method | Authorization | Status / result | Specific evidence and remaining limit |
| --- | --- | --- | --- |
| `setup_status` | Public | Implemented three status strings | `tests/setup_api.rs::admin_required_parameters_idempotent_and_handoff_not_completion` checks AwaitingLocalParams/SharingConnectionCodes; `tests/daemon_api.rs` checks ConsensusIsRunning. `start_dkg` returning does not imply generation finished. |
| `set_local_params` | Admin | Implemented local setup-code string | Setup API test above plus `invalid_fields_and_failed_driver_handoff_leave_setup_retryable` covers shape/type failures; actual process setup tests exercise the socket route. |
| `add_peer_setup_code` | Admin | Implemented peer name | `idempotent_parameter_and_peer_repeats_survive_driver_handoff` tests four-peer input and repeated codes; mixed fresh setup exercises actual interoperability. |
| `reset_peer_setup_codes` | Admin | Implemented null; retain local state | `tests/setup_api.rs::successful_native_reset_preserves_local_identity_params_and_allows_peer_retry` checks literal null, unchanged private identity/certificate/local code/parameters and successful peer reimport. `admin_denials_preserve_imports_and_running_setup_mutations_are_unregistered` checks unauthorized state preservation and running-state lookup. These are actual decoded-request/handler checks, not an additional socket/DKG run. |
| `get_setup_code` | Admin | Implemented nullable code | `tests/setup_api.rs::authorized_setup_code_is_null_then_exact_string_and_rejects_nonnull_params` checks both authorized forms, unauthorized401 and non-null-parameter400. The running-boundary test verifies the setup-only method becomes unregistered. |
| `start_dkg` | Admin | Implemented null after dispatch | `admin_required_parameters_idempotent_and_handoff_not_completion` checks one job dispatched and repeat rejected; failed-handoff test checks retryability. `tests/setup.rs` / mixed setup separately establish all-four42-DKG completion and matching config. |

`restart_federation_setup` is explicitly unregistered in the baseline and remains absent. Independent fresh setup/persisted reopen is in scope; importing upstream guardian archives is not implied.

## Operational/admin inventory without complete schemas

Document07 inventories these methods but does not supply their full verified contracts. Unimplemented methods fall through native method lookup; this is not the same as a method-specific schema-error handler. Do not claim auth checks for an unregistered method merely because the inventory calls it admin.

| Method | Authorization stated by specification | Implementation / evidence / gate |
| --- | --- | --- |
| `status` | Not explicit | Unimplemented; exact request/result/auth required. No successful native test. |
| `consensus_ord_latency` | Not explicit | Unimplemented; request/result/auth required. No successful native test. |
| `p2p_connection_status` | Not explicit | Unimplemented; request/result/auth required. Internal peer status getters do not supply its JSON contract. |
| `shutdown` | Admin | Unimplemented native method; request/result/timing required. SIGINT/SIGTERM and watchdog tests establish process shutdown only. |
| `audit` | Admin | Unimplemented native method; request/result required. Mandatory per-item internal audit is implemented and is not this API. |
| `download_guardian_backup` | Admin | Unimplemented; request/result plus archive scope required. No upstream archive compatibility claim. |
| `auth` | Admin | Unimplemented native method; request/result required. Existing request-level admin checking is not an `auth` endpoint. |
| `sign_api_announcement` | Admin | Schema unavailable; service checks admin then returns explicit schema error. `tests/announcements.rs::undocumented_admin_json_shapes_are_not_guessed` and daemon socket test check refusal/auth boundary. Typed signing helper is implemented, not native request parsing. |
| `sign_guardian_metadata` | Admin | Schema unavailable; same service auth/error route, both names tested by `undocumented_admin_json_shapes_are_not_guessed`. Socket test explicitly exercises announcement signing, not both names. |
| `backup_statistics` | Admin | Unimplemented; request/result required. Opaque backup storage tests are not this endpoint's coverage. |

## Mint module methods

Wire name is `module_<configured instance ID>_<method>`; all public at API0.1. Source: [module dispatch](../src/api/modules.rs), [Mint](../src/modules/mint/mod.rs). Native JSON has no RPC_HEX wrapper. Tests use arbitrary configured IDs42/7 and reject unknown/misrouted/noncanonical textual IDs.

| Method | Status / contract | Specific evidence and remaining limit |
| --- | --- | --- |
| `signature_shares` | Implemented: existing output-location order, omitted gaps, no acceptance wait | `tests/module_api.rs::mint_sparse_outputs_repeated_recovery_and_exact_missing_error` creates real outputs and checks missing locations; `tests/mint.rs::repeated_blinded_lookup_overwrites_and_missing_locations_are_omitted` covers underlying index. Replies omit indices/null placeholders; a shortened list is incomplete for threshold issuance. |
| `recovery_signature_shares` | Implemented: request order including duplicates; whole-call400 on any missing share | Same sparse module API test asserts exact `No blinded signature share found` error and repeated-request ordering; `empty_state_native_nulls_ranges_and_configured_instances` checks empty request. Honest guardians return different shares, not matching-response votes. |
| `recovery_count` | Implemented exact u64 | Sparse module API test checks count after issuance/spends; empty-state test checks0; native malformed-parameter test rejects coercion. |
| `recovery_slice` | Implemented half-open indexed selection / records without indices | Sparse module API test checks tagged Output/Input native objects and ranges; empty-state test covers huge absent range without allocating it. |
| `recovery_slice_hash` | Implemented SHA256(consensus-encoded returned list) | Sparse module API test checks nonempty slice/hash correspondence; empty-state test checks literal SHA256(`00`). Own nonempty encoding comparison is not an independent external hash fixture. |

MINT-015 literal/error tests and real local issuance/unblind/spend tests supplement these rows. The separate mixed setup/recovery run compares all five empty Mint methods before and after all-four restart; it does not establish nonempty external share/recovery behavior. The stopped external deposit attempt had recovery count0 and did not verify a successful live issuance/share workflow.

## Wallet module methods

Wire name uses the configured instance ID, with API0.0 methods and target/advertised module API0.1. Source: [module dispatch](../src/api/modules.rs), [Wallet](../src/modules/wallet/mod.rs). WAL-016/017 define native JSON and scan behavior; amounts/fees are satoshis, rates sat/kvB, indices/counts exact u64, displayed Bitcoin txids reverse digest bytes. Fedimint output-location requests remain `{txid,out_idx}`.

| Method | Status / contract | Specific evidence and remaining limit |
| --- | --- | --- |
| `consensus_block_count` | Implemented count including genesis | `tests/module_api.rs::wallet_native_schema_sparse_ranges_display_order_and_exact_integers` serializes u64::MAX exactly; empty-state test checks0. Mixed live captures compare all four count108 after real deposit scan. |
| `consensus_feerate` | Implemented nullable agreed sat/kvB | Same native test checks1000 and empty-state test checksnull; Wallet tests verify qth-smallest present vote. Actual driver observed2000. Q16 concerns proposer handling of missing estimates, not this result's numeric units. |
| `federation_wallet` | Populated reference shape verified | Following the 2026-09-11 user decision, native tests assert `{value,outpoint:"txid:vout",tweak}` and exact large values; empty-state/socket/live observations covernull. Fresh first-deposit and consolidation captures directly verify populated strings on all four guardians. |
| `receive_fee` | Implemented nullable satoshi quote, Q16 policy limit | Empty-state test checksnull; `quote_invariant_does_not_break_unrelated_wallet_reads` covers fatal pending-count quote boundary; Wallet component tests check package arithmetic. Actual CLI/public observations632 at agreed2000 and configured316vB corroborate this case, not every pending state. |
| `send_fee` | Implemented nullable satoshi quote, Q16 policy limit | Same empty/boundary/component evidence; actual observation456 at agreed2000 and228vB. Stored estimates are not replaced by measured final Bitcoin vsize. |
| `transaction_id` | Implemented Fedimint output-location lookup / nullable Bitcoin display txid | Native test checks u64::MAX output index and reversed display hash; empty test checksnull. Every fresh monetary survivor case binds the certified Wallet output location to the actual Bitcoin withdrawal txid before and after restart. |
| `output_info_slice` | Reference format implemented and fresh mixed validation passed | The user approved native `"txid:vout"` strings on 2026-09-11. A regression compares the exact retained reference discovery response, display order, leading zeros and maximum vout. Sparse entries and explicit null remain covered. The writer must still correct WAL-016. |
| `pending_transaction_chain` | Implemented newest pending-count records first | Native test asserts `[chain[2],chain[1]]`, then empty after pending removal; empty-state test checks[]. This fixture is local state construction. Healthy mixed captures cover the pending consolidation/withdrawal chain and its clearance after confirmation. Every monetary survivor case also verifies an empty pending chain and matching state after restart. |
| `transaction_chain` | Implemented construction order retained after confirmation | Native test checks fields/large integers and retention; `created` is block count and consolidation `input` excludes deposit input. Local Wallet transitions cover construction. Healthy mixed and all four monetary survivor captures verify guardian-created withdrawals, retained chain records and matching confirmed state. |

[Q17 public conflict](../tests/fixtures/interop/wal016-outpoint-conflict/manifest.json) is written-spec versus baseline API evidence, not a Bitcoin wire-encoding defect. In that historical attempt, the deposit was mined/discovered but Wallet remained null and Mint recovery was zero. Later approved-format runs completed both deposit claims; see the current run results. No compatibility proxy or silent JSON rewrite is part of this ledger.

## Transport, error boundaries and open decisions

`tests/websocket.rs` covers RFC handshake/masking literals, access-secret401, fragmentation, size/time limits and cancellation. `tests/rpc.rs` covers exact IDs, batch/notification rules and separate admin auth. `tests/json.rs` covers full-width numbers, duplicate escaped fields and bounded output. These common tests support shared transport behavior; they do not prove each endpoint's response schema.

Open decisions remain in [writer questions](spec-writer-questions.md): Q14 empty-current/restart status selection (future Initial captures narrow but do not close it); Q15 normalization/signature/order of nonnormalized backup timestamps; Q16 missing-estimate proposer policy despite genuine estimator conditioning; Q17 requires a written-spec correction; its implementation authority is resolved, and populated Wallet reference verification now passes. Required operational/admin schemas and chain-ID rules also remain gates. Closing one row must not silently close these others or enable core API0.9 advertisement.
