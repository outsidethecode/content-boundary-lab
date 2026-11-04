# Threat model

The threats the reference implementation is built to answer, and what answers each. Every row has a reference control and the
tests that exercise it, or says plainly that it is a limitation or out of scope; `tests/test_docs.py` fails if a row
loses its control or cites a test that does not exist. The structure is STRIDE per trust boundary. The first nine rows are
the rows of M0 §3, unchanged; the rest record threats that the implementation of the workflow made concrete. How the pieces
fit is in [architecture.md](architecture.md); the reasoning is in [decisions.md](decisions.md); each public claim is traced
to a test in [claims.md](claims.md).

Passing tests show that a control stops the cases the tests exercise, **under the assumptions stated at the end of this
file**. They do not show the system is free of other flaws. The deliberately seeded defects that would show each case is
reproducible without its control are a later stage (M2) and are not built.

## 1. Actors

| Actor | Trust stance |
|---|---|
| Vendor contributor (external) | Authenticated by the identity provider. Device, network and organisation untrusted. |
| Production coordinator (internal) | Authenticated. Gets no trust from network location. |
| Scanner (service) | Trusted to *produce* verdicts, not trusted to be *correct*. The lab's scanner is synthetic. |
| Identity provider (simulated) | Trusted for identity assertions only, never for project permissions. |
| System jobs (`rescan`, `promote`) | The lab's own work, recorded under named system actors; not authenticated, and run by the operator's code. |
| Platform operator | Out of scope. |

## 2. Attacker profiles

- **T1: over-reaching vendor user.** A legitimate account acting outside its grant. The most likely case.
- **T2: compromised vendor account or token.** Phishing, or malware on the vendor's workstation.
- **T3: former vendor.** The engagement has ended or been revoked.
- **T4: unauthenticated attacker** who can reach the API.
- **T5: malicious content.** The file is the attacker, and the uploader may be innocent.

## 3. Assets and trust boundaries

| Asset | What matters |
|---|---|
| A1 | unreleased reference content (confidentiality) |
| A2 | the trusted production store (integrity) |
| A3 | engagement records (integrity) |
| A4 | scan verdicts and acceptance records (integrity, and their binding to the bytes) |
| A5 | the audit trail (attribution for leak investigations) |
| A6 | the token verification configuration: public keys, issuer, audience |

| Boundary | |
|---|---|
| TB1 | vendor environment → API |
| TB2 | identity provider → API (identity assertions, verified by cryptography, not by network location) |
| TB3 | API → engagement store, the server-side source of truth for authorisation |
| TB4 | quarantine → trusted store. Promotion is the only crossing. |
| TB5 | scanner → API (verdicts) |
| TB6 | staff → API. Internal users get no network-based trust either. |

## 4. Threats and controls

Status is **Implemented** (a control and tests), **Limitation** (stated, with what is done about it) or **Out of scope**.
A test is cited by file and function.

### 4.1 Rows of M0 §3

| ID | Boundary | Threat | Attacker | Control | Tests | Finding | Status |
|---|---|---|---|---|---|---|---|
| TM-1 | TB1/TB2 | Spoofing: identity taken from a header that a gateway supposedly sets | T4, T1 | The application verifies the signed ES256 token itself ([identity.py](../src/content_boundary_lab/identity.py)) and has no code that reads an identity header; claims other than issuer and subject authorise nothing | `tests/test_every_route_requires_a_token.py::test_no_route_answers_anything_but_the_same_401_without_a_verified_token_and_none_changes_state`<br>`tests/test_engagements_api.py::test_identity_headers_and_cookies_are_never_credentials`<br>`tests/test_engagements_api.py::test_identity_headers_do_not_change_who_a_verified_caller_is`<br>`tests/test_identity.py::test_every_algorithm_but_es256_is_refused`<br>`tests/test_identity.py::test_a_key_embedded_in_the_header_is_never_used`<br>`tests/test_identity.py::test_fabricated_permission_claims_are_ignored` | F-01 | Implemented |
| TM-2 | TB3 | Disclosure: another production's asset read by ID | T1, T2 | One query binds asset → its real production → the production the URL named → the caller's current engagement ([assets.get_asset_in_scope](../src/content_boundary_lab/assets.py)); a missing asset and another production's asset are one byte-identical 404 | `tests/test_asset_lookup.py::test_an_alpha_vendor_cannot_find_a_bravo_asset_through_alphas_url`<br>`tests/test_asset_lookup.py::test_a_caller_engaged_in_both_productions_still_gets_only_the_asset_the_url_names_the_production_of`<br>`tests/test_asset_access_api.py::test_every_object_level_miss_is_one_byte_identical_404`<br>`tests/guards/test_asset_scope.py::test_no_module_in_src_reads_updates_or_deletes_an_asset_except_by_the_scoped_statement` | F-02 | Implemented |
| TM-3 | TB3 | Elevation: a revoked or expired engagement still works | T3 | The engagement is read from SQLite on every request, inside the request's `BEGIN IMMEDIATE`, on one injected clock instant ([authz.authorize_engagement](../src/content_boundary_lab/authz.py)); a revocation is final and visible to every request that begins after it commits | `tests/test_authz.py::test_a_revoked_engagement_is_denied_as_soon_as_the_revocation_commits`<br>`tests/test_engagements_api.py::test_a_revoked_engagement_is_refused_at_once`<br>`tests/test_engagements_api.py::test_an_expired_engagement_is_refused`<br>`tests/test_engagements_api.py::test_token_claims_grant_nothing_to_a_caller_without_an_engagement`<br>`tests/test_asset_access_api.py::test_the_same_token_is_refused_after_the_engagement_is_revoked`<br>`tests/test_scoped_revocation.py::test_an_alpha_coordinator_cannot_revoke_a_bravo_engagement_with_bravos_id_under_alphas_production` | F-06 | Implemented |
| TM-4 | TB1→TB4 | Tampering: writes outside quarantine via the filename | T1, T2 | Storage keys are server-generated and the client's name is display metadata only; every path is a checked 32-hex basename opened relative to a no-follow root descriptor ([quarantine.py](../src/content_boundary_lab/quarantine.py)); only `quarantine.py` and `assets.py` touch files | `tests/test_delivery_upload_api.py::test_the_only_new_entry_anywhere_is_the_server_named_file_in_quarantine`<br>`tests/test_quarantine.py::test_publish_refuses_names_that_are_not_server_made_before_it_touches_the_filesystem`<br>`tests/test_quarantine.py::test_a_root_that_is_a_symlink_is_not_followed`<br>`tests/test_asset_access_api.py::test_a_hostile_display_name_cannot_inject_a_header_or_an_unsafe_filename`<br>`tests/guards/test_delivery_scope.py::test_only_the_trusted_and_the_quarantine_modules_open_move_or_delete_files` | F-05 | Implemented |
| TM-5 | TB5 | Tampering: data the caller supplied decides the scan outcome | T1, T2, T5 | The verdict is keyed on, and bound to, the SHA-256 the server computes from the stored bytes through the single function `trust.content_identity`; a declared hash is only compared with it, before any cache lookup or scanner call | `tests/test_seal_api.py::test_a_declaration_that_does_not_describe_the_bytes_is_rejected_before_the_cache_and_the_scanner`<br>`tests/test_seal_api.py::test_the_cache_is_for_the_content_not_for_the_path_the_name_or_the_file`<br>`tests/test_seal_api.py::test_a_cached_verdict_that_is_not_for_this_content_this_scanner_and_this_moment_is_not_reused`<br>`tests/test_delivery_initiation_api.py::test_identical_declarations_are_separate_deliveries_because_a_declared_hash_is_not_an_identity`<br>`tests/test_scanner.py::test_the_reported_digest_follows_the_bytes_not_a_claim` | F-03 | Implemented |
| TM-6 | TB4 | Tampering: bytes swapped after acceptance | T1, T2 | Seal closes writes by state; the acceptance is bound to the sealed digest; promotion hashes and counts the bytes as it writes them into trusted staging and publishes only bytes whose digest is the accepted one ([promotion.copy_verified](../src/content_boundary_lab/promotion.py)) | `tests/test_promotion.py::test_bytes_changed_in_quarantine_after_acceptance_are_never_published`<br>`tests/test_promotion.py::test_a_file_changed_while_it_is_being_copied_cannot_get_past_the_digest`<br>`tests/test_promotion.py::test_the_downloaded_bytes_are_the_bytes_whose_digest_was_verified_during_the_copy`<br>`tests/test_seal_api.py::test_sealing_closes_writes_by_state`<br>`tests/test_acceptance_api.py::test_a_digest_other_than_the_sealed_one_is_refused` | F-04 | Implemented |
| TM-7 | TB1 | Denial of service: oversized upload | T1, T4 | A size cap enforced on the bytes that arrive, while streaming; the vendor's declared size is not the limit | `tests/test_delivery_upload_api.py::test_the_limit_is_enforced_on_the_bytes_that_actually_arrive_and_reading_stops_there`<br>`tests/test_delivery_upload_api.py::test_exactly_the_limit_is_accepted_and_one_more_byte_is_not`<br>`tests/test_delivery_upload_api.py::test_an_honest_content_length_over_the_limit_is_refused_before_any_byte_is_read` | Baseline | Implemented |
| TM-8 | TB6 | Repudiation: an action attributed to the wrong actor | T1 | Audit events name the verified subject only, or one of the two named system actors; nothing in a request can name another actor | `tests/test_identity.py::test_conversion_to_an_audit_actor_is_controlled`<br>`tests/test_acceptance_api.py::test_who_accepted_is_the_verified_caller_and_nothing_in_the_request_can_name_someone_else`<br>`tests/test_audit.py::test_the_system_actors_are_named_identities_in_a_namespace_no_issuer_can_have`<br>`tests/test_engagements_api.py::test_the_audit_count_ignores_events_from_earlier_requests` | Baseline | Implemented |
| TM-9 | TB4 | Real malware gets past the stub | T5 | None. The scanner detects one synthetic marker and has no detection value; its identity says so in every verdict, response and audit event that shows one | `tests/test_scanner.py::test_the_shipped_scanner_is_named_and_labelled_honestly` | Limitation | Limitation |

### 4.2 Rows the implementation added

| ID | Boundary | Threat | Attacker | Control | Tests | Finding | Status |
|---|---|---|---|---|---|---|---|
| TM-10 | TB3/TB4 | A coordinator accepts a verdict that has expired, or that a scanner no longer in use made | T1, T5 | Acceptance rechecks the verdict in the accepting transaction, on that transaction's one clock read: `no_detection`, for H, by exactly the engine, version, kind and policy the server runs now, `valid_until` later than that instant | `tests/test_acceptance_api.py::test_a_verdict_is_acceptable_until_valid_until_and_not_at_it`<br>`tests/test_acceptance_api.py::test_a_verdict_from_another_engine_version_or_policy_is_not_acceptable`<br>`tests/test_acceptance_api.py::test_a_delivery_that_once_reached_scan_passed_is_not_acceptable_merely_for_that` | A9, hash binding | Implemented |
| TM-11 | TB3 | A coordinator accepts the deliveries of a vendor whose engagement was revoked | T3 | Acceptance refuses while the delivery owner's engagement is revoked; natural expiry does not block it | `tests/test_acceptance_api.py::test_a_revoked_vendors_deliveries_can_no_longer_be_accepted`<br>`tests/test_acceptance_api.py::test_the_natural_expiry_of_the_vendors_engagement_does_not_block_acceptance` | A9 | Implemented |
| TM-12 | TB3 | A delivery of another production, or another vendor's, reached by guessing its id (upload, seal, inspect, accept, promote) | T1, T2 | Each delivery lookup is one scoped statement binding the delivery, its real production, the URL's production and the caller's role and engagement; a miss is one generic 404; promotion takes the production as an argument and looks inside it | `tests/test_seal_api.py::test_only_the_vendor_that_owns_the_delivery_can_seal_it`<br>`tests/test_delivery_upload_api.py::test_a_caller_who_is_refused_for_the_production_never_learns_whether_the_delivery_exists`<br>`tests/test_acceptance_api.py::test_a_missing_delivery_and_another_productions_delivery_look_the_same_to_a_coordinator`<br>`tests/test_acceptance_api.py::test_only_a_coordinator_of_the_deliverys_production_can_accept_it`<br>`tests/test_promotion.py::test_a_delivery_of_another_production_is_not_promoted_through_this_one` | F-02 pattern | Implemented |
| TM-13 | TB3/TB4 | Two writers race for one delivery (two seals, acceptances, rescans or promotions) | T1, T2 | Compare-and-set transitions under `BEGIN IMMEDIATE`; only the winner leaves the source state; the no-clobber link is a second barrier for promotion; no scan or copy holds the writer lock | `tests/test_acceptance_api.py::test_two_simultaneous_acceptances_make_one_state_change_and_one_event`<br>`tests/test_promotion.py::test_promoters_racing_for_one_delivery_publish_one_asset`<br>`tests/test_promotion.py::test_a_second_promotion_of_the_same_delivery_is_refused_while_the_first_is_copying`<br>`tests/test_seal_api.py::test_two_seals_of_one_delivery_cannot_both_complete_and_the_scan_holds_no_writer_lock`<br>`tests/test_rescan.py::test_two_rescans_of_one_delivery_cannot_both_run` | Baseline | Implemented |
| TM-14 | TB4/TB5 | A token, or a request, claims to be one of the lab's own system jobs, or starts one | T1, T2, T4 | The `system:` issuer namespace is refused to every configured token issuer and to every actor but the two named ones, each limited to its own events; neither job has a route | `tests/test_audit.py::test_nobody_else_may_use_the_system_namespace`<br>`tests/test_settings.py::test_an_issuer_in_the_reserved_system_namespace_is_refused_by_the_settings_object`<br>`tests/test_rescan.py::test_a_token_naming_the_system_issuer_authenticates_nobody`<br>`tests/test_rescan.py::test_no_route_starts_a_rescan`<br>`tests/test_promotion.py::test_every_event_of_a_promotion_is_the_promotion_jobs_and_no_route_starts_one`<br>`tests/guards/test_delivery_scope.py::test_only_the_rescan_and_the_promotion_job_refer_to_the_transaction_that_runs_as_the_system` | Baseline | Implemented |
| TM-15 | TB4 | A write to quarantine or to the trusted root overwrites a file that is already there | T1, T2 | Placement is a hard link that the kernel refuses when anything occupies the name (a file, a directory, a pipe, a symlink, even a dangling one); the occupant is left as it was | `tests/test_promotion.py::test_a_file_already_at_the_final_name_is_never_overwritten`<br>`tests/test_trusted_store.py::test_publishing_never_replaces_whatever_is_at_the_final_name`<br>`tests/test_quarantine.py::test_publishing_never_replaces_anything_that_is_already_there` | F-05 / F-04 pattern | Implemented |
| TM-16 | TB4 | The recovery pass adopts, overwrites or deletes a file that is not provably the promotion's own, or adopts one that was swapped after it was verified | T1, T2 | Adoption needs the accepted digest and size of every byte, a regular file, the expected link count, and one file fingerprint from the first look to the recording transaction; anything else is left exactly as found and reported; a file at a final name is removed only by device and inode | `tests/test_promotion.py::test_a_file_that_is_swapped_after_it_was_verified_is_not_adopted_and_no_row_is_written`<br>`tests/test_promotion.py::test_a_published_file_that_no_longer_matches_its_own_verified_copy_is_reported_and_preserved`<br>`tests/test_promotion.py::test_cleanup_after_a_failure_never_removes_a_file_that_is_not_the_one_published`<br>`tests/test_trusted_store.py::test_remove_if_same_file_leaves_everything_else_exactly_as_it_is` | F-04 | Implemented |
| TM-17 | TB4 | The association between a promotion's event, delivery, asset and accepted digest is rewritten afterwards | T1, T2 | The binding is rows written once, in one transaction, and the database refuses to change, delete or replace them (see the schema table in [architecture.md](architecture.md)) | `tests/test_promotion.py::test_nothing_the_application_can_run_rewrites_the_record_of_a_promotion`<br>`tests/test_promotion.py::test_the_event_the_delivery_the_asset_and_the_accepted_digest_agree_and_share_one_instant` | F-04 | Implemented |
| TM-18 | all | A decision without its audit event, or an audit event without its decision, after a failure | T1, T4 | State change and audit event commit together or not at all; the flow counts exactly one event per transaction before it commits | `tests/test_audit.py::test_a_failing_audit_insert_rolls_back_the_state_change`<br>`tests/test_acceptance_api.py::test_a_failing_audit_insert_rolls_the_acceptance_back`<br>`tests/test_promotion.py::test_a_failed_audit_insert_leaves_no_asset_row_and_removes_only_the_file_this_promotion_published`<br>`tests/test_promotion.py::test_a_commit_that_fails_leaves_no_asset_row_and_no_published_file` | Baseline | Implemented |
| TM-19 | TB4 | Quarantined bytes change, vanish or become a link between the seal and promotion | T1, T2 | A rescan compares the re-hash with the sealed H first and ends in `INTEGRITY_FAILED`; promotion treats a missing, symlinked or non-regular source as an integrity failure; H is never replaced | `tests/test_rescan.py::test_bytes_that_no_longer_hash_to_the_sealed_digest_are_an_integrity_failure_not_a_scan`<br>`tests/test_promotion.py::test_a_missing_symlinked_or_non_regular_source_is_an_integrity_failure_and_publishes_nothing` | F-04 | Implemented |
| TM-20 | TB4 | A crash or fault leaves a promotion half done | operational | Intent first (`PROMOTING` with the attempt and asset key), then copy, then one short publishing transaction; a recovery pass handles each crash row by proof or by report, and gives the same state when run twice | `tests/test_promotion.py::test_after_p1_only_there_is_nothing_on_disk_and_the_recovery_pass_runs_the_rest`<br>`tests/test_promotion.py::test_the_recovery_pass_twice_gives_the_same_state`<br>`tests/test_promotion.py::test_a_target_whose_bytes_are_not_the_accepted_bytes_is_reported_and_left_alone` | F-04 | Implemented |
| TM-21 | build | A private key, or code that mints tokens or fetches keys, in the reference | maintainer error | A guard fails on token minting, key creation or loading, key fetching and network imports in `src/`, and on a private key anywhere in the repository | `tests/guards/test_token_minting.py::test_no_module_under_src_mints_tokens_creates_or_loads_private_keys_or_fetches_keys`<br>`tests/guards/test_token_minting.py::test_no_private_key_is_committed_anywhere_in_the_repository` | F-01 | Implemented |
| TM-22 | build | Vulnerable code in the reference application, or a switch that selects it | maintainer error | `src/` imports nothing from `labs/` or `tests/`, contains no dynamic loading or evaluation, names no vulnerable variant, and `create_app` requires its dependencies explicitly, with no default scanner | `tests/guards/test_isolation.py::test_reference_source_does_not_import_labs_or_tests`<br>`tests/guards/test_isolation.py::test_reference_source_names_no_vulnerable_variant`<br>`tests/guards/test_isolation.py::test_reference_source_has_no_dynamic_loading_or_evaluation`<br>`tests/test_app.py::test_there_is_no_default_scanner_the_composition_root_must_pass_one` | Isolation | Implemented |
| TM-23 | TB3 | SQL built from input, or a read or write of a table outside the module that owns it | T1, T2 | Parameterised statements only; each table is touched by named modules in named statement shapes, checked by guards; connections are opened only by the store | `tests/test_asset_lookup.py::test_one_parameterised_statement_binds_every_condition`<br>`tests/guards/test_delivery_scope.py::test_no_module_in_src_touches_the_deliveries_table_except_as_allowed`<br>`tests/guards/test_connections.py::test_only_the_store_opens_sqlite_databases` | Baseline | Implemented |

### 4.3 Limitations that have no control, and what is done about them

| ID | Boundary | Limitation | Attacker | What is done | Tests | Finding | Status |
|---|---|---|---|---|---|---|---|
| TM-24 | TB4 | A process that can write the trusted root changes a file after it was verified, or after it was promoted | operator-side | Assumed controlled outside the application (M0 §5.4). Before the recording transaction the code checks the file's fingerprint and rolls back on a difference; after promotion nothing re-verifies the file (the optional `verify_trusted()` is not built) | `tests/test_promotion.py::test_a_file_that_is_swapped_after_it_was_verified_is_not_adopted_and_no_row_is_written` | F-04 | Limitation |
| TM-25 | TB4 | Verdict validity is not rechecked at promotion | T5 | Recorded in the Addendum as a documented gap: promotion checks that the verdict is a `no_detection` verdict for the accepted digest, and acceptance (which is final) checked the rest | `tests/test_promotion.py::test_promotion_asks_only_whether_the_verdict_is_a_no_detection_verdict_for_the_digest` | F-03 | Limitation |
| TM-26 | TB4 | A delivery stranded in `SEALING` (A-J7) is not recovered; the path-routing and malformed-URL answers are not uniform; reconciliation has no exclusion from active uploads or promotions | operational | Carried forward to the final lifecycle milestone and M1M; the passes are maintenance-window operations and are not scheduled | `tests/test_rescan.py::test_a_missing_file_leaves_the_delivery_in_sealing_as_a_seal_does_and_a_second_rescan_is_refused` | Baseline | Limitation |
| TM-27 | TB6 | The audit trail is not tamper-evident, and every request takes the writer lock | operator-side | Stated in M0 §4. Triggers and an authorizer refuse update, delete and replacement through the application's connections; whoever can write the database file can change both | `tests/test_audit.py::test_an_event_with_an_engine_kind_stays_append_only` | Baseline | Limitation |

## 5. Out of scope

A malicious studio administrator; a compromised identity provider or signing key; infrastructure compromise; screen capture
or other client-side leaks; denial of service beyond the upload size limit; the platform operator. These are the exclusions of
M0 §3, and nothing in the code or the tests claims to address them.

## 6. Assumptions the results depend on

- The two storage roots are local directories on one filesystem that untrusted users cannot write to, and the parent
  directories of a configured root are followed like any configured path.
- The injected clock is right, the configured public keys are the identity provider's, and the SQLite file is not written
  by anything but the application.
- The operator's code is trusted: it can run a rescan or a promotion, and nothing authenticates it.
- The scanner is synthetic; no row above depends on it being right.
- Python 3.13.7 on macOS arm64, with the locked dependency set; no other platform is claimed.

No claim is made of conformance to any standard or of any ASVS level; the references list the requirements each finding is
mapped to.
