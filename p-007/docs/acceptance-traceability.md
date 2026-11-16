# Acceptance traceability

44 distinct named acceptance requirements map to executable checks. Additional tests cover resource limits, sibling integrity and edge cases. Live checks execute optional tools and loopback services; skips would leave the live gate BLOCKED.

| Requirement | Test file | Assertion function |
|---|---|---|
| F01 | tests/schema/test_contracts.py | test_F01_valid_case_jsonschema_and_model |
| F02 | tests/schema/test_contracts.py | test_F02_missing_and_unknown_fields |
| F03 | tests/schema/test_contracts.py | test_F03_duplicate_version_conflict |
| F04 | tests/schema/test_contracts.py | test_F04_invalid_references |
| F05 | tests/schema/test_contracts.py | test_F05_stable_normalized_plan |
| F06 | tests/unit/test_results.py | test_F06_unsupported_p006_blocked |
| F07 | tests/unit/test_results.py | test_F07_exit_zero_is_not_oracle |
| F08 | tests/schema/test_contracts.py | test_F08_oversized_input_and_limits |
| A01 | tests/authorization/test_scope.py | test_A01_offline_has_no_sockets_or_dns |
| A02 | tests/authorization/test_scope.py | test_A02_unregistered_refused_before_connect |
| A03 | tests/authorization/test_scope.py | test_A03_external_metadata_private_and_url_tricks |
| A04 | tests/authorization/test_scope.py | test_A04_redirect_no_followup |
| A05 | tests/authorization/test_scope.py | test_A05_resolution_change_refused_before_connect |
| A06 | tests/authorization/test_scope.py | test_A06_p003_method_and_category_scope |
| A07 | tests/authorization/test_scope.py | test_A07_missing_expired_revoked_mismatched_authorization |
| A08 | tests/authorization/test_scope.py | test_A08_active_zap_needs_optin_and_scope |
| R01 | tests/adapters/test_live_tools.py | test_R01_promptfoo_version |
| R02 | tests/adapters/test_live_tools.py | test_R02_promptfoo_real_local_eval |
| R03 | tests/adapters/test_contracts.py | test_R03_provider_error_and_timeout_not_pass |
| R04 | tests/adapters/test_live_tools.py | test_R04_inspect_actual_task |
| R05 | tests/adapters/test_live_tools.py | test_R05_inspect_samples_and_aggregate |
| R06 | tests/adapters/test_contracts.py | test_R06_missing_inspect_provider_blocked |
| R07 | tests/adapters/test_live_tools.py | test_R07_zap_real_passive_scan |
| R08 | tests/adapters/test_contracts.py | test_R08_active_still_refused_with_optin_if_contract_unsupported |
| R09 | tests/adapters/test_contracts.py | test_R09_alert_observation_never_confirmed |
| R10 | tests/adapters/test_live_tools.py | test_R10_browser_positive |
| R11 | tests/adapters/test_live_tools.py | test_R11_browser_server_denial_session_switch_logout |
| R12 | tests/adapters/test_live_tools.py | test_R12_browser_external_navigation_refused |
| E01 | tests/evidence/test_evidence.py | test_E01_manifest_identities |
| E02 | tests/evidence/test_evidence.py | test_E02_unchanged_hashes_verify |
| E03 | tests/evidence/test_evidence.py | test_E03_modified_artifact |
| E04 | tests/evidence/test_evidence.py | test_E04_missing_artifact |
| E05 | tests/evidence/test_evidence.py | test_E05_redaction_after_leak_oracle |
| E06 | tests/evidence/test_evidence.py | test_E06_failure_flaky_and_inconclusive_retained |
| E07 | tests/evidence/test_evidence.py | test_E07_recorded_offline_reproduction |
| E08 | tests/evidence/test_evidence.py | test_E08_dirty_tree_disclosure |
| G01 | tests/regression/test_comparison.py | test_G01_immutable_baseline |
| G02 | tests/regression/test_comparison.py | test_G02_regression |
| G03 | tests/regression/test_comparison.py | test_G03_improvement_retains_original_failure |
| G04 | tests/regression/test_comparison.py | test_G04_unchanged_pass_and_fail |
| G05 | tests/regression/test_comparison.py | test_G05_changes_noncomparable_even_with_wrong_rule |
| G06 | tests/regression/test_comparison.py | test_G06_inconsistent_repetitions_flaky |
| G07 | tests/regression/test_comparison.py | test_G07_blocked_and_untested_not_passes |
| G08 | tests/regression/test_comparison.py | test_G08_remediation_and_retest_links |
