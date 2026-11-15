# Required scenario traceability

Tests are executable assertions, not evidence that optional absent software works.
`tests/conftest.py` blocks external socket operations for every test; only marked
loopback cases may connect. Subprocess offline tests additionally disable socket
and resolver calls via `tests/no-network/sitecustomize.py`.

| Prompt case | Evidence in tests | Outcome boundary |
|---|---|---|
| 1 P001 components/endpoints/boundaries | test_actual_p001_components_endpoints_identities_boundaries | Actual static import, not runtime enforcement |
| 2 OpenAPI templates and merge | test_openapi_templates_and_methods_no_phantom_endpoints; test_explicit_correlation_merges_endpoints_and_preserves_disagreements | Executed |
| 3 tenant separation | test_real_p002_two_tenants_and_oracle_not_authorization; test_identical_service_keys_never_merge_tenants | Real P002 model/generator |
| 4 uncertain edges | test_unknown_relation_remains_unverified | Executed |
| 5 conflicting claims | test_runtime_static_conflict_retained | Source status/provenance retained |
| 6 deterministic IDs/hash/diagram | test_repeatable_semantic_snapshot_and_diagram | Actual offline replay |
| 7 hostile YAML/size/depth | test_unsafe_serialization_rejected; test_size_depth_resource_limits; test_malformed_openapi_rejected | Executed parametrizations |
| 8 traversal/symlinks | test_path_traversal_rejected; test_symlink_even_inside_root_rejected; test_fifo_input_rejected_without_blocking | Executed |
| 9 rendering injection | test_hostile_labels_do_not_inject_exports | Markdown/Mermaid/CSV; no HTML exporter |
| 10 secrets/state | test_secret_iac_attributes_redacted_all_exports; test_raw_iac_state_rejected_and_partial_report | Executed |
| 11 missing gate zero egress | test_absent_or_mock_adapter_proves_zero_egress; test_missing_gate_cli_blocked_zero_requests_with_evidence | Actual socket spy + subprocess denial |
| 12 lifecycle denial | test_real_p003_nonactive_states_deny; test_p003_window_checked_using_actual_clock | Real P003 engine |
| 13 context/exclusion/method | test_p003_context_binding_and_prerequisites_deny; test_explicit_exclusion_and_wrong_method_deny | Real P003 engine |
| 14 canonical origin/path/IPv6 | test_canonical_target_variations_denied_before_socket | Hard ceiling narrower than P003 |
| 15 encoding/userinfo/substitution | Same parametrized URL test | Denied before socket |
| 16 redirect spy | test_redirect_denied_before_connecting_to_endpoint_spy | Real local response; no redirected request |
| 17 browser subresource/WebSocket | test_browser_thirdparty_websocket_and_page_instructions_blocked | Refusal only; live browser BLOCKED |
| 18 DNS/rebinding | test_dns_rebinding_has_no_resolution_path | Hostname resolution unsupported, not a DNS implementation |
| 19 budgets/depth/time/concurrency | test_request_and_rate_budget_thresholds; test_hard_ceiling_deadline_killswitch_concurrency | Executed |
| 20 revoke/stop/budget | test_midrun_real_revoke_stops_next_request; test_real_version_amendment_invalidates_old_allow; test_p003_budget_below_tool_ceiling_enforced | Real ledger transitions and loopback |
| 21 side effects | test_mutating_methods_and_unreviewed_navigation_denied; URL side-effect cases | No browser forms/click capability |
| 22 credential leak | test_content_headers_and_tokens_discarded | Real guarded HTTP; browser credential test BLOCKED |
| 23 ZAP active jobs | test_zap_active_jobs_fail_contract | Restrictive P004 contract, not verified ZAP AF |
| 24 provisional alerts | test_zap_passive_alert_is_provisional_and_scope_bound | Fixture-only artifact import |
| 25 actual egress path | test_actual_egress_guard_and_functional_local_request | Actual numeric loopback socket |
| 26 Playwright local graph | test_optional_real_playwright_request_graph | SKIPPED / BLOCKED, not passed |
| 27 live namespace introspection | test_live_cluster_without_scoped_identity_blocked; test_optional_live_kubernetes_inventory | Refusal PASS; actual integration SKIPPED / BLOCKED |
| 28 optional vendor absence | test_optional_onyx_openhands_missing_report_error_no_invention; test_optional_local_manifest_contracts_are_declarations | No vendor API claim |
| 29 repeat exports | test_two_cli_runs_equivalent_and_independent_report | Network-disabled CLI subprocesses |
| 30 controlled changes | test_controlled_diff_added_removed_changed_and_policy; test_diff_distinguishes_provenance_only_from_inventory_changes | Graph and provenance changes distinguished |
| 31 partial report | test_partial_cli_report_counts_failed_sources_and_preserves_good; test_midrun_cli_denial_retains_partial_counts | Real partial live CLI and failed offline source |
| 32 cleanup | cleanup, tamper and ownership traversal tests in test_cli_lifecycle.py | Hash preflight; foreign files retained |
| 33 offline CI | test_cli_offline_with_socket_and_dns_disabled + no-network suite/demo commands | Local equivalent executed; remote CI NOT TESTED; Python-level denial only |
| 34 forged instructions | test_forged_manifest_cannot_enable_live_or_execute; test_source_parsing_never_executes_code; test_env_example_imports_names_never_values_or_expands | Data never evaluated |
| 35 replay | test_cached_or_foreign_decision_never_grants_scope; context version/digest cases | No capability-token input; fresh real check |

Additional tests validate actual generated JSON Schemas, retained source hashes,
untrusted dependency/Dockerfile declarations, output overwrite refusal, independent
report commands and explicit correlation refusal across tenants/origins/principals.
See `validation-status.md` for current counts/paths and `known-limitations.md` for
unmet optional gates.
