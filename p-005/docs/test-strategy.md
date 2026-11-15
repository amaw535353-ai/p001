# Verification strategy and acceptance matrix

The software tests validate model invariants and safe artifact production, never
exploitability. `make test` runs the entire P-005 suite. `make verify` also runs
lint/format, mypy, generated-schema drift, dependency consistency, source/rule/pin
checks, both real offline demonstrations, and root `make unit static`. Every check
preserves its actual exit status. Evidence/engineering/manifest.json points at a
unique retained run with JUnit, logs, versions and source/lock hashes.

## Required 40 checks and their executable coverage

| # | Acceptance behavior | Test function (parameterized cases count separately) |
|---|---|---|
| 1 | Valid schema | test_fixture_schema |
| 2 | Deterministic model/threats | test_two_builds_are_deterministic |
| 3–4 | Missing/incompatible versions | test_missing_unsupported_schema_rejected; test_cli_reports_incompatible_schema_distinctly |
| 5 | Duplicate IDs | test_duplicate_graph_ids |
| 6 | Orphan endpoints | test_invalid_metadata_or_references |
| 7 | Tenant/zone references | test_invalid_metadata_or_references |
| 8 | Classification/trust values | test_invalid_metadata_or_references |
| 9 | Cycles/self-loops bounded | test_cycle_paths_are_bounded; test_self_loop_handled_without_invented_onward_hop |
| 10 | Input budgets | test_huge_deep_inputs_rejected; test_candidate_budget_fails_closed |
| 11 | Unsafe YAML/JSON | test_untrusted_yaml_json_never_executes |
| 12 | Traversal/symlinks | test_path_traversal_and_symlink; test_atomic_output_does_not_truncate_hardlinked_file |
| 13 | P-004 declarations preserved | test_p004_declared_stays_declared |
| 14 | Inference/provenance retained | test_p004_inferred_remains_uncertain |
| 15 | Honest fallback/invalid input | test_cli_fallback_and_malformed_no_silent_fallback |
| 16–17 | Tenants and human/workload identities | test_tenants_and_principals_remain_distinct |
| 18–19 | Actor and agent/tool boundaries | test_actor_and_agent_tool_crossings |
| 20 | No inferred enforcement | test_unknown_authorization_never_tested; test_p004_observed_requires_specific_observed_claim |
| 21 | Oracle versus observed behavior | test_actual_p002_generator_oracle_is_not_enforcement |
| 22 | P-003 scope | test_out_of_scope_is_flagged; test_actual_p003_context_is_not_authorization |
| 23 | Rule facts and candidate status | test_matching_rule_has_facts_and_trace |
| 24 | Absent features | test_absent_features_do_not_fire |
| 25 | Tenant deduplication | test_tenant_hypotheses_not_deduplicated |
| 26 | Cross-tenant controlled variant | test_controlled_variants_surface_specific_hypotheses |
| 27–29 | Prompt/delegation/approval cases | test_indirect_prompt_delegation_approval |
| 30 | Transparent ordinal triage | test_priority_is_ordinal_with_rationale |
| 31 | NOT_TESTED plans | test_all_plans_are_unexecuted_and_controls_owned |
| 32 | Risk ID validation | test_unverified_risk_ids_fail_with_source |
| 33 | No invented ATLAS IDs | test_catalog_actual_source_checksum_and_ids |
| 34 | Version/format/checksum fail closed | test_catalog_source_version_format_checksum_fail_closed |
| 35 | Review invalidation | test_changed_architecture_invalidates_reviews; test_human_editorial_workflow_is_separate_and_digest_bound |
| 36 | Inert diagram/report syntax | test_diagram_markdown_injection_is_inert |
| 37 | Public artifact redaction | test_redaction_across_all_public_artifacts; test_source_hash_after_redaction |
| 38 | No external connections | test_offline_cli_end_to_end_zero_egress plus kernel-networkless Docker demonstration |
| 39 | Native capability honesty | test_absent_adapters_never_verified |
| 40 | Full offline lifecycle/hashes | test_offline_cli_end_to_end_zero_egress |

Additional tests cover forged paths/observations, review explanations, stale and
cross-threat references, native Python non-execution, absent hardware/feature
rules, local catalog candidate updates and artifact tampering. Property tests use
Hypothesis with recorded dependency versions. All default P-005 tests deny socket
creation/DNS; child CLI attempts are logged before rejection, including caught
exceptions. A deliberate probe first proves the guard is active.

## Optional kernel-networkless reproduction

After `./scripts/setup` has cached verified wheels and the digest-pinned Python
base is available, the following builds a fresh dependency environment. Docker
may resolve the base artifact during setup; no package download occurs in RUN.
The actual **execution** has kernel networking disabled and no host mounts:

```bash
docker build --network none -f scripts/Dockerfile.offline -t p005-offline-check:local .
docker run --rm --label owner=p005-offline-v1 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 --memory 512m --cpus 1 --pids-limit 64 --tmpfs /app/generated:rw,nosuid,nodev,uid=10001,gid=10001,mode=0700,size=32m p005-offline-check:local
```

It runs only reviewed P-005 code. No untrusted/generated Python is executed. This
host's rootless Docker lacks cgroup delegation: resource flags are requested,
**resource enforcement is not asserted**. UID, network mode, read-only filesystem
and dropped capabilities are checked separately. See evidence/container-proof.json
for the actual command, image digest, exit and output comparison.

Predecessor regression tests use the P-005 venv with the actual editable siblings.
P-002's local redirect fixture and P-004's ten marked local safety tests run
separately on owned 127.0.0.1 servers, outside the zero-network P-005 demonstration.
No scanner, target deployment, real cloud or business endpoint is used. Optional
SDV, missing P-002 generated standard dataset, browser/ZAP/Kubernetes checks retain
SKIPPED/BLOCKED/NOT_TESTED status. They are not counted as passing tests.
