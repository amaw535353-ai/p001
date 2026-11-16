# Acceptance traceability

58 distinct required assertions are named in executable tests. I01–I04 run actual
optional tools with `make test-live`; missing tool dependencies fail the live gate,
never pass as mocks. The remaining requirements run with sockets/DNS disabled.
Additional security, unit and end-to-end assertions are reported separately.

| ID | Test module | Executable assertion |
|---|---|---|
| D01 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D01_same_seed_stable_content` |
| D02 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D02_new_seed_and_version_retained` |
| D03 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D03_exact_duplicates_detected` |
| D04 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D04_near_duplicates_are_review_signal` |
| D05 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D05_lineage_split_leakage` |
| D06 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D06_sealed_labels_absent_from_visible_inputs` |
| D07 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D07_upstream_license_and_permission_required` |
| D08 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D08_expected_outcome_consistency` |
| D09 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D09_coverage_reconciles_to_samples` |
| D10 | [tests/dataset_quality/test_quality.py](../tests/dataset_quality/test_quality.py) | `test_D10_ambiguous_labels_require_adjudication` |
| E01 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E01_oracle_uses_observed_behavior_not_exit` |
| E02 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E02_sample_results_survive_aggregation` |
| E03 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E03_high_average_cannot_hide_critical_failure` |
| E04 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E04_threshold_rubric_and_scorer_recorded` |
| E05 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E05_model_judge_supplementary_without_ground_truth` |
| E06 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E06_judge_calibration_disagreement_is_reported` |
| E07 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E07_hidden_expected_label_field_rejected` |
| E08 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E08_judge_injection_content_cannot_change_host_rubric` |
| E09 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E09_missing_tool_is_blocked` |
| E10 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E10_timeout_and_provider_errors_not_passed` |
| E11 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E11_repetitions_keep_variation_and_flaky_ids` |
| E12 | [tests/evaluator/test_scoring.py](../tests/evaluator/test_scoring.py) | `test_E12_metric_denominators_and_counts` |
| I01 | [tests/adapters/test_integrations.py](../tests/adapters/test_integrations.py) | `test_I01_actual_inspect_task_executes` |
| I02 | [tests/adapters/test_integrations.py](../tests/adapters/test_integrations.py) | `test_I02_actual_inspect_evals_task_import_and_conversion` |
| I03 | [tests/adapters/test_integrations.py](../tests/adapters/test_integrations.py) | `test_I03_actual_agentdojo_local_environment` |
| I04 | [tests/adapters/test_integrations.py](../tests/adapters/test_integrations.py) | `test_I04_actual_promptfoo_assertions_retained` |
| I05 | [tests/adapters/test_integrations.py](../tests/adapters/test_integrations.py) | `test_I05_p007_actual_schema_valid_import_and_bad_version` |
| I06 | [tests/adapters/test_integrations.py](../tests/adapters/test_integrations.py) | `test_I06_absent_p006_blocked_and_merged_p007_explicit` |
| M01 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M01_label_flip_without_version_detected` |
| M02 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M02_scorer_threshold_change_blocks_comparison` |
| M03 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M03_failed_sample_omission_detected` |
| M04 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M04_duplicate_passing_sample_cannot_inflate` |
| M05 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M05_unversioned_evaluator_implementation_detected` |
| M06 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M06_changed_judge_prompt_is_noncomparable` |
| M07 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M07_holdout_key_leakage_negative_test` |
| M08 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M08_recomputed_hash_cannot_hide_lineage_leak` |
| M09 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M09_selective_category_omission` |
| M10 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M10_changed_plan_and_run_manifest_detected` |
| M11 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M11_model_upgrade_not_direct_regression` |
| M12 | [tests/benchmark_integrity/test_manipulation.py](../tests/benchmark_integrity/test_manipulation.py) | `test_M12_lab_preserves_original_altered_and_audit_explanation` |
| P01 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P01_manifest_has_generator_commit_seed_hash` |
| P02 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P02_scorer_and_rubric_identity_retained` |
| P03 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P03_tool_model_provider_identity_in_plan` |
| P04 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P04_unchanged_artifacts_verify` |
| P05 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P05_modified_sample_label_scorer_detected` |
| P06 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P06_missing_artifact_detected` |
| P07 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P07_new_version_preserves_baseline` |
| P08 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P08_reproduction_reports_implementation_drift` |
| P09 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P09_upstream_commit_attribution_preserved` |
| P10 | [tests/provenance/test_reproducibility.py](../tests/provenance/test_reproducibility.py) | `test_P10_public_export_excludes_markers_and_sealed_rows` |
| S01 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S01_valid_card_and_manifest` |
| S02 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S02_missing_sample_fields_and_unknown_fields` |
| S03 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S03_duplicate_registry_ids_rejected` |
| S04 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S04_bad_cross_references_rejected` |
| S05 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S05_unsupported_modality_and_capability` |
| S06 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S06_outcome_and_label_provenance_required` |
| S07 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S07_content_dataset_and_structure_bounds` |
| S08 | [tests/schema/test_contracts.py](../tests/schema/test_contracts.py) | `test_S08_frozen_version_cannot_be_overwritten` |
