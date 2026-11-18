# Acceptance traceability

This catalog maps all 88 specification requirements to executed assertions or explicit native gates. The 168 offline tests are engineering assertions; these 88 rows are not an additional test count. Native check labels sometimes cover a narrower observation than the full requirement, so the requirement status below takes precedence.

Exact function references and limitations are in [the machine-readable catalog](../contracts/acceptance-catalog.json). Raw runtime evidence stays outside Git. Sanitized results and commands are in [test results](test-results.md) and [verification summary](verification-summary.json).

| Category | PASS | PARTIAL | NOT_TESTED | REFERENCE_ONLY | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| C | 8 | 0 | 0 | 0 | 8 |
| T | 4 | 5 | 1 | 0 | 10 |
| O | 8 | 0 | 0 | 0 | 8 |
| F | 3 | 3 | 2 | 0 | 8 |
| W | 6 | 2 | 0 | 0 | 8 |
| X | 10 | 0 | 0 | 0 | 10 |
| D | 10 | 0 | 0 | 0 | 10 |
| E | 10 | 0 | 0 | 0 | 10 |
| H | 5 | 2 | 0 | 1 | 8 |
| R | 5 | 3 | 0 | 0 | 8 |
| **Total** | 69 | 15 | 3 | 1 | **88** |

FAIL, BLOCKED, INCONCLUSIVE and NOT_APPLICABLE each have zero requirement rows. The separate full Wazuh indexer/dashboard deployment gate is **BLOCKED**, not part of the manager-only W01–W08 row count. Historical failed attempts remain in ignored local evidence; final check counts do not erase them.

| ID | Requirement status | Evidence or remaining limit |
| --- | --- | --- |
| C01 | PASS | test_scope_has_no_sibling_changes |
| C02 | PASS | Owned Docker configuration inspection and completed scoped cleanup; docs/verification-summary.json |
| C03 | PASS | Owned Docker configuration inspection and completed scoped cleanup; docs/verification-summary.json |
| C04 | PASS | Owned Docker configuration inspection and completed scoped cleanup; docs/verification-summary.json |
| C05 | PASS | test_unknown_fields_strict_on_source_contract |
| C06 | PASS | Registry digest resolution and inspected local images; docs/image-verification.json |
| C07 | PASS | Runtime-secret byte comparison against publishable source and ignored-file checks; zero matches |
| C08 | PASS | Owned Docker configuration inspection and completed scoped cleanup; docs/verification-summary.json |
| T01 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| T02 | PASS | Native core T02: malformed OTLP refused |
| T03 | PARTIAL | Archive unknown-source refusal tested offline; native Collector unknown-source drop/quarantine accounting not measured. |
| T04 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| T05 | PARTIAL | Atomic payload/batch bounds exercised offline; actual Collector oversize boundary not driven. |
| T06 | PARTIAL | Application queue saturation is measured; native Collector memory/queue exhaustion and per-container cgroup enforcement are unverified. |
| T07 | NOT_TESTED | Archive write outage/retry is tested offline. A controlled native Collector exporter-outage detection assertion was not executed. |
| T08 | PARTIAL | Native accepted-span metric observed; rejected/dropped source and exporter-failure metric increments not measured end to end. |
| T09 | PARTIAL | Actual liveness and separate ingestion checks pass. Health endpoint does not guarantee downstream exporter readiness. |
| T10 | PASS | test_configuration_security_bounds |
| O01 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| O02 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| O03 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| O04 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| O05 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| O06 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| O07 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| O08 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| F01 | PASS | Native Langfuse checks: four PASS on actual v2 observations API; six observations |
| F02 | PASS | Native Langfuse checks: four PASS on actual v2 observations API; six observations |
| F03 | PARTIAL | Authenticated observation read succeeds and unauthenticated API read receives 401; graphical UI/session access was not tested. |
| F04 | PARTIAL | Keys remain in server environment and outside Git; browser network/client bundles not independently inspected. |
| F05 | PASS | Native Langfuse checks: four PASS on actual v2 observations API; six observations |
| F06 | NOT_TESTED | A second native Langfuse project and cross-project credential isolation test were not created/executed. |
| F07 | PARTIAL | Independent archive persisted through staged Langfuse stop/start failures; a controlled per-exporter loss/outage experiment is unverified. |
| F08 | NOT_TESTED | Native per-trace retention/deletion across Langfuse stores not tested. This explicit status satisfies disclosure, not deletion assurance. |
| W01 | PASS | Native Wazuh checks: 20 exact child rule IDs, 20 benign controls, actual localfile alert, fixed level 5 despite supplied severity 15 |
| W02 | PASS | Native Wazuh checks: 20 exact child rule IDs, 20 benign controls, actual localfile alert, fixed level 5 despite supplied severity 15 |
| W03 | PASS | Native Wazuh checks: 20 exact child rule IDs, 20 benign controls, actual localfile alert, fixed level 5 despite supplied severity 15 |
| W04 | PASS | Native Wazuh checks: 20 exact child rule IDs, 20 benign controls, actual localfile alert, fixed level 5 despite supplied severity 15 |
| W05 | PASS | Native Wazuh checks: 20 exact child rule IDs, 20 benign controls, actual localfile alert, fixed level 5 despite supplied severity 15 |
| W06 | PARTIAL | Newline/control-character refusal and source projection tested offline; hostile native Wazuh log-injection path not exercised. |
| W07 | PARTIAL | Native startup/readiness failures are detected and retained; explicit running-manager outage test and continuous monitoring unverified. |
| W08 | PASS | Owned Docker configuration inspection and completed scoped cleanup; docs/verification-summary.json |
| X01 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| X02 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| X03 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| X04 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| X05 | PASS | Native Wazuh checks: 20 exact child rule IDs, 20 benign controls, actual localfile alert, fixed level 5 despite supplied severity 15 |
| X06 | PASS | test_duplicate_delivery_no_double_count, test_same_event_id_changed_payload_rejected |
| X07 | PASS | test_out_of_order_preserves_source_and_observed_time, test_mixed_utc_formats_sort_by_actual_time |
| X08 | PASS | test_missing_event_and_sequence_are_gaps, test_missing_p006_request_id_stays_partial |
| X09 | PASS | test_time_proximity_never_joins, test_ambiguous_request_does_not_create_link |
| X10 | PASS | Native core checks: 20 PASS; actual source SDK, Collector and authenticated archive |
| D01 | PASS | test_sensitive_classes_removed_before_queue |
| D02 | PASS | test_sensitive_classes_removed_before_queue |
| D03 | PASS | test_sensitive_classes_removed_before_queue |
| D04 | PASS | test_sensitive_classes_removed_before_queue |
| D05 | PASS | test_sensitive_classes_removed_before_queue |
| D06 | PASS | test_sensitive_classes_removed_before_queue |
| D07 | PASS | test_secret_in_allowed_identifier_fails_closed, test_unsafe_import_or_allowed_metadata_is_refused |
| D08 | PASS | test_redaction_policy_and_counter_recorded |
| D09 | PASS | test_source_credential_tenant_binding |
| D10 | PASS | test_configuration_security_bounds |
| E01 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E02 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E03 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E04 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E05 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E06 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E07 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E08 | PASS | Preserved native case: eight exact-ID events, six Langfuse observations, nine verified objects/manifests, sanitized handoff |
| E09 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| E10 | PASS | Runtime-secret byte comparison against publishable source and ignored-file checks; zero matches |
| H01 | PASS | Actual committed P007 ReportExport example: 11 source results preserved (9 PASS, 1 FAIL, 1 FLAKY); REFERENCE_ONLY artifact provenance |
| H02 | PASS | Actual committed P007 ReportExport example: 11 source results preserved (9 PASS, 1 FAIL, 1 FLAKY); REFERENCE_ONLY artifact provenance |
| H03 | REFERENCE_ONLY | Safe path/hash/size checks pass on synthetic run-byte fixtures; original committed P007 example has no selected run bytes here. |
| H04 | PASS | Actual committed P007 ReportExport example: 11 source results preserved (9 PASS, 1 FAIL, 1 FLAKY); REFERENCE_ONLY artifact provenance |
| H05 | PARTIAL | Actual exporter shape and sibling subcontracts are validated using an explicitly authored fixture; no generated P008 handoff existed. |
| H06 | PASS | test_p008_summary_omits_sample_results_and_evaluator_content |
| H07 | PARTIAL | Actual unchanged P006 authorization method executed with fixture dependencies. Missing request ID is preserved; live P006 deployment not tested. |
| H08 | PASS | test_scope_has_no_sibling_changes |
| R01 | PASS | Socket-disabled suite and disposable demo: integrity, tamper, safe paths, local retention; native archives verified before/after cleanup |
| R02 | PARTIAL | Local tenant object/export purges and complete disposable store cleanup pass; native per-record retention across every downstream store is unverified. |
| R03 | PASS | test_tenant_read_filter, test_producer_cannot_read_evidence, test_cross_tenant_ingest_denied |
| R04 | PASS | test_unauthorized_export_audited |
| R05 | PASS | Native core R05: Collector restart and six retained trace events |
| R06 | PARTIAL | Application saturation/retry counts measured offline; native Collector sustained outage, queue exhaustion and loss accounting are not measured. |
| R07 | PARTIAL | Finite configuration, preflight and resource failures recorded. Shared parent cgroup makes individual container enforcement inconclusive. |
| R08 | PASS | Owned Docker configuration inspection and completed scoped cleanup; docs/verification-summary.json |
