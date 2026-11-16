# Actual sibling and future handoff contracts

P-007 PR #5 was merged into p001-initial before this implementation. P-008 uses
that approved base, not P-007's feature branch. `import_p007` validates the actual
merged `report-export.schema.json` and actual `p007.models.ReportExport` 1.0. The
committed synthetic example contains 11 normalized results. Import preserves source
run ID, manifest digest, result statuses/assertions/expected/observed/runner metadata,
definition/compatibility hashes, control status, handoff and provenance read-only.
Incompatible versions or statuses fail. Reference preservation does not authenticate
the original evidence files or rerun P-007; no result becomes a label automatically.

| Source | Executed interface | Scope |
|---|---|---|
| P-002 | Actual generate + Dataset 1.0 validator, tiny fixtures | Synthetic identity/tenant/scenario references only |
| P-003 | Actual sealed Engagement 1.0 + verified digest | Read-only draft metadata; expired window retained; no network authority |
| P-005 | Actual build + analyze, p005-model-1.0 | Candidate threat IDs only; no confirmed findings |
| P-007 | Actual ReportExport 1.0 schema/model | Read-only 11-result fixture import; source target execution NOT_TESTED |
| P-006 | No implementation at approved base | BLOCKED |
| P-009 | p008-handoff-1.0 export | Future consumer NOT_TESTED; no telemetry platform built |
| P-010 | p008-handoff-1.0 export | Future consumer NOT_TESTED; no risk register/findings generator built |

Exports contain dataset/evaluator/run identities, sanitized metrics, provenance,
limitations and evidence-manifest digest references. Sealed sample results and raw
prompts/outputs/traces are excluded. Missing consumer applications stay NOT_TESTED.
A network-capable benchmark would require actual fresh P-003 authorization and
P-007 execution semantics; this implementation instead remains entirely offline.
