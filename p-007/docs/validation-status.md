# Validation status — 2026-11-16

| Gate | Outcome | Practical limit |
|---|---|---|
| A offline core | PASS | 55 socket/DNS-disabled tests; small synthetic fixtures only |
| B scope refusal | PASS | exact P007-owned loopback lease + actual fresh P003; active always blocked |
| C tools | PASS for four local tool executions | no vendor model, P006, crawler or active-scan claim |
| D regression | PASS | explicit synthetic policy transitions detect improvement/regression |
| E evidence | PASS | 76 selected artifact hashes verified; offline reproductions consistent |
| F siblings | PASS for actual available P001-P005 contracts; P006 BLOCKED | runtime Kubernetes and legal authority unverified |
| G consultancy handoff | IMPLEMENTED | report/export/traceability and questions-only workbook; humans NOT DEMONSTRATED |

Final engineering suite: 69 passed, zero failed/skipped. Offline suite: 55 passed.
Root unit: 7 passed. Root static, lint, mypy and schema drift passed. Remote CI is
configured but was NOT_RUN at the initial local handoff. The user subsequently
authorized commit, push and merge; the PR records remote CI outcomes. All runtime
evidence remains local and ignored.

See delivery-report.md for exact run IDs, tool versions/commands, comparisons,
reproduction paths, source gaps, resource/browser limitations and human provenance.
