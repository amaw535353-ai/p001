# Validation status — 2026-11-16

| Gate | Recorded result | Limit |
|---|---|---|
| A dataset integrity | PASS | 48 authored samples; 21 strict schemas; label, lineage and hash gates |
| B offline evaluation | PASS | Full demo/reproduction with sockets and DNS disabled; fresh core environment without sibling packages |
| C four tools | PASS for actual adapter operations | Inspect Evals native corpus/judge NOT_TESTED; AgentDojo full official suites NOT_TESTED |
| D manipulation | PASS for 12 controlled checks | M12 proves structural isolation only; no live judge resistance claim |
| E scoring | PASS | Per-sample observations retained; one deliberate critical FAIL remains visible |
| F comparison/reproduction | PASS | Identical run UNCHANGED; changed dataset NOT_COMPARABLE; hashes match reproduction |
| G sibling/future integration | Available actual contracts validated | P-006 BLOCKED; P-009/P-010 consumers NOT_TESTED |
| H handoff | Local sanitized artifacts generated | Unpublished; independent human gates NOT DEMONSTRATED |

Engineering tests: **82 passed, zero failed/errors/skips**, including four actual
optional-tool assertions. Socket/DNS-disabled suite: **78 passed**, four live tool
assertions intentionally deselected. Root tests: **7 passed**. Root structural and
narrow secret checks, Ruff lint/format, mypy (18 source files), 21-schema drift,
Python dependency compatibility and initial/fresh setup checks passed. All 58
required acceptance IDs map to executable tests. Full-suite JUnit is retained in
ignored .runtime/verification/tests.xml. At the initial local handoff, the configured
GitHub workflow was NOT_RUN. The user subsequently authorized source commit, push
and merge; consult the resulting pull request for the remote check outcomes.

A clean source reconstruction from the approved base Git archive plus the local
patch passed fresh setup, all 78 offline tests, schema/quality validation and the
full demo. Its frozen dataset manifest exactly matched the original. No second
Git worktree or remote repository was created.

Synthetic baseline evaluation: 47 PASS / 1 critical FAIL, not an engineering-test
failure. The baseline's failing sample is p008-injection-04. Four full tool paths
also preserve 47/48 and that failure. No live external model, provider, target or
human competency was evaluated. Known-advisory audits returned zero for the final
checked Python/npm locks; license/publication review remains separate.

See delivery-report.md for exact IDs/hashes, inventory, commands and limitations.
