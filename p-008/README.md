# P-008 — AI Security Evaluation Datasets and Regression Testing Pipeline

Local synthetic training platform. **Codex implemented / Codex tested.** Human
independent reproduction and external human verification are **NOT DEMONSTRATED**.
This does not certify a learner, model or product.

Python 3.12: authored cases → strict datasets and private outcome records → quality
gates → immutable snapshot → fixed evaluation plan → observations and host oracle →
reconciled sample metrics → strict comparison, reproduction and sanitized handoff.

The core runs without network, API keys, a hosted model, P-006 or optional tools.
It creates **48 samples, six families, 24 lineage groups**, 24 ALLOW/24 DENY labels.
Seed 20261116 produces development 10, validation 10, public benchmark 10, sealed
holdout 10, regression 8. The intentionally defective baseline yields **47 PASS /
1 critical FAIL**, exposing why an aggregate alone is misleading. The corrected
local policy is a separate evaluator/model identity.

```bash
cd /workspace/p001/p-008
./scripts/setup                       # pinned hash-locked core, local sibling parsers
./scripts/setup --tools               # optional: pinned Inspect AI/Evals, AgentDojo, Promptfoo
make doctor validate
make dataset-build SEED=20261116
make dataset-freeze VERSION=1.0.0      # refuses an existing frozen version
make dataset-audit
make plan
make eval                             # expected exit 1: deliberately retained failure
make report RUN=<run-id>
make integrity-check RUN=<run-id>
make compare BASELINE=<run-id> CURRENT=<run-id>
make reproduce RUN=<run-id> SAMPLE=p008-injection-04
make benchmark-integrity RUN=<run-id>
make export RUN=<run-id>
make import-p007 FILE=../p-007/examples/report-export.example.json
make integrations
make demo                             # fresh nested registry; rerunnable without overwrites
make verify test-offline
make test-live                        # four actual optional tool integrations
make cleanup RUN=<nonbaseline-id> CONFIRM=p008-owned-artifacts
```

Direct CLI supports `--root`, `--split`, `--family`, `--repetitions`, `--policy`,
`--dry-run` and recorded `--plan`. Example:

```bash
./scripts/p008 eval --tool inspect_ai --family authorization
./scripts/p008 eval --tool inspect_evals --family authorization
./scripts/p008 eval --tool agentdojo --family authorization
./scripts/p008 eval --tool promptfoo --family authorization
PYTHONPATH=src/p008/adapters/offline_guard ./scripts/p008 demo
```

Exit 0 means the requested operation completed; evaluation exit 1 means observed
failure; exit 2 means blocked, incomplete, invalid or noncomparable. Reproducing a
failure can return 0 when bytes match; its `evaluation_status` remains FAIL.
`make validate` checks schemas and a newly generated fixture, explicitly not a
frozen version. `dataset-audit` and `integrity-check` check the stored version.

Inventory #41 Inspect AI executes a real task with a local mock model; #42 Inspect
Evals imports `strong_reject` and executes its record converter on P-008 data;
#4 AgentDojo executes an actual local runtime and task predicates; #3 Promptfoo
executes its CLI and per-test assertions. Inspect Evals' upstream corpus/hosted
judge and AgentDojo's official full suites are **NOT_TESTED**. These are synthetic
adapter checks, not real-world jailbreak or authorization evidence.

All runtime data, including sealed outcome keys, lives under ignored `.runtime/`.
Private expected outcomes are separate from `model-inputs.json`. Public exports
exclude sealed sample rows and all raw observations; local imports are read-only.
No command publishes, pushes, creates a PR or contacts an external model.

Start with [architecture](docs/architecture.md), [validation](docs/validation-status.md),
[delivery report](docs/delivery-report.md), [acceptance map](docs/acceptance-traceability.md),
[tool sources](datasets/upstream/source-lock.json), and the unanswered
[learner workbook](docs/learner-workbook.md).
