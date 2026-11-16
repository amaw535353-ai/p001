# P-007 — AI Security Control Regression Testing and Evidence Reproduction Framework

Synthetic local laboratory / Codex implemented and tested / human independent
reproduction NOT DEMONSTRATED. P-006 has no committed implementation at the
inspected base and its live integration is BLOCKED.

Python 3.12 CLI: strict contracts → catalog and immutable plan → offline or scoped
runner → behavior oracle → sanitized evidence → comparison and reproduction.
The default command uses deterministic fixtures and has no network dependency.

```bash
cd /workspace/p001/p-007
./scripts/setup                    # hash-locked core, local sibling packages
./scripts/setup --tools            # optional pinned Promptfoo, Inspect, Playwright, ZAP
make doctor
make validate
make catalog
make plan TARGET=offline-demo
make run TARGET=offline-demo PROFILE=offline
make demo                         # baseline, simulated fix, regression and reproduction
make compare BASELINE=<run-id> CURRENT=<run-id> RULE=synthetic-remediation-v1
make reproduce RUN=<run-id> TEST=T-offline-cross-tenant
make evidence-verify RUN=<run-id>
make report RUN=<run-id>
make verify                       # offline tests, lint, typecheck, schema drift
make test-live                    # actual optional tools and guarded loopback tests
PYTHONPATH=tests/no-network .venv/bin/python -m pytest tests -m 'not live'
PYTHONPATH=tests/no-network .venv/bin/python scripts/demo-contracts.py
make cleanup RUN=<non-baseline-run-id> CONFIRM=p007-owned-evidence
```

The baseline deliberately contains a FAIL and a FLAKY result. They demonstrate
retained failures and inconsistent samples; `make run` therefore exits 1. Run CLI
exit codes are 0 for all passed applicable checks, 1 for an observed failure, and
2 for blocked/incomplete/flaky execution or invalid input. Cleanup requires the
shown confirmation and refuses protected baselines. Nothing pushes or publishes.

Real tool commands use fixed local providers and owned fixtures:

```bash
./scripts/p007 run --target local-model --profile promptfoo
./scripts/p007 run --target local-model --profile inspect_ai
./scripts/p007 run --target local-fixture --profile playwright --local-demo
./scripts/p007 run --target local-fixture --profile zap --local-demo
./scripts/p007 run --target p006-unavailable --profile p006  # records BLOCKED
```

`--local-demo` explicitly creates an ephemeral, simulated P-003 governance ledger
for the in-process P-007 fixture. It does not assert a human reviewed it. The real
P-003 evaluator is re-read before each request. Arbitrary URLs/targets, redirects,
hostnames, hosted models and active ZAP scans are unsupported and fail closed.
ZAP passively analyzes one broker-captured response; it never crawls the target.

This verified host is Linux x86_64, Python 3.12.14, Node 24.22.1, Java 21.0.13,
Chromium 156.0.8078.79. Inspect is isolated because its current Pydantic requirement
conflicts with the verified sibling lock. The browser pin uses the existing Debian
Chromium; its managed-host sandbox helper is unavailable, so only trusted fixture
pages run with sandbox disabled. No general-purpose browser/target is supported.
macOS/Windows/ARM and a browser upgrade are NOT_TESTED; see the operations guide.

Runtime runs live under ignored `evidence/`, reports under ignored `reports/` and
tool data under ignored `.tools/`/`.runtime/`. Do not commit those directories.
Hashes prove consistency, not signer identity, trusted time or oracle correctness.

Review [validation](docs/validation-status.md), [architecture](docs/architecture.md),
[acceptance traceability](docs/acceptance-traceability.md),
[tool compatibility](docs/runner-adapters.md), [contracts](docs/p001-p006-integration-contracts.md),
[delivery details](docs/delivery-report.md), and the questions-only
[learner workbook](docs/learner-workbook.md).
