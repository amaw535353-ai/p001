# P-007 delivery record — 2026-11-16

Implemented in `/workspace/p001/p-007` in existing private repository
`amaw535353-ai/p001`. Verified default/base `p001-initial`, HEAD
`24e9d656f17c64dd694e4f2d32b4df570ea0d95f`; feature
`feat/p-007-control-regression`. At the initial local handoff, changes were
uncommitted and dirty; that HEAD did not represent the working tree. No push,
publication or PR had been performed. The user subsequently authorized commit,
push and merge; current publication and CI status are tracked by the GitHub PR
and branch history. The run identities below preserve the original local evidence.

P006 is BLOCKED: no committed `p-006/` tree or implementation was found. Its separate
source prompt was not supplied and would not establish a runtime. Four requested
source maps/career artifacts were absent; see source-discovery.md. The supplied
P007 row was preserved as Promptfoo #3, Inspect #41, ZAP #62 and Playwright #145.

## Architecture

Strict versioned catalog/control/target contracts → deterministic digest-bound plan →
fixed adapter → for HTTP, owned fixture lease and fresh actual P003 preflight →
behavior oracle before redaction → immutable artifacts/manifest → comparator,
offline reproduction, JSON/JSONL/Markdown/JUnit and P008/P009/P010 handoff.
26 catalog cases, six controls, 13 generated schemas plus a separate P006 contract.
44 named acceptance requirements are traced to code; additional checks test resources,
contracts and edge cases. No hosted model, AWS, Docker socket or public scanner is used.

## Validation actually executed

| Test group | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| adapters | 13 | 0 | 0 |
| authorization | 10 | 0 | 0 |
| evidence | 9 | 0 | 0 |
| integration | 6 | 0 | 0 |
| regression | 8 | 0 | 0 |
| schema | 7 | 0 | 0 |
| security | 10 | 0 | 0 |
| unit | 6 | 0 | 0 |

**69 P007 tests passed, 0 failed, 0 skipped** in the final full suite. The final
offline-only suite passed **55 tests with socket/DNS functions disabled**. Root
`make unit static`: **7 unit tests passed; static PASS**. Ruff, mypy (21 source
files), schema drift, pip dependency checks, normal setup and cached offline core
setup passed. Git diff whitespace check passed. Earlier development failures were
retained and corrected; they are not counted as passing live integrations.

## Actual runner outcomes

| Tool | Installed version | Target | Results | Evidence run |
|---|---|---|---|---|
| promptfoo | 0.125.1 | local-model | 6 PASS | `run-20261116T092926-6d70b329232f48fa` |
| inspect | 0.3.290 | local-model | 6 PASS | `run-20261116T092925-8c69182f06de4ca4` |
| playwright | 1.65.2 | local-fixture | 1 PASS | `run-20261116T093548-f0f95b758aa14dd9` |
| zap | 2.17.0 | local-fixture | 1 PASS | `run-20261116T092926-c1e7ea803f4e4f56` |

Promptfoo/Inspect each ran all six allowed/denied/injection/disclosure cases through
the real tool and a deterministic local provider. Inspect retains per-sample exact
scorer results and aggregates. Playwright used actual Chromium 156.0.8078.79 and
server/UI checks. ZAP passively analyzed exactly one authorized captured response;
three header observations remain NOT_REVIEWED and unconfirmed. Active scans remain
BLOCKED even with opt-in because the exact bounded P003 activity is unsupported.

Actual command arrays are in each result/manifest. Tool invocation forms:

```
promptfoo eval --config <generated.json> --output <result.json> --no-cache --no-progress-bar --no-table --no-write --max-concurrency 1
.tools/inspect/bin/python -m p007.adapters.inspect_ai.worker <input.json> <summary.json>
Playwright sync API: pinned Chromium, isolated contexts, guarded route fulfillment
zap.sh -Xmx768m -cmd -silent -host 127.0.0.1 -port 0 -dir <owned-home> -autorun <generated.yaml>
```

Only the loopback P007-owned fixture is network-capable. Tests proved unknown/public,
metadata/private/ambiguous destinations, unapproved redirects, mapping changes,
expired/missing/revoked/mismatched authorization and out-of-scope methods/activities
refuse before traffic. Every HTTP operation rechecks actual P003 evidence/current
state; external browser navigation is blocked. P003 approvals here are explicitly
simulated engineering records, not independent human/legal approval.

## Baseline, remediation, regression and evidence

- Baseline `run-20261116T093547-56f8df5073924abf`: {'PASS': 9, 'FAIL': 1, 'FLAKY': 1}.
- Simulated remediation `run-20261116T093548-d22a7b8f996b4efa`: {'PASS': 10, 'FLAKY': 1}.
- Introduced regression `run-20261116T093548-d7e2e31d0dcd423e`: {'PASS': 9, 'FAIL': 1, 'FLAKY': 1}.
- Explicit policy/target-version compatibility rules detect output-validation
  FAIL→PASS improvement and sentinel PASS→FAIL regression. Other identity changes
  are non-comparable; the mixed repeated sample stays FLAKY.
- Two recorded offline reproductions were consistent; CLI reproduction also passed.
- 9 selected retained runs verified **76 artifact hashes/sizes**.
  Modified/missing artifacts and manifest/result edits were detected by negative tests.
- Evidence: `p-007/evidence/<run-id>/manifest.json`; reports:
  `p-007/reports/<run-id>/`; demo summary:
  `p-007/reports/demo-run-20261116T093547-56f8df5073924abf.json`.

Baselines are immutable and protected from cleanup. SHA256 checks establish recorded
content consistency only, not identity, trusted time, authenticity or oracle correctness.
Raw temporary tool files are discarded after safe fields are captured; structured
samples, original codes/statuses and native output hashes remain. Source drift blocks
offline reproduction rather than silently substituting current inputs.

## Sibling integrations

| Project | Verified scope and limits |
|---|---|
| P001 | PASS metadata contract, runtime kind/Kubernetes NOT_TESTED |
| P002 | PASS actual Dataset 1.0 generation/identity/scenario export |
| P003 | PASS actual sealed metadata and fresh synthetic ledger evaluator; legal authority NOT VERIFIED |
| P004 | PASS actual inventory/Snapshot 1.0 and architecture digest |
| P005 | PASS actual model/analyze threat/control hypotheses; not findings |
| P006 | BLOCKED, no committed implementation or verified target |

Actual sibling contract demo also ran with network disabled. Exports retain future
P008 metadata, P009 evidence references and P010 retest/control outcomes without
implementing those platforms. An illustrative schema-valid export is committed in
`p-007/examples/report-export.example.json`.

## Install and operator commands

```bash
cd /workspace/p001/p-007
./scripts/setup
./scripts/setup --tools
make doctor
make validate
make catalog
make plan TARGET=offline-demo
make run TARGET=offline-demo PROFILE=offline
make demo
make compare BASELINE=run-20261116T093547-56f8df5073924abf CURRENT=run-20261116T093548-d22a7b8f996b4efa RULE=synthetic-remediation-v1
make reproduce RUN=run-20261116T093547-56f8df5073924abf TEST=T-offline-cross-tenant
make evidence-verify RUN=run-20261116T093547-56f8df5073924abf
make report RUN=run-20261116T093547-56f8df5073924abf
make verify
make test-live
PYTHONPATH=tests/no-network .venv/bin/python -m pytest tests -m 'not live'
PYTHONPATH=tests/no-network .venv/bin/python scripts/demo-contracts.py
make cleanup RUN=<owned-non-baseline-run-id> CONFIRM=p007-owned-evidence
./scripts/p007 run --target local-model --profile promptfoo
./scripts/p007 run --target local-model --profile inspect_ai
./scripts/p007 run --target local-fixture --profile playwright --local-demo
./scripts/p007 run --target local-fixture --profile zap --local-demo
```

Default baseline run exits 1 because its failure is intentional. All PASS exits 0;
blocked/incomplete/flaky or invalid operations exit 2. The demo command asserts the
expected lifecycle and exits 0. Cleanup requires explicit confirmation and refuses
protected baselines. An owned disposable passing run was removed to test cleanup.
Normal and `P007_OFFLINE=1` cached core setup both executed successfully; optional
tools were installed using the pinned locks/npm graph and verified by real runs.

## Files, dependencies, limits and handoff

New `p-007/` source, schemas, catalog, fixture policies, runner modules, scripts,
tests, documentation and lockfiles; new read-only-permission offline CI workflow.
Root README links P007. Root static checker now excludes ignored `.runtime` tool
homes from CPython parsing, because ZAP generates Jython templates there; source
checks and secret scanning remain enabled. No sibling source/data was changed.

Direct tool licenses: Promptfoo and Inspect MIT; ZAP and Playwright Apache-2.0.
Core/sibling pins and isolated Inspect constraints are documented; complete installed
package/license metadata is in dependency-inventory.json. UNKNOWN entries and
upstream notices need review before any redistribution. Runtime artifacts, packages,
credentials, cookies, browser profiles and environments are not source deliverables.

At the initial local handoff, CI was configured but had not run on GitHub. Remote
CI outcomes for the later authorized publication are recorded in the PR. Only the
recorded Linux x86_64 host was tested. macOS/Windows/ARM, other browser engines,
vendor/hosted models, arbitrary targets and live P006 are NOT_TESTED/unsupported.
The managed host lacks Chromium's sandbox helper; the explicit sandbox-disabled
profile handles trusted fixture pages only. Process groups have CPU/time/output and
sampled RSS ceilings, but no hard cgroup memory fence; the in-process browser has no
hard RSS boundary. No general sandbox, broad jailbreak resistance or security
effectiveness of real vendor systems is claimed. Real model nondeterminism needs
new empirical data; the alternating fixture demonstrates accounting only.

Codex implemented and tested. `docs/learner-workbook.md` contains questions only;
**G1–G4 NOT DEMONSTRATED**. Human independently reproduced and External human
reviewer verified remain **NOT DEMONSTRATED**. No client engagement, competence
certification or publication approval is inferred.
