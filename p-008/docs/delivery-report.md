# P-008 delivery report — 2026-11-16

This report records the initial local engineering handoff, before source publication.
The user subsequently explicitly authorized commit, push and merge in the existing
private repository. The resulting pull request and Git history record the final
source revision, remote checks and merge; generated datasets/reports remain local.

Implemented locally: **P-008 — AI Security Evaluation Datasets and Regression Testing Pipeline.**
Engineering provenance: **Codex implemented / Codex tested**. Human independently reproduced and External human reviewer verified: **NOT DEMONSTRATED**.

## Repository and source state

- Existing private repository: https://github.com/amaw535353-ai/p001; checkout `/workspace/p001`.
- Base: `p001-initial`; local feature: `feat/p-008-evaluation-pipeline`.
- HEAD/base commit: `2c2ddfe72cb205c89c7b7b6bf7614008dfb4dcc1`. Implementation changes are local and uncommitted; the tree is dirty. Intent-to-add entries expose new files in `git diff` without creating a commit.
- Project path: `p-008/`; only this project and its new offline CI workflow are changed. Existing P-001–P-007 files are unchanged.
- No push, PR creation, merge, dataset/report publication or repository-setting change was performed.
- P-007 PR #5 is merged at this base; its feature branch was not modified. Branch-protection state is NOT_VERIFIED because the direct API route was forbidden; open-PR search returned none during discovery.
- P-006 has no committed application/runtime and remains BLOCKED.
- Four requested background crosswalk/risk/project-list/career documents were absent; exact names and source gaps are in source-discovery.md. The uploaded master prompt is a specification, not execution evidence.

## Architecture and data flow

Seed + authored cases → strict bundle/reference validation → duplicate/label/lineage audit → frozen public inputs and separate private expected outcomes → anchored plan → fixed local tool/responder → actual observations and mock server traces → deterministic host oracle → sample results and reconciled descriptive metrics → strict identity comparison/reproduction → sanitized local P-007/P-009/P-010 handoff. Cohesive flat modules implement the requested registry, dataset, validation, integrity, planning, adapters, scoring, comparison and reproduction components. See architecture.md.

## Actual inventory and quality

| Dataset | Seed | Samples | Development | Validation | Public | Sealed | Regression |
|---|---:|---:|---:|---:|---:|---:|---:|
| synthetic-core 1.0.0 | 20261116 | 48 | 10 | 10 | 10 | 10 | 8 |
| synthetic-core 1.1.0 | 20261117 | 48 | 10 | 10 | 10 | 10 | 8 |

- Six families, eight samples each: integrity, injection, authorization, disclosure, boundary and context; 24 lineage groups, 24 ALLOW/24 DENY outcomes. Text/UTF-8 only. Formal Risk #21 mapping covers eight integrity samples; other scenarios do not invent taxonomy mappings.
- Six task definitions and 24 scenario definitions at 1.0.0; deterministic oracle and exact-behavior rubric at 1.0.0, threshold 1.0; evaluator/adapter definitions 1.0.0. All serialized contracts use schema 1.0.
- Self-authored fictional provenance retains generator version/seed/source SHA-256, base commit, attribution and LicenseRef-P008-Synthetic. Redistribution is review_required. Sealed labels/canaries are generated only into ignored private runtime storage.
- Actual initial audit: invalid labels 0; exact duplicate pairs 0; near-duplicate review candidates 0; leakage groups 0; missing dataset provenance/licenses 0. Category/split/modality/difficulty/outcome coverage reconciles to 48.
- Seed/version changes preserve historical baselines. Tiny related templates are not independent or representative populations; metadata correctness and semantic contamination need human review.
- Baseline frozen manifest SHA-256: `4f5ac4f3fd5f072621997f35d322524a6f91af59c37c7e26eafbfae880aaa139`.
- Generator source SHA-256: `a55b3b62a9476ba186081791912952dd5ceac2f2c6dd43572d66fa7e3d6f15d1`.
- Scorer implementation SHA-256: `47998251b5f293aed15af9586d1eba601b579efb0ba73f862782150afd0b88fb`.

## Actual tool integration outcomes

All evaluated behavior uses `p008-local / deterministic-policy-v1 / model version 1.0.0`, network disabled, no API keys or vendor model. Dependency installation and advisory/source inspection used package/GitHub network access; evaluations did not.

| Inventory/tool | Installed | Actual selected operation/environment | P-008 samples executed | Outcome |
|---|---|---|---:|---|
| #41 inspect_ai | 0.3.290 | Real Inspect Task/solver/scorer with local mock outputs and native .eval logs | 48 | 47 PASS / 1 deliberate critical FAIL / 0 blocked |
| #42 inspect_evals | 0.29.0 | Actual strong_reject task import/record conversion on P-008 synthetic records; upstream benchmark samples 0, native corpus/judge NOT_TESTED | 48 | 47 PASS / 1 deliberate critical FAIL / 0 blocked |
| #4 agentdojo | 0.1.35 | Actual FunctionsRuntime and BaseUserTask/BaseInjectionTask in P-008 in-memory environment; official full suites NOT_TESTED | 48 | 47 PASS / 1 deliberate critical FAIL / 0 blocked |
| #3 promptfoo | 0.125.1 | Actual eval CLI, pinned local CommonJS provider and fixed per-test Javascript assertions | 48 | 47 PASS / 1 deliberate critical FAIL / 0 blocked |

Each adapter also passed its separate live acceptance test on eight authorization examples. The intentional full-collection FAIL is faithfully retained, not a missing integration. Worker argv arrays, raw native results, tool config, upstream source references, package/adapter identities and all artifact hashes are stored with each run. Shared preflight supports capability/version checks and fixed-plan dry-run. No arbitrary URLs/plugins/providers are accepted.

- `inspect_ai` run `run-4ad37a619d9c41e28135928584f87d5b`, plan digest `bce097cfe2762ce891fbba841713f6dd3ccc14e0c39ac09be92511b8642e8b4e`.
  Actual worker command: `/workspace/p001/p-008/.tools/venv/bin/python /workspace/p001/p-008/src/p008/adapters/worker.py /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-4ad37a619d9c41e28135928584f87d5b/tool-input.json /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-4ad37a619d9c41e28135928584f87d5b/tool-output.json`
- `inspect_evals` run `run-c34ccecef410416e9a3bb1558423b479`, plan digest `a18ecc379d5371cb82c0fd8ae2f635703b9bda1a7c221e42d8b748573bacb943`.
  Actual worker command: `/workspace/p001/p-008/.tools/venv/bin/python /workspace/p001/p-008/src/p008/adapters/worker.py /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-c34ccecef410416e9a3bb1558423b479/tool-input.json /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-c34ccecef410416e9a3bb1558423b479/tool-output.json`
- `agentdojo` run `run-c82c08f0637448799ef28b8b0598b23a`, plan digest `ad725ab58de4f0215ef96bbf3825908e8d4dcaca294787097bb5b0f95dbe1491`.
  Actual worker command: `/workspace/p001/p-008/.tools/venv/bin/python /workspace/p001/p-008/src/p008/adapters/worker.py /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-c82c08f0637448799ef28b8b0598b23a/tool-input.json /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-c82c08f0637448799ef28b8b0598b23a/tool-output.json`
- `promptfoo` run `run-db51487aa53f434ab2e5e62636d2851f`, plan digest `b2304a12ba7acf2144b3c536bdd22b6b2604964b89b4f9d14f47e62cc13bb9cf`.
  Actual worker command: `/opt/codex/runtimes/codex-primary-runtime/dependencies/node/bin/node --max-old-space-size=512 /workspace/p001/p-008/.tools/npm/node_modules/promptfoo/dist/src/entrypoint.js eval --config /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-db51487aa53f434ab2e5e62636d2851f/promptfoo-config.json --output /workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-db51487aa53f434ab2e5e62636d2851f/tool-output.json --no-cache --no-progress-bar --max-concurrency 1`

## Scoring and results

- Baseline `run-6d01a1bdec4943ab92d2015b2a6138bb`: 48 unique fully executed samples; 47 PASS, 1 FAIL, 0 BLOCKED/NOT_TESTED/INCONCLUSIVE; zero flaky samples. Critical ID: `p008-injection-04`.
- Unique pass rate 47/48 = 97.9167%; one false accept and zero false rejects against fictional authored decision labels. Required dimensions and threshold are retained per sample. A critical security failure vetoes a passing run.
- Illustrative Wilson interval: [0.8910078200, 0.9963128890]. Related templates violate independence; this is not population confidence or real-model security evidence.
- Per-sample observations/scores: `/workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/runs/run-6d01a1bdec4943ab92d2015b2a6138bb/sample-results.json`. Each run also retains anchored run.json and native tool files.
- Metrics reconcile every planned sample/repetition, prevent duplicate denominator inflation, retain failures and classify incomplete/flaky observations separately. Host oracles explicitly read private expected outcomes; model/judge input projections do not.
- Model judging is supplementary-only and disabled. Judge agreement arithmetic is tested with a clearly synthetic fixture; actual human calibration, model-judge behavior and human adjudication are NOT_TESTED.

## Risk #21 laboratory and limits

- Preserved lab: `/workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/lab/lab-5d666885646341ab8042ad60e161fbde`; all 12 controlled checks completed.
- M01 label flip: frozen hash detects an unauthorized change; a naive decision-only rate can be skewed while the independent disclosure oracle still rejects exposure.
- M02 threshold change and M05/M06 evaluator/judge drift: scorer/configuration digests block silent comparability.
- M03 failed-row omission, M04 passing-row duplication and M09 favorable-category selection: planned sample/repetition reconciliation rejects a misleading 100% presentation.
- M07 sealed-key leakage: explicit visible-input/canary checks detect known key exposure even after digest recomputation. M08 lineage split movement is detected by scenario/template/construction grouping.
- M10 plan edit: recorded digest/independent anchor mismatch. M11 changed model identity: noncomparable. M12 judge injection: retained hostile content cannot edit host configuration; live LLM resistance is not established.
- Every case preserves original.json, altered.json and event.json, with distinct digests and an explanation. Hashes require trusted retained anchors and do not prove honest initial labels, authorship, trusted time or semantic nonleakage. Human review remains necessary.

## Comparison and reproduction evidence

- Same identity rerun `run-7472f46171c04523b147cc58f0a791f9`: `UNCHANGED`, comparable; all sample transitions retained.
- New dataset run `run-2c2777e587a04af5bcf3cd690083fd6c` (1.1.0/new seed): `DATASET_CHANGED`, NOT_COMPARABLE; no regression delta claimed.
- Offline reproduction `run-21263cdf090548b09fddedc49e7305c6` matches original selected failure `p008-injection-04`. Input manifest `4f5ac4f3fd5f072621997f35d322524a6f91af59c37c7e26eafbfae880aaa139`; original/reproduced selected-output hash `1413cb37fb197162857ee768c7d367769b9de17d7d7a45e6431691029b4a9df8`.
- Actual Inspect reproduction `run-89e0b99760e5457db06df42a0acf9788` matches `run-4ad37a619d9c41e28135928584f87d5b`; selected-output hash `431263307bbb4a249b3634980b2982ede1990e5f0351d7df9b1cdfc41189ac2c`.
- Reproduction-mechanics status PASS is distinct from evaluation status FAIL. Current source/tool/lock drift is rejected instead of substituting current inputs.

## Sibling and future integration matrix

| Project | Actual status | Contract and limit |
|---|---|---|
| P-002 | PASS | Dataset-1.0; Generated references only, not native enforcement. |
| P-003 | PASS | sealed-Engagement-1.0; Read-only metadata validation; time window may be expired. No network tasks or real authority used. |
| P-005 | PASS | p005-model-1.0; Modelled candidate threats only; no findings or automatic P008 labels. |
| P-007 | PASS | ReportExport-1.0; Actual merged P007 contract validated read-only. Evidence references retained, not re-executed or authenticated; results are not dataset labels or fresh authorization. |
| P-006 | BLOCKED | absent; No committed application or independently verified runtime at inspected base. |
| P-009 | NOT_TESTED | p008-handoff-1.0; Export-only future consumer. |
| P-010 | NOT_TESTED | p008-handoff-1.0; Export-only future consumer; no consultancy findings generated. |

P-007 import preserves its original 11-result example, run ID, manifest digest, normalized results, control status, handoff and provenance. It does not authenticate/reexecute source evidence or turn control outcomes into labels. Standalone core operation was also verified with no sibling packages installed; those integrations then remain BLOCKED.

## Executed engineering verification

| Category | Passed | Failed / skipped |
|---|---:|---|
| unit | 8 | 0 / 0 |
| schema | 8 | 0 / 0 |
| dataset_quality | 10 | 0 / 0 |
| provenance | 10 | 0 / 0 |
| evaluator | 12 | 0 / 0 |
| benchmark_integrity | 12 | 0 / 0 |
| adapters | 6 | 0 / 0 |
| security | 13 | 0 / 0 |
| integration | 3 | 0 / 0 |

- Total **82 passed**, 0 failed/errors/skips; all 58 required acceptance IDs mapped. Four actual tool assertions are included in adapters. Socket/DNS-disabled rerun: **78 passed**, four live assertions intentionally deselected.
- Root `make unit static`: 7 tests passed and structural/narrow secret checks passed. P-008 make verify, Ruff lint/format, mypy (18 source files), all 21 schema drift/validity checks and both Python dependency compatibility checks passed.
- Setup reran successfully in the existing environment. A fresh hash-locked core-only environment installed the documented editable project and reproduced the full demo with sibling modules unavailable. A clean source reconstruction from the approved base Git archive plus the patch also passed fresh setup, all 78 offline tests, schema/quality validation and the demo; its manifest matched `4f5ac4f3fd5f072621997f35d322524a6f91af59c37c7e26eafbfae880aaa139` exactly. The owned reconstruction is ignored under `.runtime/clean-source`; no second Git worktree or remote clone was created. A relocated standalone wheel is unsupported.
- Core/tool Python locks audited separately with pip-audit 2.10.1: zero known advisories for 24/135 locked packages. Final npm audit: zero known advisories after five reviewed pinned transitive overrides, followed by real Promptfoo reruns. No advisory suppressions.
- Dependency/license metadata inventory and exact gap resolutions are documented. Local-project redistribution rights still require review. This is not a complete legal or vulnerability-free attestation.
- CI workflow `.github/workflows/p008-offline.yml` is configured but **NOT_RUN** remotely because no push occurred. Linux x86_64/Python 3.12.14/Node 24.22.1 verified; other OS/architecture targets NOT_TESTED.

## Files, publication and learner handoff

- Changes add P-008 source, 21 schemas, generator/quality/registry/pipeline/oracles, four tool workers, read-only sibling import, strict comparison/reproduction, manipulation lab, CLI/Make/scripts, two Python locks, npm lock/overrides, documentation/licenses/workbook, tests and one new CI workflow.
- Runtime datasets, sealed keys, native tool logs, raw dummy-secret observations, reports, imports, baselines, temporary environments and caches are ignored. `git diff --check` and root narrow secret checks passed. Existing sibling source/data/evidence was not edited.
- Sanitized local handoff: `/workspace/p001/p-008/.runtime/delivery/demo-2fdd4845b65a4e868dd56feec1bf3e78/exports/export-95513b5557501d92d2395933`. It includes dataset card, nonholdout model-visible inputs, quality/provenance, evaluation report and versioned P-007/P-009/P-010 handoff. Sealed sample result rows, raw observations and known secret/key markers are excluded. Publication status remains REVIEW_REQUIRED / NOT_PERFORMED.
- Exact local source diff is available with `git diff -- p-008 .github/workflows/p008-offline.yml`; a retained patch is placed under ignored `.runtime/delivery/p008.patch` after final documentation review.
- Unanswered learner workbook: `p-008/docs/learner-workbook.md`; **G1–G4 NOT DEMONSTRATED**. No human evidence was fabricated.

A high score or a large dataset does not prove an AI system is secure. These results establish finite synthetic pipeline mechanics, provenance checks and reproducibility only.
