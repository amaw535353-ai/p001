# P-005 delivery and evidence

## Repository and preservation

- Actual repository: amaw535353-ai/p001, /workspace/p001.
- Branch: feat/p-005-threat-modeling, created from clean `work` at
  6e153d22b6822bed22e9895b0bef7b176456c258.
- Working directory: /workspace/p001/p-005. Changes are new, uncommitted p-005/
  files for review; no predecessor/root tracked file changed, no push or publish.
- The two uploaded build prompts were byte-identical. The current task cannot
  open another dedicated Codex chat; branch/directory isolation was used.
- Reused the existing checkout; no Git worktree or new repository was created.

## Working capabilities

Strict typed graph/evidence/scope contracts and eight generated JSON schemas;
bounded JSON/YAML parser and no-follow/atomic output IO; directed candidate trust
boundaries and bounded real-hop paths; 23-rule safe boolean DSL; source-constrained
risk references, ordinal triage, owned proposed controls and non-executable
positive/negative test designs; exact-digest synthetic review ledger; increasing-
version diff/invalidation; actual offline predecessor adapters; pinned ATLAS data;
escaped/redacted exports, integrity checks and a synthetic consultancy report.
No live runner, LLM or generated-Python executor exists.

The two-tenant fixture has 37 nodes, 39 flows and 37 inferred boundaries. It
produces **34 hypotheses**, never findings. All 34 verification plans remain
NOT_TESTED and all controls CONTROL_PROPOSED. The checked-in sample contains
8 selected candidates with matching controls, mitigations, plans and real paths.

Rules fired: approval-integrity, broad-delegation, budget-exhaustion, dependency-origin, direct-instructions, goal-drift, indirect-prompt, mcp-boundary, provider-routing, retention-isolation, retrieval-integrity, sensitive-audit, unsafe-output.

Prompt risk references on this baseline: R1, R4, R5, R6, R7, R8, R10, R12, R13, R14, R15, R18, R24, R35, R36, R37. They are not claims
of taxonomy completeness or real risk coverage. The other available risk rules
fire only on relevant added features/controlled variants; unavailable taxonomy
entries are rejected rather than guessed.

## Commands and actual outcomes

| Check | Outcome |
|---|---|
| hash-locked ./scripts/setup | PASS; verified wheels and editable actual sibling contracts |
| P005_OFFLINE=1 ./scripts/setup | PASS; cached hash-verified refresh |
| pip install --no-index --no-build-isolation -e '.[dev]' | PASS in prepared venv |
| make doctor | PASS for OFFLINE_CORE; optional/tool/taxonomy limits explicit |
| make verify | PASS: 98 passed, 0 failed, 0 errors, 0 skipped |
| Ruff lint / format / mypy | PASS, 17 runtime Python modules checked |
| eight schema drift checks / pip check / source checks | PASS |
| make demo-offline | PASS: build, validate, analyze, graph, report, plans, diff, catalog, manifest/verify |
| make demo-integrations | PASS: actual P001/P002/P003/P004 metadata contracts |
| root make unit static | PASS: 7 tests and static checks |
| P-002 predecessor regression | 80 PASS; 1 SKIPPED (optional SDV) |
| P-003 predecessor regression | 162 PASS; 1 SKIPPED (optional pre-existing standard dataset/venv integration) |
| P-004 predecessor regression | 128 PASS; 3 SKIPPED (browser/ZAP/Kubernetes prerequisites) |
| Docker kernel-networkless demo | PASS; exit 0, UID 10001, lo only, CapEff zero, read-only root |
| Docker versus host content comparison | PASS: 26 artifact hashes identical |
| Real target / native tools / learner G1–G4 | NOT_TESTED / BLOCKED / UNVERIFIED |

Evidence: evidence/engineering/run-1794767676272353962/manifest.json (exact commands, exits, JUnit, package
versions, fixture/source/lock hashes); evidence/engineering/manifest.json is the
latest pointer/copy. Regression XML and reconciled counts are in
`evidence/regressions/summary.json`; original initial harness failure is retained
in the scrubbed logs. A zero-network guard prevented P-002's local redirect
fixture; its controlled loopback rerun passed. P-004's ten marked local safety
cases also passed separately. No real target/scanner was used.

Early P-005 development runs exposed and fixed a redaction/status collision, an
outside-root test's depth assumption, type annotations and a static-check literal
false positive. No required engineering check remains failed. Earlier evidence
runs are retained and not relabeled as passing.

Linux x86_64, Python 3.12.14, 5 reported CPUs, 33 GiB host RAM. Dependencies and
versions are in requirements.lock and engineering evidence. No paid account or
service is required. Container image: sha256:302387873fa96a3812c81a66974f43f3683e6c29ec654bd349a1ac191c988daa.
Resource flags were supplied, but rootless cgroup enforcement is NOT_VERIFIED.
Container runtime proof and exact command are in evidence/container-proof.json.
No P-005 container remains running. Install-time artifact retrieval is separate
from the verified networkless execution.

## Actual integration results

- P-001 VERIFIED for allowlisted local declarative inventory: 24 nodes, no invented
  flows. IAM, network policy and full kind lifecycle remain NOT_TESTED/BLOCKED.
- P-002 VERIFIED using its actual tiny generator and Dataset validator: 96 nodes,
  122 grant/oracle edges and 18 design hypotheses. Human/workload distinction,
  document classifications/trust, scenario context and ALLOW/DENY expectations
  remain separate from NOT_TESTED enforcement.
- P-003 VERIFIED sealed Engagement context: version, scope, exact tenant-aware
  source/URL matching, exclusions and assessment window. This is NOT real legal
  authority, fresh ledger validation or target-side enforcement.
- P-004 VERIFIED actual offline inventory and Snapshot validation: 153 nodes,
  52 directed flows and 28 design hypotheses. Source statuses, IDs, addresses,
  evidence pointers and coverage/boundary/observation summaries are retained;
  unknown imported zones stay unknown. Passive alerts stay unverified signals.

Exact source and generated run paths: generated/integrations/integration-results.json.
The independent baseline run correctly labels unused predecessors NOT_TESTED;
integration status is run-specific. No integration is inferred from an absent
master prompt or unexecuted command.

## Catalog and native tools

ATLAS content 2026.10, format 6.1.0, official
commit f56c1468731d6428e5bf875263b4643b46d67437; 221 technique entries parsed. Distribution SHA-256:
ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d. Apache-2.0 notice and full license retained. Source and projection
checksums match. This verifies inspected structural projection, not execution of
upstream schemas or full ATLAS relationship semantics. Technique links are
CANDIDATE_REVIEW/UNMAPPED with rationale, not attacks or evidence of weakness.

Threat Dragon #122, pytm #123 and Threagile #124: versions/schema versions null,
executed false, no native output digest, no roundtrip, BLOCKED because tools and
reviewed schemas are unavailable. Native exports are intentionally unimplemented;
no fake vendor-looking files or Python are emitted. Own JSON/Markdown/Mermaid/DOT
work offline. See docs/tool-adapter-compatibility.md and adapter-status.json.

## Artifacts and handoff

- generated/demo-baseline/: complete model/entities, 34 threats, real paths,
  proposed controls/mitigations, plans, rule/risk/ATLAS mappings, statuses,
  three diagrams, four reports, empty initial review log and integrity manifest.
- generated/demo-changed/ and generated/model-diff.json: controlled cross-tenant
  link/out-of-scope change, new boundaries/hypotheses and invalidated old decisions.
- examples/reference-architecture/: eight selected sanitized candidates and
  matching linked artifacts; sample-manifest.json records exactly this subset.
- examples/change-scenario/model-diff.json: sanitized change example.
- schemas/, rules/core.json and catalogs/: versioned contracts, safe rules,
  actual official catalog bytes and attribution.

Host baseline artifact root: b91ad2e8a667c0fa0cbcbc39c6b8edf58d9e87d202822e9df67c9cb01c0c8544.
Hash matching establishes integrity/reproducibility, not authenticity, assessment
quality or human verification. Pattern redaction passed synthetic canary tests;
arbitrary private content still requires independent review before publication.
Consult docs/publication-checklist.md and docs/source-attribution.md for licensing.

Future P-006/P-007/P-009/P-010/P-083 and P-091/P-092/P-093/P-099 consumers can pin
schemas and manifests. No future project is implemented or certified. All plans
need independent acceptance, missing evidence and fresh P-003 authorization.

## Outstanding work and limits

Full authoritative 37-risk validation is BLOCKED: the four requested source
files are absent. Only 23 prompt-described entries are usable; 14 numbered slots
are explicitly unavailable. Supply the authoritative risk/crosswalk files and
review mappings before claiming full taxonomy alignment. Native adapters need
real reviewed tool versions/schemas and separately verified containment before
implementation. Confirmed findings/tested-control imports are not implemented.
No authenticated multiuser signoff, arbitrary code plugin, live importer, CSV
intake, external LLM, rendered SVG/PNG or target assessment is claimed.

A fresh dependency environment was exercised in the container. A separately
published cloud snapshot/CI/WSL2 host is NOT_TESTED. The existing repository has
no overall license added by this work; review redistribution rights. Independent
learner challenges in docs/learner-workbook.md remain unsolved; G1–G4 UNVERIFIED.
Codex built and tested software, not the learner's security competence.

## Precise reviewable file tree

Runtime outputs, caches, virtual environments and generated evidence are ignored.
The following source/data/docs/example paths are new under p-005/:

```text
.dockerignore
.env.example
.gitignore
AGENTS.md
Makefile
README.md
catalogs/ATLAS-pin.json
catalogs/ATLAS-pinned.yaml
catalogs/Apache-2.0.txt
catalogs/LICENSE-ATLAS.txt
catalogs/README.md
docs/architecture.md
docs/consultancy-report-template.md
docs/implementation-plan.md
docs/integration-contracts.md
docs/learner-workbook.md
docs/limitations.md
docs/publication-checklist.md
docs/schema-and-interfaces.md
docs/security-assumptions.md
docs/source-attribution.md
docs/test-strategy.md
docs/threat-model-methodology.md
docs/threat-rules.md
docs/tool-adapter-compatibility.md
docs/trust-boundaries.md
evidence/.gitkeep
examples/change-scenario/README.md
examples/change-scenario/model-diff.json
examples/reference-architecture/README.md
examples/reference-architecture/architecture.dot
examples/reference-architecture/architecture.mmd
examples/reference-architecture/attack-paths.json
examples/reference-architecture/controls.json
examples/reference-architecture/mitigations.json
examples/reference-architecture/model.json
examples/reference-architecture/sample-manifest.json
examples/reference-architecture/threat-register.json
examples/reference-architecture/trust-boundaries.mmd
examples/reference-architecture/verification-plan.json
fixtures/baseline/architecture.yaml
fixtures/variants/added-egress.yaml
fixtures/variants/changed-permissions.yaml
fixtures/variants/disabled-logging.yaml
fixtures/variants/disabled-policy.yaml
fixtures/variants/excessive-tool-actions.yaml
fixtures/variants/stale-grants.yaml
fixtures/variants/tenant-boundary-change.yaml
fixtures/variants/wrong-audience.yaml
pyproject.toml
requirements.in
requirements.lock
rules/core.json
schemas/adapter.schema.json
schemas/control.schema.json
schemas/model.schema.json
schemas/review.schema.json
schemas/risk.schema.json
schemas/rule.schema.json
schemas/threat.schema.json
schemas/verification.schema.json
scripts/Dockerfile.offline
scripts/build-schemas.py
scripts/check-sources.py
scripts/demo-integrations.py
scripts/demo.py
scripts/export-demo.sh
scripts/p005
scripts/setup
scripts/verify.py
scripts/verify.sh
src/p005/__init__.py
src/p005/__main__.py
src/p005/adapters/status.py
src/p005/catalogs/atlas.py
src/p005/cli.py
src/p005/data/LICENSE-ATLAS.txt
src/p005/data/atlas-index.json
src/p005/data/atlas-mappings.json
src/p005/data/atlas-pin.json
src/p005/data/risks.json
src/p005/data/rules.json
src/p005/domain/schemas.py
src/p005/evidence/safety.py
src/p005/export/diagrams.py
src/p005/export/reports.py
src/p005/export/run.py
src/p005/ingestion/fixtures.py
src/p005/ingestion/predecessors.py
src/p005/modeling/diff.py
src/p005/modeling/graph.py
src/p005/modeling/review.py
src/p005/modeling/risk_catalog.py
src/p005/modeling/rule_engine.py
tests/conftest.py
tests/no-network/sitecustomize.py
tests/test_exports.py
tests/test_integrations.py
tests/test_model.py
tests/test_rules.py
docs/delivery-report.md
```
