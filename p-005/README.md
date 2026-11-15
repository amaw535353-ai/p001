# P-005 — AI Threat Modeling-as-Code and Trust Boundary Analysis System

**Synthetic design hypotheses, never confirmed vulnerabilities.** Python 3.12 CLI
for offline architecture intake, directed data-flow/trust-boundary analysis,
explainable STRIDE/AI rule hypotheses, proposed controls and independent review.
Built in the existing `amaw535353-ai/p001` repository on
`feat/p-005-threat-modeling`, alongside unchanged P-001–P-004.

The working reference fixture has two tenants, distinct human/workload identities,
37 nodes and 39 flows. Analysis creates 34 candidate hypotheses, not 34 findings.
Eight controlled design variants exercise permission, tenant, token, connector,
egress, tool, logging and policy changes. No targets, LLM API, AWS account,
scanners, rendering engine or heavy service is needed.

## Installation

Tested: Linux x86_64, Python 3.12.14. WSL2 Linux is a prospective reproduction target;
native Windows is unsupported because safe filesystem operations require POSIX.
Use this existing isolated checkout; do not create worktrees unless requested.

```bash
cd /workspace/p001/p-005
./scripts/setup                  # hash-locked wheels, editable local projects
source .venv/bin/activate
make doctor
make test
make verify
make demo-offline
make demo-integrations
```

`python -m pip install -e '.[dev]'` is supported after inspection. The setup script
pins and verifies the complete dependency/tool chain and installs the actual local
sibling contracts. It caches wheels under ignored `generated/setup/wheels`.
`P005_OFFLINE=1 ./scripts/setup` refreshes from that cache with hashes and no index.
After dependency installation, normal commands require no network. No services
need to remain running or survive a cloud snapshot.

## Real operator commands

With `.venv/bin` on PATH (or use `./scripts/p005`):

```bash
p005 model build --input fixtures/baseline/architecture.yaml --out generated/demo-baseline
p005 model validate --input generated/demo-baseline/model.json
p005 analyze --model generated/demo-baseline/model.json --out generated/demo-baseline
p005 graph render --model generated/demo-baseline/model.json --format mermaid --out generated/demo-baseline/diagrams/architecture.mmd
p005 report --run generated/demo-baseline --format markdown
p005 model build --input fixtures/variants/tenant-boundary-change.yaml --out generated/demo-changed
p005 diff --before generated/demo-baseline/model.json --after generated/demo-changed/model.json --out generated/model-diff.json
p005 tests plan --run generated/demo-baseline --out generated/demo-baseline/verification-plan.json
p005 catalog validate --input catalogs/ATLAS-pinned.yaml
p005 catalog list
p005 catalog update --from-local-file catalogs/ATLAS-pinned.yaml --metadata catalogs/ATLAS-pin.json --out generated/catalog-candidate.json
p005 adapters status
p005 evidence manifest --run generated/demo-baseline
p005 evidence verify --run generated/demo-baseline
```

`make demo-offline` executes and logs the end-to-end workflow with sockets and DNS
blocked in child processes. Tests instrument failed attempts too, even if caught.
An optional Docker engineering check also runs with kernel networking disabled;
see docs/test-strategy.md. Docker is not required for ordinary use.

Review decisions are separate, explicit synthetic editorial records. Substitute a
real generated threat ID; do not treat this example as a decision to apply:

```bash
p005 review decide --run generated/demo-baseline --threat THREAT_ID --decision NEEDS_INFORMATION --reviewer-role synthetic-reviewer --reason 'Independent evidence is still needed' --at 2026-11-15T01:00:00Z --simulate-review
p005 tests plan --run generated/demo-baseline --accepted-only --out generated/accepted-plan.json
```

Reasoned priority overrides use `--priority HIGH|MEDIUM|LOW`. These records are
unverified caller assertions, not authenticated signatures, findings or permission
to test. No attack execution command exists. Out-of-scope proposals remain flagged
and cannot enter an accepted-only plan. Architecture diffs invalidate old decisions.

## Intake and outputs

`model build --source p004 --input <snapshot.json> --out generated/p004-run` uses the
actual local Snapshot validator and digest. `--fallback-fixture <architecture.yaml>`
works only for an absent snapshot, never malformed input. `--source p002` accepts a
real synthetic Dataset; `--source p001` accepts only the reviewed root inventory
paths. `--context ../p-003/examples/engagement-draft-a.json` applies exact source-ID
scope constraints without granting live authority. See integration-contracts.md.

Each analyzed run contains model/entity tables, threats, paths, controls,
mitigations, verification-plan, rule trace, risk traceability, ATLAS mapping,
integration/adapter statuses, diagrams, reports, an empty initial review ledger,
and a hash manifest. Generated data and evidence are ignored. Inputs outside the
checkout, unsafe YAML, inconsistent references, symlinked paths, unowned output
runs and unsupported versions fail with exit 2. Success is exit 0; test plans
report NOT_TESTED. Different model digests need different run directories.

## Limits that remain explicit

- The four named taxonomy/crosswalk/career documents were not supplied. Of 37 risk
  number slots, only 23 descriptions explicitly supplied in the prompt are usable.
  The other 14 and full authoritative taxonomy validation are **BLOCKED**.
- ATLAS is a pinned official October 2026 / format 6.1.0 distribution, with 221
  verified parsed IDs. Structural projection is validated; upstream Python schemas
  are not executed. Mappings remain CANDIDATE_REVIEW or UNMAPPED.
- Threat Dragon, pytm and Threagile are **BLOCKED**: absent native versions/schemas.
  No fake native exports or imported Python execution are provided.
- Imported metadata does not establish enforcement. No external requirement IDs,
  compliance results, confirmed controls, real legal authority or learner mastery.
- Full P-001 kind runtime remains blocked by host cgroup delegation. P-005 does not
  require or change it. Optional predecessor runtime services are not deployed.

Start with docs/architecture.md, schema-and-interfaces.md, integration-contracts.md,
security-assumptions.md and limitations.md. Read docs/learner-workbook.md **before**
viewing generated candidates when practicing independent assessment. G1–G4 remain
UNVERIFIED. The delivery report records exact checks, artifacts and remaining work.
