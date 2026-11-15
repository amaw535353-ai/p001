# P-003 — AI Security Engagement Scoping, Authorization, and Rules-of-Engagement Toolkit

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

An offline Python 3.12 toolkit for fictional consultancy intake, scope, ROE,
version-bound simulated approvals, stop-work decisions, planning exports and audit
records. `p-003/` is isolated alongside `p-002/` in `amaw535353-ai/p001`. P-001/P-002
source and infrastructure are unchanged. This task uses the existing isolated
checkout and feature branch; it cannot open another Codex chat on the user's behalf.

The engine never contacts a target or runs a scanner. An `ALLOW` is a point-in-time
local governance decision. Recorded approval, mechanically valid scope, actual legal
authority and target-side enforcement are different claims. Only the first two are
demonstrated with synthetic fixtures. Actor labels are caller assertions; this is
not a multiuser authentication service, legal advice or an e-signature service.

## Install and validate

Supported reproducible lock: Linux x86_64, Python 3.12 (tested 3.12.14). The lock
contains exact versions and SHA-256 hashes for binary wheels. Installation requires
PyPI/files.pythonhosted.org; offline execution needs no account, LLM, AWS or server.

```bash
cd /workspace/p001/p-003
./scripts/setup
./scripts/verify.sh
```

Verification executes the P-003 tests, lint, format check, type check, dependency
consistency and root `make unit static`. Evidence is written under ignored
`evidence/engineering-*/manifest.json`, with current JUnit results, real exit codes,
tool versions, fixture hashes and a code manifest. See
[engineering results](docs/engineering-test-results.md) for the actual latest run.

## Explicit fictional workflow

Initialization creates drafts and conspicuously simulated review *fixtures*, never
approvals. It refuses existing engagements. Use a fresh `--store` or archive the
owned store with `reset` first. Demo clocks are fixed UTC, not the machine clock.

```bash
./scripts/p003 demo init --seed 42
./scripts/p003 engagement list --actor demo-a-assessor
./scripts/p003 engagement show --id ENG-DEMO-A --actor demo-a-assessor
./scripts/p003 engagement validate --file examples/engagement-draft-a.yaml
./scripts/p003 engagement submit --id ENG-DEMO-A --actor demo-a-requestor --version 1 \
  --at 2026-11-15T08:10:00Z --reason 'Fictional review request'
policy_digest=$(./scripts/p003 engagement show --id ENG-DEMO-A --actor demo-a-reviewer \
  | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["result"]["engagement"]["content_digest"])')
./scripts/p003 engagement approve --id ENG-DEMO-A --actor demo-a-reviewer --version 1 \
  --scope-digest "$policy_digest" --simulate-review --evidence-ref training-review-a-v1 \
  --at 2026-11-15T08:20:00Z --reason 'Explicit simulated training review only'
./scripts/p003 engagement activate --id ENG-DEMO-A --actor demo-a-owner --version 1 \
  --at 2026-11-15T09:00:00Z --reason 'Fictional prerequisites met'
./scripts/p003 scope evaluate --request examples/check-allow.json
./scripts/p003 scope evaluate --request examples/check-deny-unknown-path.json # exit 3
./scripts/p003 export markdown --id ENG-DEMO-A --actor demo-a-assessor --output generated/brief.md
./scripts/p003 export policy --id ENG-DEMO-A --actor demo-a-assessor --output generated/engagement-policy.json
./scripts/p003 export oscal --id ENG-DEMO-A --actor demo-a-assessor --output generated/assessment-plan.mapping-draft.json
./scripts/p003 evidence manifest --id ENG-DEMO-A --actor demo-a-reviewer
```

`scope evaluate` requires explicit budgets and context in a bounded JSON/YAML
request. `--id`, `--actor`, `--target`, `--test-class`, `--at` can override that request.
There are no silently populated authorization prerequisites. Exit codes: 0 success,
2 invalid/unavailable operation, 3 governance denial. `--help` works for each command.

```bash
./scripts/p003 scope diff --old examples/engagement-draft-a.json --new examples/scope-extension-v2.json
./scripts/p003 engagement amend --id ENG-DEMO-A --actor demo-a-requestor --version 1 \
  --file examples/scope-extension-v2.json --reason 'Request additional metadata path'
./scripts/p003 scope evaluate --request examples/check-allow.json # DENY: fresh approval required
./scripts/p003 engagement suspend --id ENG-DEMO-A --actor demo-a-owner --version 2 \
  --reason 'Fictional emergency stop'
./scripts/p003 reset --confirm p003-local # archive only this owned store; never delete unrelated files
```

After decisions enter the ledger, use current/default event timestamps for later
transitions; backdating is refused. Historical request clocks never bypass current
stops. An amendment is a complete new sealed engagement, linked to the old digest.
No digest auto-fix occurs on input. For newly drafted training records, use the
typed `sealed` API and a separately reviewed `ReviewEvidence`, then run `engagement
create --file`. All domain artifacts require semantic validation as well as JSON
Schema validation; see [model](docs/scope-and-authorization-model.md).

For the complete scripted demonstration (separate explicit simulated approval
commands, positive/negative decisions, exports, pending amendment, stop, archive
and reconstruction):

```bash
.venv/bin/python scripts/demo-workflow.py
./scripts/p003 test --offline
.venv/bin/python scripts/clean-reconstruction.py
```

The reconstruction script builds the wheel and tests a fresh installation outside
the checkout. It first downloads hash-verified dependency wheels. Once
`.runtime/wheels` is populated, `--offline` verifies the same workflow without an
index or service connection; that offline reconstruction was actually executed.

## Frameworks and integrations

- **AISVS #126:** v1.01, official pinned commit; unaltered Chapter 5 requirement
  rows and levels. Selected references: `v1.01-C5.2.1`, `v1.01-C5.2.5`,
  `v1.01-C5.3.1`. They remain **planned**, not assessed or compliant. Attribution
  and CC-BY-SA-4.0 terms: [framework documentation](docs/aisvs-version-and-attribution.md).
- **OSCAL #128:** pinned official AP schema 1.2.3. Export is an
  **`oscal-mapping-draft`, NOT VALID OSCAL**, with missing SSP/catalog mapping and
  observed official-schema rejection. No assessment-results/POA&M/FedRAMP/ATO claim.
- **P-001:** `./scripts/p003 import p001` reads the actual versioned declarative
  inventory; runtime endpoints remain **NOT TESTED** by this module.
- **P-002:** `./scripts/p003 import p002` uses the actual sibling validator and
  provenance checks. Imported actors are unassigned; assets are proposals; its
  application permission oracle never becomes assessment authorization.
- **Redmine #142:** default dry-run has zero network requests. Live writes need
  explicit opt-in and an ownership manifest. Live integration is **NOT TESTED**;
  no local instance was present. No deletion or approval import exists.

```bash
./scripts/p003 redmine sync --target lab --id ENG-DEMO-A --actor demo-a-reviewer --dry-run
# Only against an independently enabled, owned local instance with private token:
./scripts/p003 redmine ownership-init --target lab --confirm p003-local
./scripts/p003 redmine sync --target lab --id ENG-DEMO-A --actor demo-a-reviewer --write --confirm p003-local
```

Source files are under `src/p003/`; schemas under `schemas/`; deterministic
synthetic JSON/YAML under `examples/`; editable consultancy forms under
`templates/`; actual private run artifacts under ignored `generated/` and
`evidence/`. Start with [architecture](docs/architecture.md),
[precedence](docs/policy-and-precedence.md), [limitations](docs/authorization-limitations.md),
and the [human-only workbook](docs/learner-workbook.md).
