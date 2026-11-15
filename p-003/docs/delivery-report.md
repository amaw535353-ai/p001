# P-003 delivery report

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

## Delivery identity and working software

Repository: amaw535353-ai/p001. Branch: feat/p-003-engagement-scoping-roe.
Module: /workspace/p001/p-003. Base commit:
657b6e46e131e2b1641d66c2c038b20bef349942. The delivery is a local P-003-only commit;
`git log -1 --format='%H %s'` identifies it. No push, PR, publication or real cloud
deployment occurred. P-001/P-002 tracked files and infrastructure remain unchanged.

The CLI and typed package implement synthetic intake/scope/ROE, four-role labels,
explicit simulated review and activation, version/digest-bound approval, conservative
amendments, immediate stop overrides, pure offline preflight decisions, hash-linked
SQLite audit, JSON/YAML validation, Markdown/policy/evidence exports, AISVS registry,
truthfully partial OSCAL mapping, read-only foundation imports and guarded Redmine
tracking. State, evidence and generated files are private/ignored; no service is
needed for the prepared offline workflow.

```text
p-003/
  AGENTS.md, README.md, Makefile, pyproject.toml, requirements.in, requirements.lock
  src/p003/
    models.py, targets.py, policy.py, store.py, cli.py, demo.py, util.py
    exports.py, frameworks.py, adapters.py, redmine.py, verification.py
    data/aisvs/   # unchanged official Chapter 5 + CC-BY-SA license
    data/oscal/   # unchanged official AP schema + NIST notice
    data/sources.json
  schemas/       # strict domain, request, policy and evidence contracts
  examples/      # 2 clients, JSON/YAML drafts, executed training policy, review and amendment
  templates/     # 12 editable fictional consultancy deliverables, digest/provenance headers
  tests/         # unit, CLI, workflow, negative, property and adapter contract coverage
  scripts/       # setup, CLI wrapper, verification, demo, contracts, fresh wheel reconstruction
  docs/          # architecture, policy, state machine, sources, threat model, evidence, workbook
  evidence/      # actual uniquely named run manifests and current JUnit; ignored
  generated/     # actual planning exports; ignored
```

## Exact workflow commands

Run `cd /workspace/p001/p-003; ./scripts/setup`. The README contains the full exact
submit/approve/activate commands with fixed UTC demo timestamps and digest lookup.
Use `.venv/bin/python scripts/demo-workflow.py` for a recorded separate-action
training demonstration. Core command entrypoints:

```bash
./scripts/p003 demo init --seed 42
./scripts/p003 engagement validate --file examples/engagement-draft-a.yaml
./scripts/p003 scope evaluate --request examples/check-allow.json
./scripts/p003 export markdown --id ENG-DEMO-A --actor demo-a-assessor --output generated/brief.md
./scripts/p003 export policy --id ENG-DEMO-A --actor demo-a-assessor --output generated/engagement-policy.json
./scripts/p003 export oscal --id ENG-DEMO-A --actor demo-a-assessor --output generated/assessment-plan.mapping-draft.json
./scripts/p003 evidence manifest --id ENG-DEMO-A --actor demo-a-reviewer
./scripts/p003 redmine sync --target lab --id ENG-DEMO-A --actor demo-a-reviewer --dry-run
./scripts/p003 reset --confirm p003-local
./scripts/verify.sh
.venv/bin/python scripts/clean-reconstruction.py --offline
```

Evaluate intentionally DENIES until the separate explicit review/activation steps
have completed. Commands refuse repeated initialization or overwrite; choose a fresh
store/output or archive owned state. Redmine write is disabled by default; exact
ownership-init and --write confirmation commands are in README and
redmine-integration.md. No destructive external cleanup capability exists.

## Actual results and governance claims

Final tests: 163 P-003 passed / 0 failed / 0 skipped, plus 7 foundation tests and
structural checks. All six verifier command groups passed; all 23 demo steps and
17 clean wheel/install checks passed. See engineering-test-results.md for commands,
versions, full hashes and evidence paths. Positive outcomes are mechanical training
observations, not live enterprise security findings.

| Governance topic | Technically enforced | Model/human claim or NOT VERIFIED |
|---|---|---|
| Approval/scope/change | Exact version, digest, targets, activities, review bytes; fresh review per amendment | Authentic client authority and signatures NOT VERIFIED |
| Role/tenant separation | Four distinct labels, client filters, no self-approval label | Human identity/multiuser authentication NOT VERIFIED |
| Target/scope | Local-only syntax, exact paths/ports/methods, exclusion and forbidden-class precedence | Ownership, DNS/rebinding, upstream terms NOT VERIFIED |
| Time/contact/budgets | UTC boundaries, current stop state, supplied prerequisites and counter ceilings | Trusted clock, reachable person and usage telemetry NOT VERIFIED |
| Evidence/audit | Digests, private state, append-only triggers, serialized replay/checks, sanitized decisions | Malicious store owner and independent custody NOT VERIFIED |
| Runner/export | Point-in-time decision and explicit stale-export warning | Actual scanner compliance/target enforcement NOT VERIFIED |

## Framework and foundation outcomes

AISVS: official v1.01 commit 3ae3af45c363467b8ad823ef79219236e67ca22f. Exact selected
references v1.01-C5.2.1, v1.01-C5.2.5 and v1.01-C5.3.1, all Level 2 and PLANNED.
Source text/levels and CC-BY-SA-4.0 attribution are preserved. No target compliance
assessment was performed.

OSCAL: official 1.2.3 AP schema pinned and checksummed. Output mode is
oscal-mapping-draft, NOT VALID OSCAL. Actual rejection and a machine-readable missing
SSP/catalog/semantic-field matrix are exported. Full AP conformance is not implemented.

Redmine: official 6.1.0 source REST routes inspected; wiki proxy access returned 403.
Owned-project/issue reconciliation and abuse guards pass stub tests. Live version,
edition, permissions, notification configuration and API behavior are NOT TESTED:
no service was present. Issue statuses never become P-003 approval.

P-001: real source inventory adapter verified; runtime NOT TESTED by P-003, no
redeployment. P-002: real existing synthetic standard graph and manifest imported
through its own validator; application-permission oracle excluded, actors unassigned,
assets proposed only. Both integrations are optional; standalone core passes without
live services. Sibling absence is an explicit operation error/optional test skip,
never an invented connection or implicit approval.

## Limitations, deviations and next steps

The requested new feature branch was created in the existing task; tools cannot
open a separate chat/session. Lowercase p-003/ matches the repository convention.
Named career/crosswalk/reference master-prompt files were absent, so detailed risk
mappings were not fabricated. No real/non-local assessment mode or high-impact
exception path is supplied. All edits, including scope reduction, require reapproval;
stopped engagements cannot automatically resume. Retention/deletion/notification
instructions are human procedures, not background enforcement.

A fully conformant OSCAL exporter needs a validated synthetic SSP/catalog and
semantic mapping. Optional live Redmine verification needs an independently enabled,
owned instance and privately supplied suitable token/notification settings. Production
use would additionally need authentic client/legal review, authenticated identities,
trusted clocks/telemetry, independently protected auditing and actual runner controls.
Those are limitations/backlog, not permission to implement future projects or access
real targets now. No claims of fresh cloud-task snapshot restoration or publication
are made by a local wheel reconstruction.

## Independent learner work

Use learner-workbook.md: draw trust boundaries, independently reproduce decisions
with unfamiliar fixtures, review amendments/revocation/approval discrepancies, identify
human verification gaps, draft/defend fictional ROE, and obtain an independent human
challenge when possible. Evidence tables remain blank; no answer key is supplied.
G1, G2, G3 and G4 are all NOT DEMONSTRATED.
