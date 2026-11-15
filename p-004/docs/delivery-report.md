# P-004 delivery handover

## 1. Repository and integrations

Repository `amaw535353-ai/p001`, existing isolated `/workspace/p001`; new branch
`feat/p-004-architecture-attack-surface` from clean base
`4b7f14aea75c65f111f16f84ae7908dabca6570c`. Lowercase `p-004/` matches siblings.
No separate repository/worktree/session was created; tools cannot open a new chat.
No commit, push or publication. Changes are the new module and a scoped offline
CI workflow. P001–003 source/infrastructure are unchanged. All three actual source
contracts were inspected and integrated; the four named crosswalk/roadmap files
were unavailable. No missing detailed mapping was invented.

## 2. Functional architecture and actual tree

Bounded non-executing inputs -> strict tenant-aware graph -> explicit correlation /
semantic diff -> JSON/JSONL/CSV/Mermaid/memo and hashed evidence. Optional guarded
HTTP calls the real P003 evaluator through read-only ledger replay before each
operation and actual socket send. This is not a browser crawler or vulnerability
scanner. Per-source evidence claims retain measured scope/status and disagreements.

```text
.github/workflows/p004-offline.yml
p-004/
  AGENTS.md README.md Makefile pyproject.toml requirements.in requirements.lock
  .gitignore .env.example
  config/{offline.example,local-observation.example,zap-passive-import}.json
  src/p004/{__init__,cli,models,safety,parsers,graph,correlation,policy,
            transport,optional,fixture,reporting}.py
  schemas/{architecture,input,discovery-policy,owned-target,snapshot,
           assets,endpoints,identities,flows,trust_boundaries,coverage}.schema.json
  scripts/{setup,p004,demo.py,build-schemas.py,verify.py,dependency-inventory.py}
  fixtures/static/{architecture,openapi,onyx.contract,openhands.contract,traffic.sanitized}.json
  fixtures/{local-web-app,unsafe-test-inputs}/README.md
  tests/{conftest,test_static,test_policy_transport,test_cli_lifecycle,test_additional_contracts}.py
  tests/no-network/sitecustomize.py
  docs/   design, operations, methodology, schemas, safety, adapter/source mapping,
          verification matrix/results, dependency inventory, workbook, disclosure
  reports/.gitkeep evidence/.gitkeep
```

Runtime reports/evidence/wheels/venv/state are ignored. The README and individual
docs contain operator details; no nonfunctional browser/ZAP command is advertised.

## 3. Commands

From `/workspace/p001/p-004`, run `make install`, `make doctor`, `make verify`,
`make demo-offline` or `make demo-diff`. Repeat cached setup with
`P004_OFFLINE=1 make install`. `.runtime/latest-demo.json` identifies fresh outputs.

```bash
./scripts/p004 inventory --input reports/demo-1794745109021761928-A --format json
./scripts/p004 graph --input reports/demo-1794745109021761928-A --format mermaid
./scripts/p004 report --run reports/demo-1794745109021761928-A --format markdown
./scripts/p004 verify-artifacts --input reports/demo-1794745109021761928-A
make reset-owned RUN=reports/demo-1794745109021761928-A
```

For a new safe diff, use `diff --before PATH --after PATH --out NEW.json`.
For cross-run correlation, use `correlate --declared PATH --observed PATH
--out NEW_DIRECTORY [--mapping REVIEWED.json]`. These commands emit no traffic.
Reset retains evidence unless explicit `--delete-evidence --confirm p004-local`
is supplied; it checks all hashes before removing only recorded files.

Local observation syntax is implemented: `observe-local --engagement ID --version N
--target http://127.0.0.1:PORT/SAFE_PATH --profile safe-readonly --store OWNED_P003_STORE
--context REVIEWED_CONTEXT.json --owned FIXTURE_OWNERSHIP.json --max-requests 30
--max-seconds 120 --out NEW_DIRECTORY`. Missing prerequisites produce a BLOCKED
report and exit 3. See operations.md for the independent P003 review prerequisites
and `python -m p004.fixture` startup. P004 has no approval-writing command.

## 4. Tool status

P001 static-only; P002 actual generator/validator exercised; P003 real evaluator
and synthetic ledger lifecycle exercised with real local HTTP; Playwright BLOCKED;
ZAP fixture/contract-only, live NOT TESTED; Onyx/OpenHands contract-only, vendor
interfaces NOT TESTED; Kubernetes live BLOCKED. A standalone browser/cluster adapter
must still be implemented and verified before enabling it.

## 5. Tests and evidence

`make verify`: **128 PASS, 0 FAIL, 0 ERROR, 3 SKIPPED**; seven command groups all
exit 0. Includes ruff format/lint, mypy, schema checks, pip check and root
`make unit static` (7 foundation tests). The network-disabled offline-only run:
**118 PASS, 3 SKIPPED, 10 DESELECTED**, exit 0. The 10 loopback tests run in the
full suite; do not sum repeated runs as extra coverage. Deliberate CLI refusal
and partial cases return 3 and 2 respectively and are asserted in tests.

Engineering evidence is `evidence/engineering-1794745220729844686/{manifest.json,
pytest.xml,local-http-run/}`; operator commands and 14-file artifact verification
are in `evidence/delivery-summary.json`. Remote CI itself is NOT TESTED.

## 6. Observed outputs

Offline demo produced **157 assets, 13 endpoints, 52 flows, 49 candidate crossings**.
Examples: declared P001 tenant-a/tenant-b APIs, `/readyz` GET, `/infer` POST,
`/objects/{key}` GET/PUT, mock simulator, workload identities, namespaces/cluster,
emulator storage and telemetry. Those are source declarations, not runtime reachability
or control assertions. The successful real local HTTP report contains an OBSERVED
GET `/health`, its response status and P003 decision reference. Bodies/cookies were
discarded. Offline Mermaid/memo are under `reports/demo-1794745109021761928-A/`;
controlled delta is `reports/release-diff.json`, mixed correlation under
`reports/correlated-release/`. No unknown attack-surface denominator is invented.

## 7. Actual authorization guarantees

Real fresh P003 version/digest/review/state/context/target/method/window/budget
checks plus a narrower exact numeric loopback transport ceiling. No hostname/DNS,
redirect following, ambient proxy, browser/background request, mutation, cookie,
arbitrary credential header or approval mock can enable traffic. Tests exercise
the actual socket boundary and mid-run revoke/amendment. The inevitable decision-to-
send race and per-process counters remain limitations. Synthetic local review is
neither legal permission nor enterprise actor authentication or target enforcement.

## 8. Limits and versions

See known-limitations.md and validation-status.md. Python 3.12.14, p004 1.0.0,
Pydantic 2.12.5, PyYAML 6.0.3 and jsonschema 4.26.0 were used. Browser/ZAP/vendor/
cluster live gates, cross-process quotas, atomic revocation, unknown dynamic
architecture and independent publication review remain unresolved. P002 tenant IDs
and P001 namespace IDs deliberately remain distinct; no identity equivalence is
inferred merely from a similar name. Later P005/P007/P009/P010 and enterprise
assessments receive export contracts only, not completed implementations.

## 9. Learner work

The unsolved learner-workbook.md asks for independent reconstruction, user versus
workload identity analysis, five candidate crossings, endpoint/contract comparison,
an extra authorized inspection, unfamiliar architecture analysis, consultancy memo
and independent scanner-alert review. **G1–G4: NOT DEMONSTRATED**. AI assistance
does not satisfy an independent gate; a qualified human reviewer is required.

## 10. Publication

Review dependency-inventory.json and actual LICENSE files; runtime dependencies
are MIT, Hypothesis MPL-2.0 and regex has Apache-2.0 AND CNRI-Python terms. Do not
assume a license for the repository. Attribute reused P001–003 interfaces and
AI assistance. Inspect data minimization/redaction and ensure ignored reports,
private stores, raw captures and credentials are absent from Git. Preserve honest
optional statuses and candidate-only claims. Publication and remote push require
separate explicit human action; neither was performed.
