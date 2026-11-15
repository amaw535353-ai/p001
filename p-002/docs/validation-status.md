# Actual validation status

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

**CORE VERIFIED, INTEGRATIONS PARTIAL.** Executed 2026-11-15 UTC on Linux x86_64,
Python 3.12.14, Docker 29.9.2 rootless; 5 CPUs / 33 GiB reported RAM. No cgroup memory
enforcement is claimed. P-001 tracked source remains unchanged. New P-002 files are
local and uncommitted. No push, publication or fresh-task restoration was performed.

| Capability | Actual result | Evidence |
|---|---|---|
| Full core + optional CPU SDV | PASS: 81 tests; 1 metadata-save recommendation warning | `evidence/core-tests-1794735999021499934.json` |
| Fresh core-only venv, no SDV | PASS: 80; optional SDV explicitly NOT TESTED/skipped: 1 | `evidence/core-tests-1794736027059543894.json` |
| Formatting/lint/typing | PASS: Ruff and mypy, 17 source files | `evidence/engineering-checks-1794736099024840735.json` |
| Determinism | PASS: all 186 exported/ownership files identical in two output directories | repeatability run in evidence |
| Nextcloud 34.0.6 | PASS: 24 requests (18 allow, 6 deny), after restart too; 12 native file IDs/modified times/hashes; import repeated | `evidence/integration-nextcloud-1794735625665965675.json` |
| Redmine 6.1.6 | PASS: 36 requests (24 allow/update, 12 deny), import repeated | `evidence/integrations-1794734967183867740.json` |
| Label Studio 1.23.0 | PASS: 6 task/annotation round trips, import repeated; NOT tenant RBAC | `evidence/integrations-1794735146618409094.json` |
| P-001 marker API | PASS: 1 readback + 1 wrong-tenant-token denial; import repeated | `evidence/integrations-1794735324696606480.json` |
| Python release advisory scan | PASS: 61 checks after updating pytest/setuptools; previous 2 package failures retained | audit runs in evidence |
| Secret scan | PASS: narrow publishable-source patterns only | latest audit run |
| Full native policy parity / container OS audit | NOT TESTED | limitations run |
| P-001 Kubernetes | BLOCKED: no delegated rootless cgroup driver | P-001 doctor and limitations |
| Current optional service availability | BLOCKED/off after deliberate teardown: 4; expected exit 2 | latest integrations run |
| Human G1–G4 | NOT DEMONSTRATED; outside builder verification | learner workbook |

Default corpus: 2 tenants, 6 departments, 36 humans, 6 workloads, 6 groups, 60 documents,
12 issues, 60 tasks/annotations, 22 grants, 6 delegations, 2 requests/approvals,
42 business events, 48 lifecycle events and 12 scenarios. Oracle: 38 ALLOW / 62 DENY
out of 100 generated cases. These are not native security test counts.

Seed `2026`; logical time `2026-01-15T12:00:00Z`; schema `1.0`; generator `1.0.0`.
Dataset SHA-256: `1aaa0c5e65c59a33e1f2771500b7080f3b1331a79be2f1e6b2ab2f146300adf4`.
Content-root SHA-256: `fea5c5d2efc65103267156fc91fda12520985b328ded5088ab7921ef1c77edf1`.
Source/config SHA-256: `90a6e58901f010ce7606c4fda3fde6a8812db512e75f95a7e0d830a66a4f50af`.
The complete root/hash map is `generated/standard/reproducibility.json`.

| Measured generator | Elapsed seconds | Peak RSS KiB | Output bytes |
|---|---:|---:|---:|
| standard | 0.1803 | 47144 | 1575050 |
| stress-local | 0.7294 | 65976 | 6477799 |

These are local measurements, not universal resource guarantees. Cold-image startup
requires 8 GiB free; cached-image new deployments require 2 GiB. Run services
sequentially. Existing owned running labs use functional readiness without allocation
gating. No public ports are bound. All P-002 containers/networks were removed and
teardown was rerun safely. Generated data, evidence and excluded private bootstrap
configuration remain available.

Both setup scripts were executed and repeated. Actual user-facing CLI commands
executed include `make generate`, `make validate`, `make export`, `make doctor`,
`make scenario-list`, `make scenario-seed ID=S04`, `scenarios diff/validate S04`,
`make scenario-reset ID=S04` twice, unsafe S08 seed/reset, `make test lint typecheck`,
SDV generation/validation, stress-local opt-in generation/validation, per-adapter
lab up, seed/verify, repeated import tests, scoped Nextcloud cleanup twice, and
`make down` twice. `make integration-test` after teardown deliberately reports 4
BLOCKED availability checks with exit 2; it is not described as a passing integration.
P-001 `make unit static` also passed (7 tests plus structural checks).

Initial Redmine bootstrap, SDV API and helper disk/alias problems were diagnosed and
corrected. Earlier failed pytest/advisory runs remain in evidence. The final results
above describe the corrected implementation, not a claim that every historical
attempt passed. The first performance command lacked `/usr/bin/time`; the reported
measurements instead use Python perf_counter/getrusage on actual generation children.

Native object-only cleanup was exercised for Nextcloud; Redmine/Label Studio use
tested whole-owned-deployment teardown, with their object-only API cleanup paths
not separately exercised. Complete canonical ACL inheritance/deny/time/delegation/
approval equivalence, Label Studio Enterprise access isolation, real SSO, GPU modes,
RAG synchronization, container OS advisory coverage and hosted CI remain unverified
or excluded. The nested CI template is not automatically discovered by the parent
repository's GitHub workflow runner. No formal risk/framework mapping is invented.

`evidence/handover-report.json` is the sanitized machine-readable report and joined
traceability view. Evidence is excluded from Git. Publication requires an independent
review of source/licenses and excluded files. Reusable `install_script` and
`start_skill` were saved in the environment draft, preserving P-001 instructions.
Review/save the draft in environment settings and publish only when desired; saving
a draft neither publishes this code nor proves restoration into a fresh task.
