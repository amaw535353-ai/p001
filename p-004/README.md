# P-004 — Automated AI Application Architecture Discovery and Attack Surface Mapping.

**Synthetic laboratory. Offline core implemented; optional integrations partially
verified. No confirmed vulnerabilities, client authorization or learner proficiency
is asserted.** This module lives in `amaw535353-ai/p001/p-004/`, matching the existing
lowercase `p-002/` and `p-003/` convention. The foundation remains at the repository
root. No separate repository or worktree is created.

Python 3.12 CLI `p004` parses bounded local architecture declarations, OpenAPI 3.x,
Kubernetes, Compose, Python route decorators, Dockerfiles, dependency declarations,
env **example names only**, reviewed IaC projections and the actual P-001/002/003
contracts. It builds a tenant-aware graph, correlates explicitly mapped snapshots,
retains conflicting evidence, computes deterministic semantic differences and emits
sanitized JSON/JSONL, CSV, Mermaid, Markdown and SHA-256 evidence manifests.

## Install and validate

From `/workspace/p001/p-004`:

```bash
make install
make doctor
make test
make verify
make demo-offline
make demo-diff
```

Installation downloads hash-locked wheels, then installs offline from `.runtime/wheels`;
editable P-002/P-003 installs use their existing inspected source without dependency
resolution. `P004_OFFLINE=1 make install` needs the populated wheel cache and makes
no package-index request. No Onyx, OpenHands, ZAP, browser binary, Docker, cloud
account, model API or GPU is needed. Commands never change approval state.

`make verify` runs pytest (including guarded loopback tests), lint, format, types,
schema drift, dependency consistency and root `make unit static`. Exact results go
under ignored `evidence/engineering-*/manifest.json` and `pytest.xml`.

`make demo-offline` generates seed 2026 with the **actual P-002 tiny generator**,
validates its typed graph, imports P-001 source and P-003 context, and writes a fresh
owned run under `reports/`. `.runtime/latest-demo.json` records its path. No imported
application permission grant becomes assessment authorization. Run offline with a
Python network-denial hook for an additional reproducibility check:

```bash
PYTHONPATH=tests/no-network .venv/bin/python scripts/demo.py --diff
PYTHONPATH=tests/no-network .venv/bin/python -m pytest tests -m 'not local_network'
```

These are Python socket/DNS denial checks, not an OS-wide container firewall claim.
The CI workflow uses the same commands; remote CI execution is not claimed until run.

## Operator CLI

All paths below use real CLI syntax. Substitute actual fresh run paths; existing
directories/files are never overwritten.

```bash
./scripts/p004 discover-offline --root .. --config p-004/config/offline.example.json --out reports/custom-run
./scripts/p004 inventory --input reports/custom-run --format json
./scripts/p004 graph --input reports/custom-run --format mermaid
./scripts/p004 report --run reports/custom-run --format markdown
./scripts/p004 verify-artifacts --input reports/custom-run
./scripts/p004 diff --before reports/RUN_A --after reports/RUN_B --out reports/new-diff.json
./scripts/p004 correlate --declared reports/RUN_A --observed reports/RUN_B --out reports/correlated
make reset-owned RUN=reports/custom-run
```

`reset-owned` validates every owned hash and **retains evidence by default**. To
explicitly remove only the recorded run files, use `reset-owned --input PATH
--confirm p004-local --delete-evidence`. Unlisted files remain. No service, namespace,
Docker image, store, other checkout or global cache is deleted.

For correlation, an optional `--mapping .runtime/reviewed-map.json` maps observed
asset IDs to declared asset IDs. The mapping is one-to-one and must match tenant,
environment, kind and canonical address. Missing mapping keeps separate identities.
Same labels, DNS aliases and shared IPs do not silently merge identities.

## Explicit local HTTP observation

**Not a browser crawl.** The implemented live transport sends only fixed reviewed
GET/HEAD requests to literal `127.0.0.1`, with an independent ceiling of 30 requests,
30/minute, 120 seconds, depth zero, concurrency one and 64 KB per response. It uses
numeric AF_INET sockets, no DNS/proxy/cookies/bearer credentials, no query strings,
no redirect following and no response-body archival. Ambient global proxy settings
are refused rather than consumed. A GET is not intrinsically side-effect free;
the owned target and each path must be reviewed.

Start the owned deterministic UI/API fixture separately (loopback only):

```bash
.venv/bin/python -m p004.fixture --port 8764 --owned-out .runtime/fixture-owned.json
```

A separate operator must supply a **real P-003 ACTIVE ledger engagement**, immutable
approved version/digest, exact URL assets, synthetic ownership and current review
evidence. See [operations](docs/operations.md). There is no `approve`, `demo approval`
or approval-writing command in P-004. The example context deliberately contains an
invalid digest and unconfirmed prerequisites; it cannot grant access.

```bash
./scripts/p004 observe-local --engagement ENG-ID --version 1 \
  --target http://127.0.0.1:8764/health --profile safe-readonly \
  --store .runtime/OPERATOR-P003-STORE --context .runtime/reviewed-context.json \
  --owned .runtime/fixture-owned.json --max-requests 30 --max-seconds 120 \
  --out reports/local-observation
```

Missing prerequisites produce a hashed **BLOCKED** report and exit 3, with zero
requests. Every allowed operation replays the actual P-003 ledger/review evidence
and invokes `p003.policy.evaluate` immediately before connecting and again before
sending. A mid-run amendment/revocation blocks the next request. A narrow
decision-to-send race remains; no atomic distributed revocation claim is made.
Synthetic training approval never authorizes another person's infrastructure.

## Integration reality

| Component | Implemented / verified boundary |
|---|---|
| P-001 | Actual source/manifests imported. Live Kubernetes BLOCKED by host cgroup delegation and missing reviewed namespace identity. Prior Docker onboarding smoke is separate evidence. |
| P-002 | Actual deterministic generator and typed dataset validator exercised. Oracle grants remain declarations. |
| P-003 | Real read-only ledger replay, review verification and evaluator exercised with explicit disposable simulated approvals and real loopback transport. Not legal/identity verification. |
| Playwright #145 | BLOCKED: independent browser egress sandbox unavailable. Browser entry point refuses; no live request graph claimed. |
| ZAP #62 | Passive-import **P-004 contract** and provisional alert import tested. Not an Automation Framework plan; no installed/version-verified ZAP integration, Safe-mode process or live scan claimed. |
| Onyx #1 / OpenHands #2 | Versioned local architecture-manifest contracts and absence handling tested. No vendor checkout/API deployed or verified; edition/native permission behavior unknown. |

See [known limitations](docs/known-limitations.md), [engineering results](docs/validation-status.md),
[schema/exports](docs/evidence-schema.md), [safety](docs/scope-and-safety.md) and the
[unsolved learner workbook](docs/learner-workbook.md).

## Files

```text
p-004/
  src/p004/       cli, models, safety, parsers, graph, correlation, policy,
                  transport, optional adapters, fixture, reporting
  config/         offline inputs, invalid-by-default live context, passive contract
  fixtures/       synthetic OpenAPI/architecture/vendor/traffic contracts
  schemas/        generated strict JSON Schemas
  scripts/        setup, p004, demo, schema generation, verification
  tests/          parser/property/contract, policy/real transport, CLI/lifecycle
  docs/           design, methods, evidence, operations, limits, workbook, disclosure
  reports/        ignored owned run outputs
  evidence/       ignored actual engineering evidence
```
