# P-002 — Synthetic Enterprise Data, Users, Assets, and Attack Scenario Generator

**SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT**

An offline Python library and CLI generate a versioned enterprise graph, intended
policy oracle, portable exports and twelve reversible scenario snapshots. Optional
adapters import representative subsets into independently enabled local Nextcloud,
Redmine, Label Studio and the inspected P-001 marker API. The generator never calls
an LLM, sends invitations, makes payments or accesses real AWS.

See [actual validation](docs/validation-status.md) before making a readiness claim.
Generated ALLOW/DENY values are **generated oracle** results, never evidence of
native platform enforcement. Human assessment is **NOT DEMONSTRATED**.

From this directory, on Linux x86_64 / Python 3.12:

```bash
./scripts/setup
make doctor
make generate
make validate
make test
make lint typecheck
make scenario-list
make scenario-seed ID=S04
./scripts/p002 scenarios diff S04
make scenario-reset ID=S04
make export
make evidence
```

The installed entrypoint also supports `p002 generate --seed 2026 --profile standard
--mode fixtures`. `scripts/p002` works before an editable install and consistently
uses this component's venv. The core needs neither Docker nor SDV nor internet after
installation. To generate another seed, choose another output, e.g.
`./scripts/p002 generate --seed 17 --output generated/seed17`. An existing baseline
is immutable: mismatching contents or hashes fail rather than overwrite it.

```bash
# Explicitly opt in to an inconsistent derived fixture; never execute its text.
./scripts/p002 scenarios seed S08 --unsafe-scenario
./scripts/p002 scenarios validate S08
./scripts/p002 scenarios reset S08
# Stress generation is bounded and requires a separate opt-in.
./scripts/p002 generate --profile stress-local --allow-stress --output generated/stress
# Optional CPU SDV, separate lock and deliberately weaker reproducibility claim.
./scripts/setup-sdv
./scripts/p002 generate --mode sdv --profile tiny --output generated/sdv-run1
```

Optional labs run **one at a time**, on an internal-only Docker network. The CLI
uses an owned helper to make real HTTP requests inside that network; this works
around the observed rootless daemon's lack of internal-network port publishing.
There are no public host ports, production URL options, proxy credentials in
exports or remotely accessible previews. Direct `--transport http` uses only fixed
loopback ports, for a separately authorized lab providing that binding.

```bash
./scripts/lab up nextcloud
./scripts/p002 adapters dry-run --name nextcloud
./scripts/p002 adapters seed --name nextcloud --target lab
./scripts/p002 adapters verify --name nextcloud --target lab
./scripts/integration-test --name nextcloud  # repeat-import + readback
./scripts/lab down nextcloud --confirm p002-local
# Substitute redmine, label-studio, or p001. P-001 needs its existing workload image.
make integration-test  # only running owned labs; absent labs count BLOCKED, exit 2
make down              # explicitly confirms deletion of P-002-owned lab deployments
```

API cleanup is also available with `p002 adapters cleanup --name NAME --target lab
--confirm p002-local`. It deletes only journaled objects; P-001 has no delete API,
so remove its entire P-002-owned disposable deployment instead. Generated baselines
and private evidence survive `make down`. No global Docker cleanup is performed.

The root is a P-001 repository, so the component path is deliberately `p-002/`.
P-001 source and infrastructure are unchanged. The four career/taxonomy attachments
named in the request were unavailable; risk numbers are carried from that request,
with no invented formal names, crosswalk claims or AISVS/ASVS mappings.

Read [architecture](docs/architecture.md), [data model](docs/data-model-and-dictionary.md),
[API/edition notes](docs/nextcloud-redmine-labelstudio-apis.md),
[operations](docs/operations-and-teardown.md) and the
[learner workbook](docs/learner-workbook.md). All names, domains, amounts, canaries
and records are fictitious. Coincidental resemblance does not establish anonymity.
