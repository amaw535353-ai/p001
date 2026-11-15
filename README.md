# P-001 — Reproducible Cloud-Native AI Security Laboratory and Infrastructure-as-Code Platform

**Synthetic lab / not a real client engagement / no independently verified findings yet.**
**INCOMPLETE / PARTIALLY VERIFIED:** cloud host runs Docker containers, but kind is
blocked by missing rootless cgroup delegation. Kubernetes controls and full lifecycle
remain unverified. See [validation](docs/validation-status.md).

## Supported-host matrix

| Host | Installer | Actually verified | Full kind lab |
|---|---|---|---|
| This Debian 13.6 x86_64 cloud host | Supported | Tools, IaC validation, unit/HTTP and Docker smoke | BLOCKED: rootless cgroup delegation |
| Linux x86_64 with kind-compatible Docker | Target | Not tested on another host | Pending reproduction |
| Ubuntu 24.04 GitHub runner | CI target | Workflow not executed | Manual gated job only |
| macOS Docker Desktop | Not supported by pinned binary installer | NOT TESTED | Requires reviewed host-specific tool pins |
| Windows WSL2 x86_64 | Linux installer target | NOT TESTED | Requires compatible Docker/cgroup setup |
| Native Windows / ARM | Unsupported | NOT TESTED | No compatibility claim |

## Quick start

Supported installer target: **Linux x86_64**, Python 3.12+, curl, Make, working Docker.
Full deployment requires a kind-compatible Docker host with cgroup v2 and delegation
for rootless Docker. Budget **4 CPUs, 8 GiB RAM and 20 GiB free disk** (estimates).
This cloud machine has ample reported RAM/disk but fails kind's delegation check.
macOS Docker Desktop and Windows WSL2 Linux x86_64 are prospective hosts, **not tested**;
native Windows, ARM and GPU workflows are unsupported by this pinned installer.

```bash
cd /workspace/p001                 # use your checkout path elsewhere
./scripts/install                 # verified binaries, hash-locked wheels, signed providers
make doctor
make lab-up                       # local only; plan, apply, readiness and baseline
make lab-test
make lab-evidence                 # sanitized manifest + transcript under evidence/<UTC>/
make lab-down                     # only the owned p001 cluster/state; rerunnable
make lab-rebuild-verify            # destroy twice, rebuild, retest, capture evidence
```

No paid services, AWS account, model API or GPU are required. Default commands never
call real AWS. `make aws-plan` intentionally refuses until a separate authorized,
reviewed account-specific configuration exists.

When deployed: tenant-a API `127.0.0.1:8081`, tenant-b `127.0.0.1:8082`, emulator
`127.0.0.1:4566`. They are loopback port-forwards, not public previews.
`GET /readyz` returns a simulator health response. Example synthetic request:

```bash
curl --fail http://127.0.0.1:8081/infer -H 'Authorization: Bearer p001-fixture-tenant-a' \
  -H 'Content-Type: application/json' -d '{"prompt":"P001 synthetic"}'
```

Expect `simulator:true`, `model:p001-deterministic-v1`, and a stable digest. Tenant-b's
fixture on tenant-a must yield 403. Fixtures are public test identities, **not secrets**.

Container-only fallback (does not validate Kubernetes): after install,
`docker build -f services/lab-api/Dockerfile -t p001-workload:local .`, then
`python3 tests/integration/container-smoke.py`. It uses docker exec for HTTP probes within internal-only networks (this rootless
daemon suppresses internal-network port publishing). It creates and removes only its named,
labelled containers/internal networks; existing name collisions fail closed.

Troubleshooting: [operations](docs/operations-and-troubleshooting.md),
[architecture](docs/architecture.md), [limitations](docs/aws-parity-and-limitations.md),
[assessment brief](docs/assessment-brief.md), [workbook](docs/learner-workbook.md).
The root is the requested project directory; no redundant nested checkout is created.

Engineering review: [inventories](docs/inventories.md),
[traceability matrix](docs/traceability-matrix.md), [command evidence](docs/reproducible-command-transcript.md),
[extension contract](docs/extension-contract.md), [AI/license disclosure](docs/publication-and-ai-disclosure.md).
