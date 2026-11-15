# Inspected P-001 interoperability

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Inspected `../services/common/app.py`, P-001 evidence schema, IaC storage conventions,
container smoke test and documented trust boundaries. Its API accepts only
`PUT /objects/fixture-[a-z0-9-]{1,40}` with `{"marker":"P001-SYNTHETIC-ONLY"}`;
`GET` reads the marker. A tenant-specific public synthetic bearer fixture is compared
in the application; the workload derives bucket `p001-tenant-a` or `p001-tenant-b`.
There is no generic document upload, user provisioning, OIDC, SSO or delete API.
P-002 exports metadata rather than pretending that interface accepts full documents.

The P-002 adapter creates a unique `fixture-p002-<dataset-hash-prefix>` object only
in a P-002-owned disposable deployment of the existing image. It makes no change to
P-001 source, IaC, RBAC or IAM. The emulator endpoint remains the exact hardcoded
local service alias expected by P-001. Marker round-trip and wrong-tenant token checks
are distinct from Kubernetes, IAM, real tenant impersonation or document ACL tests.

```bash
# If missing, build the existing P-001 image using its documented installer/build.
cd /workspace/p001
./scripts/install
docker build -f services/lab-api/Dockerfile -t p001-workload:local .
cd p-002
./scripts/lab up p001
./scripts/p002 adapters seed --name p001 --target lab
./scripts/p002 adapters verify --name p001 --target lab
./scripts/lab down p001 --confirm p002-local
```

The direct HTTP transport is fixed to `127.0.0.1:8081`, but the exercised Docker
transport reaches only the labelled P-002-owned API. Never point this adapter at an
existing user-managed P-001 lab and infer ownership. Contract tests import the actual
P-001 source when present; they are skipped honestly in a standalone checkout without
that source. Live status appears only in the execution evidence, never from this guide.
