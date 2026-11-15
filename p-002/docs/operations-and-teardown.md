# Operation and teardown

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Use this existing isolated checkout. Do not create a Git worktree unless explicitly
requested. Run commands from `/workspace/p001/p-002`. `scripts/setup` installs the
core lock and editable CLI; `scripts/setup-sdv` adds separately pinned CPU SDV tools.
Python 3.12 is required. Internet is needed only for approved dependencies/images and
explicit advisory lookups, never rules-based generation or its tests.

`make generate` creates `generated/standard`. `make validate` validates hashes,
structural schema, graph, lifecycle and oracle consistency. `make export` verifies the
already materialized portable bundle; generation writes all formats per
file into a new named directory. An interrupted incomplete directory fails closed;
preserve/inspect it and choose another output rather than overwrite it. `p002 scenarios
export` prints the strict catalog. `p002 scenarios show S04` shows its safe design.
`make scenario-seed ID=S04` creates a derived snapshot, `scenarios diff S04` shows its
changes, `scenarios validate S04` checks it, and `make scenario-reset ID=S04` removes
only the hash-verified owned snapshot. Reset is safe twice. Unsafe scenarios require
`--unsafe-scenario` (or `UNSAFE=1` in Make). No scenario invokes a target or grades a
finding; its status becomes SEEDED only.

## Optional services

`./scripts/lab up NAME` starts one pinned disposable service on the internal
`p002-local-internal` network, plus the owned HTTP helper. Names are restricted to
nextcloud, redmine, label-studio and p001. Native data stays in disposable anonymous
volumes/container layers; no host folder or existing database is mounted. Functional
readiness is checked via real HTTP. The helper sends HTTP within the network via
`docker exec -i`; credential-bearing request JSON goes through stdin, never argv.
Requests do not use ambient proxies. Redirects are refused. Host ports are not published.

Run `p002 adapters dry-run --name NAME` before a seed to inspect the export plan;
it does not contact a service. Write commands require `--target lab` independently of
the fixed endpoint policy. `p002 adapters seed --name NAME --target lab` records each
actual native ID in `.runtime/NAME-ownership.json`; repeats read back/reuse only owned
objects or fail on drift/collision. `scripts/integration-test --name NAME` repeats
imports and tests native read/update/denial where supported. `make integration-test`
checks only running labs and exits 2 when some are unavailable; unavailable is never
counted PASS. `make evidence` lists immutable evidence hashes and counts.

`./scripts/lab down NAME --confirm p002-local` removes only correctly labelled named
containers and their anonymous volumes, retires their journal, and removes the helper
and network only when unused. It never prunes globally. Repeat down is safe. `make down`
is the explicit convenience confirmation for all P-002 lab deployments. It preserves
all generated baselines, evidence, retired journals and private bootstrap configuration.
For object-only cleanup, the adapter command requires both `--target lab` and
`--confirm p002-local`. P-001 has no object delete API; deployment teardown is its scope.

Secrets are generated locally into mode-0600 `.runtime/secrets.json` and env files.
Never print them or dump `docker inspect`/logs into public evidence. The local trusted
operator can inspect private logs when troubleshooting; shared reports retain only
allowlisted statuses, IDs, hashes and version strings. Docker resource constraints
are not advertised as enforced on this host: its rootless cgroup driver is `none`.
Use one optional service at a time. Startup requires at least 8 GiB free for cold images or 2 GiB for a cached image; an already-owned running instance is checked for readiness without a new-allocation disk gate.
See actual disk/RSS measurements in validation-status rather than assuming hard limits.

## Known troubleshooting

- P-001 kind: BLOCKED by missing rootless cgroup delegation; do not elevate or bypass.
- Redmine: `SECRET_KEY_BASE` must be available to both the web process and Rails runner;
  supported `redmine:load_default_data` supplies trackers/statuses/priorities. Our local
  bootstrap uses no SMTP and a dedicated P002Analyst role.
- Label Studio: the tested Community legacy-token bootstrap is explicitly enabled;
  runtime version must agree with the pinned image. No Enterprise project RBAC claim.
- SDV: default pip resolution pulls CUDA; use the CPU script. Version 2.2 takes
  dictionary-of-DataFrames for metadata/fit/sample. Do not silently use a 1.x API.
- Nonowned name collisions, unknown files in a snapshot, redirects, off-allowlist URLs
  and drifted owned content fail closed. Preserve local changes; do not adopt them.
- Documentation web hosts were denied by policy. Official GitHub source and actual
  runtime APIs supplied the verified contract; see the source inventory for precision.
