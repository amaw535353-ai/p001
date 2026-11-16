# Runner interfaces and installed compatibility

| Inventory | Tool pin | Execution | Security meaning |
|---|---|---|---|
| #3 | Promptfoo 0.125.1 / Node >=22.22 | CLI eval, fixed local CJS provider | finite synthetic behavior checks |
| #41 | Inspect AI 0.3.290 | actual Task/generate/mockllm/scorer/eval | local empirical evaluation |
| #62 | OWASP ZAP 2.17.0 | Automation Framework, one captured HAR response | passive observations only |
| #145 | Playwright 1.65.2 / Chromium 156.0.8078.79 | real isolated browser contexts | actual owned server/UI behavior |

All adapters share version/capability discovery, preflight, bounded execution,
RunnerResult normalization, sanitized sample/metadata registration and resource
cleanup. Missing tools, wrong pins, scope failure and unsupported capabilities block;
provider errors/timeouts are inconclusive. Exit zero alone cannot pass an oracle.

Core and sibling packages use their verified Pydantic 2.12.5 toolchain. Current
Inspect requires >=2.13, so it runs in `.tools/inspect` with its own hash lock.
Promptfoo's dependency graph is fixed by `tools/package-lock.json`. ZAP's release
archive digest and bundled add-on versions are fixed; no add-on updates occur.

Actual commands and versions are retained per run. Ephemeral raw tool files are
discarded after structured results are captured; original statuses, exit codes,
safe per-sample results, native score summaries and raw-file hashes remain. Exact
external-tool reruns require a fresh run and fresh scope, not replaying expired
temporary paths. Offline reproduce is supported from the recorded snapshots.
