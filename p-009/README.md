# P-009 — Security Evidence Collection, Telemetry, and Reproducibility Platform

Synthetic local laboratory. Codex implemented/tested; human independent reproduction and
external review are **NOT DEMONSTRATED**. Telemetry observations and detector alerts are not
validated vulnerabilities or confirmed client incidents. [Current results](docs/validation-status.md)
distinguish native execution, fixtures, reference-only imports and remaining gates.

The source-selected baseline is **#114 OpenTelemetry Collector (Core), #115 OpenLLMetry
(Core), #117 Langfuse (Core), #119 Wazuh (Supporting)**. No formal P009-to-37-risk mapping
is asserted. OpenTelemetry Demo, Sigma, Phoenix and endpoint agents are not dependencies.

```bash
cd p-009
./scripts/setup
make doctor validate
make verify                    # strict schemas, lint, types, socket-disabled offline suite
make demo                      # synthetic fixture exercise; no native-product claim
docker build -t p009-app:local .
make up PROFILE=core
make test-live PROFILE=core     # actual SDK → Collector → authenticated archive
make up PROFILE=langfuse        # staged, substantial disk/memory use
make test-live PROFILE=langfuse
make test-live PROFILE=wazuh    # isolated manager; full indexer/dashboard gate stays separate
make down
make cleanup CONFIRM=p009-owned-resources
```

All Docker networks are internal. Published archive `127.0.0.1:8099` and Langfuse
`127.0.0.1:3009` are loopback only. This managed rootless host can suppress internal-network
port publishing; scripted probes run inside the private network. No graphical browser
test is implied. Runtime credentials are generated under `.runtime/`, never supplied here.
Default commands require no provider, GPU, real account, cloud or internet-connected target.

The local Unix archive owner is a trusted custodian. CLI `--tenant` selects that custodian's
view; it is not a remote authentication mechanism. The private API maps generated tokens to
fixed tenant/role identities. Remote producers cannot choose tenant/actor from their payload.

`./scripts/p009` provides scoped status, exact-ID timelines, read-only sibling imports,
integrity verification, sanitized exports and retention audit/application. Use `--help`.
Fixture demos create unique archives under ignored `.runtime/demos/`; the running native
archive lives in the labelled `p009-archive` volume. These stores have explicit separate lifecycles.

[Architecture](docs/architecture.md) · [Deployment](docs/deployment.md) ·
[Operations](docs/operations-and-troubleshooting.md) · [Acceptance](docs/acceptance-traceability.md) ·
[Privacy](docs/privacy-and-redaction.md) · [Limitations](docs/limitations.md) ·
[Delivery](docs/delivery-report.md) · [Unsolved workbook](docs/learner-workbook.md).
