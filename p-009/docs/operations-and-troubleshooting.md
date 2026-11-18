# Operator workflows

Use `make doctor validate verify`, `make up PROFILE=core`, then `make test-live PROFILE=core`.
Stage Langfuse and Wazuh tests separately. Native startup can be slow on vfs; inspect owned
container state and ignored `work/failure-*.txt` locally, without copying credentials or raw
logs into a report. Recheck readiness after restart; process health is not exporter health.

`./scripts/p009 --archive <owned-path> status|timeline|evidence-verify|export|retention-audit`
operates on a local archive. Imports require an explicit file. P007 artifact verification also
requires `--run-root <explicit-owned-run>`; an example report without bytes is REFERENCE_ONLY.
P008's authored fixture is documented, not described as a live generated export.

Native `/status` reports ingestion counters, queue state and archive integrity to an authenticated
operator. Collector metrics are private at port8888. Malformed/unknown inputs are refused; a failed
archive write leaves the sanitized queue head for retry. Queue/memory/retry settings are bounded.

`make down` retains state. `make cleanup CONFIRM=p009-owned-resources` removes only verified named
P009 resources and runtime credentials after shutdown; offline evidence/history remains. Do not
use global prune, delete unrelated images/volumes, attach an internet network, or weaken controls.
