# Executed test results

Native verification ran on 2026-11-16. Final source verification and cleanup were completed on
2026-11-18 after the managed environment resumed. These are Codex observations in a synthetic
local lab; independent human reproduction is NOT DEMONSTRATED. The sanitized
[verification summary](verification-summary.json) records counts and source hashes. Raw telemetry,
native alerts, product output, database state and exports remain ignored local evidence.

| Offline category | PASS | FAIL |
| --- | ---: | ---: |
| Archive, custody, paths, access, export and local retention | 27 | 0 |
| Configuration, JSON, identity, bounds, queue and retry | 32 | 0 |
| Exact identifiers, ambiguity, gaps, ordering and tenants | 18 | 0 |
| Detection preconditions, benign controls and injection refusal | 43 | 0 |
| Actual sibling contracts and sanitized adapter behavior | 21 | 0 |
| Privacy classes, source identity and fail-closed behavior | 22 | 0 |
| Repository scope, ignore rules, cleanup refusal and actual P006 method | 5 | 0 |
| **Socket/DNS-disabled total** | **168** | **0** |

`make verify` also passes strict configuration validation, Ruff lint/format, mypy for 22 source
modules, 11 generated-schema drift checks and 20 generated Wazuh-rule drift checks. Root
`make unit static` passes seven unit tests and the structural/narrow-secret checks. P001
`make lab-test` was not run: no root infrastructure changed, and no Kubernetes enforcement is claimed.

| Native layer | PASS | FAIL | BLOCKED | NOT_TESTED |
| --- | ---: | ---: | ---: | ---: |
| Core Collector and executed OpenLLMetry path | 20 | 0 | 0 | 0 |
| Langfuse native observations API | 4 | 0 | 0 | 1 |
| Wazuh manager and cross-product case | 5 | 0 | 1 | 0 |

The core path observes six actual spans for an executed request: workflow, authorization,
arithmetic tool, model operation, independent HTTP backend and completion. Five SDK source spans
passed the pre-export guard with zero privacy refusals. Parent/child IDs, W3C propagation,
tool/decision/request references, safe provider failure and tenant denial were observed. Actual
Collector trace, metric, audit and security endpoints accepted their corresponding signals;
the accepted-span self-metric was observable. Collector restart retained the archive. Signal
acceptance alone does not establish exhaustive downstream metric/log contents or loss accounting.

Langfuse 4.80.0 returned six stored observations through its authenticated v2 API for that exact
trace ID; the unauthenticated request was denied and planted prompt content was absent. Native
Wazuh 4.14.10 logtest generated all 20 expected child rule IDs and no P009 child alert for the
20 benign controls. The actual daemon independently ingested its controlled localfile event and
emitted rule 110900 at trusted level 5 despite a supplied severity of 15.

The preserved native case contains eight correlated archive events, six real Langfuse
observations and nine verified objects/manifests, with an actual Wazuh alert linked to the original
source event and exact shared trace/request IDs. Its sanitized export validates against the
future P010 handoff contract; consumer execution is NOT_TESTED. The offline demo separately
observed one duplicate, one out-of-order event, missing sequence 3, disposable tamper detection,
P006 partial correlation and sibling imports. It is explicitly a fixture demonstration.

The 88 requirement statuses are **69 PASS, 15 PARTIAL, 3 NOT_TESTED and 1 REFERENCE_ONLY**; see
[acceptance traceability](acceptance-traceability.md). Native check IDs are narrower than some
requirements and do not upgrade those requirements to PASS. The full Wazuh indexer/dashboard
gate is separately BLOCKED by the host prerequisite and lacks a verified deployment profile.
Native Langfuse isolation, graphical access and retention are unverified.

Earlier attempts include Langfuse legacy-reader 404s, insufficient ClickHouse memory/pool settings,
Wazuh initialization/ruleset failures and a slow full-JSON Docker status query. Their local reports
were retained. The final successful native runs use the corrected product settings. Later
controller/status and named-volume ownership changes passed final source checks; a complete
cold replay of the final Langfuse volume layout on another host is NOT_TESTED.
The final per-input Wazuh result parser was also exercised against the retained actual native
logtest output: all 40 inputs match their expected individual positive/benign result.

Actual commands included:

```bash
./scripts/setup
make doctor validate
make verify
PYTHONPATH=tests/no-network:src ./scripts/p009 demo
docker build -t p009-app:local .
make up PROFILE=core
make test-live PROFILE=core
make up PROFILE=langfuse
make test-live PROFILE=langfuse
make test-live PROFILE=wazuh
make -C .. unit static
make cleanup CONFIRM=p009-owned-resources
```

Lifecycle orchestration uses the same scoped Python functions as these Make targets. The Wazuh
test exits nonzero for its explicit blocked full-stack gate even when all five manager checks pass.
The final status command was checked against the actual authenticated archive before shutdown:
84 events, queue zero and integrity PASS. Owned Docker resources and credentials were then
removed; the copied native archive and both native case archives still verify.
