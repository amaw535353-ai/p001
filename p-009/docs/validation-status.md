# Validation status

P009 implements a synthetic local telemetry and evidence platform with actual execution of
**OpenTelemetry Collector 0.165.0, OpenLLMetry 0.63.0, Langfuse 4.80.0 and Wazuh manager 4.14.10**.
The engineering outcome is bounded by the explicit gaps below. No production incident,
validated vulnerability, formal 37-risk coverage or learner competence is asserted.

| Delivery gate | Status | Observed scope |
| --- | --- | --- |
| A — Architecture | PASS | Implemented collection, processing, stores, trust boundaries and exports documented |
| B — Collector | PARTIAL | Native ingestion/restart/authentication pass; full memory/queue saturation and exporter loss accounting unverified |
| C — Instrumentation | PASS | Actual decorated request/tool/model/backend path, six spans and context propagation |
| D — Langfuse | PARTIAL | Native ingestion, exact IDs, API authentication and canary checks pass; UI, project B and retention unverified |
| E — Wazuh | PARTIAL | Actual manager ingestion and 20 rule/benign pairs pass; indexer/dashboard BLOCKED |
| F — Correlation | PASS | Exact-ID timeline, tenant separation, explicit ambiguity/gaps and native cross-product case |
| G — Privacy | PASS | Source content disabled, pre-export guard, metadata allowlists and planted-canary checks within tested scope |
| H — Evidence | PASS | Object/manifest integrity, tamper, safe paths, append semantics and local retention under the stated custodian model |
| I — Siblings | PARTIAL | P007 actual example reference-only, P008 authored fixture, P006 actual method with fixture dependencies |
| J — Consultancy readiness | PARTIAL | Operational/evidence docs and unsolved workbook delivered; native gaps and independent reproduction remain |

All 168 socket/DNS-disabled engineering tests, seven root unit tests, root static checks, lint,
types and schema/rule drift checks pass. The 88 requirement rows separately total 69 PASS,
15 PARTIAL, three NOT_TESTED and one REFERENCE_ONLY. No final engineering test failed. Historical
failed native attempts remain in local evidence. [Test results](test-results.md) explain each layer.

The full Wazuh stack requires `vm.max_map_count >= 262144`; this host reports 65530. No kernel
or privilege weakening was performed. Manager-only success does not prove indexing, dashboards,
host detection or SOC coverage. Even on a compatible host, the full profile currently refuses
startup until a separate deployment profile has been engineered and verified.

Langfuse graphical/session access, cross-project separation and per-record retention/deletion
are NOT_TESTED. Native exporter outage/loss experiments and sustained Collector saturation remain
unverified. The Collector health endpoint provides liveness, not a guarantee of every downstream
exporter. Resource accounting shares an 8GiB parent cgroup; configured per-container limits have
not been independently established as enforced.

P006's real authorization method emits decision ID but omits request ID; its failure event omits
tenant context. The adapter preserves the former gap and refuses the latter without guessing.
Live P006 collection is NOT_TESTED. The original P007 example's artifact bytes were unavailable;
synthetic safe-path/hash fixtures do not change its REFERENCE_ONLY status. No real P008 generated
handoff existed, so its actual contract shape is tested with an explicitly authored fixture.
Sealed sample results and evaluator content are excluded. P010 consumption remains NOT_TESTED.

Scoped cleanup is complete: no owned containers, volumes, networks or runtime credential files
remain. Native snapshots, case archives, prior failures and local exports remain ignored and
verify under their separate lifecycles. Existing P001 resources, unrelated volumes and all
P001–P008 source are preserved. Images/build caches are retained without global pruning.

Codex implemented and tested this project. Human independent reproduction, external human review,
production acceptance and workbook G1–G5 are **NOT DEMONSTRATED**.
