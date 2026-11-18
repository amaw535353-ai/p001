# P009 delivery record

P009 delivers actual synthetic telemetry collection, exact-ID investigation, private evidence
storage, native product checks and a sanitized future handoff. Its remaining gates are explicit
in [validation status](validation-status.md), [test results](test-results.md) and the
[88-row acceptance catalog](acceptance-traceability.md). Native observations are dated
2026-11-16; final source checks and cleanup are dated 2026-11-18.

The repository is [amaw535353-ai/p001](https://github.com/amaw535353-ai/p001), based on default
branch `p001-initial` at `85302ea391f11df403630416b5dbf0decda831d3`. PRs #5 (P007), #6 (P008)
and #7 (P006) were observed MERGED at discovery. The feature branch is
`feat/p-009-security-evidence-telemetry`. Changes are confined to `p-009/` and its dedicated
`.github/workflows/p009-offline.yml`; the final commit identity is the Git commit containing
this report, avoiding a self-referential file hash. The direct user request authorizes commit,
push and merge. The final PR and merge commit record publication and the checked working tree.

Implementation includes 22 Python modules, strict models and 11 generated JSON Schemas,
seven fixed source mappings, privacy/source guards, an authenticated private API, bounded
ingestion, archive/custody/retention, exact-ID timelines, read-only sibling adapters, 20 versioned
detection rules with benign/abnormal fixtures, an operator CLI, core/optional product lifecycle,
hash-locked setup, container definitions, CI and the required operational/workbook documentation.
No sibling implementation or schema changed. [Source discovery](source-discovery.json) records
the reviewed sibling files, official repository references and source hashes.

The executed request passes through OpenLLMetry workflow/task/tool decorators, authorization,
an arithmetic tool and an independent deterministic HTTP backend with W3C context. Source content
suppression and a pre-network guard precede authenticated OTLP. The Collector fixes trusted source
identity, filters unknown service names and applies metadata allowlists before bounded batching
and fixed exporters. P009's authenticated API validates before queueing/persistence. Langfuse
receives supported OTLP separately; its actual stored observations are read through the v2 API.
Wazuh's isolated manager reads only a controlled synthetic localfile and generates native alerts.
P009 projects those alerts and preserves exact source references in a verified timeline/export.
See [architecture](architecture.md), [data flow](data-flow.md) and [network/failures](network-and-failure.md).

Exact immutable image references, including all SHA-256 digests, are in
[images.lock.json](../config/images.lock.json) and [image verification](image-verification.json).
Selected versions are Collector contrib 0.165.0, OpenLLMetry `traceloop-sdk==0.63.0` with
OpenTelemetry 1.45.2, Langfuse web/worker 4.80.0 and Wazuh 4.14.10. Supporting images pin
Python 3.12.14, ClickHouse 26.3.62.3, PostgreSQL 17, Redis 7.4 and Chainguard MinIO by digest.
The Python lock and [102-distribution inventory](dependency-inventory.json) record exact packages.
License observations are in [dependency and license inventory](dependency-and-license-inventory.md).
Full image SBOM/CVE, transitive license/redistribution review and independent vulnerability
assessment are unverified; immutable hashes do not establish vulnerability freedom.

All four selected products actually executed. Core native checks pass 20 assertions, including
six observed spans, five source-guarded SDK spans, parent links, W3C propagation, real tool execution,
safe provider failure, authenticated ingestion, tenant denial and Collector restart. Langfuse
passes four native API/ingestion/privacy checks and records retention NOT_TESTED. Wazuh manager
passes five checks, including all 20 expected rule IDs and 20 benign controls, actual localfile
ingestion, trusted level and the cross-product evidence case. The separate full indexer/dashboard
gate is BLOCKED; configuration or a successful manager does not satisfy that gate.

The native case preserves eight exact-ID events, six Langfuse observations and nine verified
objects/manifests. The offline demo separately verifies duplication, out-of-order arrival, an
explicit missing sequence, disposable tamper detection and sibling imports. Correlation supports
trace, request, tool, authorization-decision and related-event references within one tenant.
Ambiguous identifiers and missing links remain explicit; time proximity creates no verified join.
The actual P006 request/authorization mismatch is preserved as partial correlation.

Prompt/completion capture is disabled. Token, cookie/session, provider/Vault key, PII, body and
prompt canaries are dropped or refused before persistence/export. Source SDK, Collector/archive
and native Langfuse checks found the planted source prompt absent in the tested artifacts.
Unsafe allowed metadata fails closed; debug cannot bypass policy. Runtime-secret byte comparison
against publishable source found zero matches. Secrets and raw evidence remain outside Git.

Object/manifest SHA-256 and actual byte counts, chain changes, no-follow paths, no-overwrite
creation, access denial/audit and local tenant retention pass. Retention removes scoped object
bytes and exports while retaining minimal custody metadata/tombstones. These establish local
byte consistency under a trusted Unix/Docker custodian; source truth, trusted time, signatures,
WORM, privileged full-history rewrites and deletion of all downstream copies are not proven.

The actual P007 ReportExport 1.0 and `p007-handoff-v1` example validate read-only, preserving
11 source results: nine PASS, one FAIL and one FLAKY. Those imported statuses are not P009 test
failures or findings. Original artifact bytes are absent, so its provenance stays REFERENCE_ONLY;
synthetic run fixtures separately prove hash/size/path/tamper refusal. The P008 adapter validates
the actual `p008-handoff-1.0` shape using a labelled authored fixture because no generated export
existed. It excludes sample rows/IDs and evaluator prompts/config. The actual unchanged P006
authorization method was executed with fixture dependencies; live P006 deployment is NOT_TESTED.
No missing request ID or tenant was invented.

The `p009-handoff-v1` schema and sanitized example are delivered for future P010 consumption.
Native and offline exports include provenance, redaction, integrity references, source status
counts, timeline and explicit limitations, with empty findings. Actual P010 consumption is
NOT_TESTED. P009 does not decide severity, assessment methodology or client findings for future
related consultancy projects.

Final checks pass 168 socket/DNS-disabled tests across seven categories, Ruff, mypy, 11 schemas,
20 generated rules, seven root unit tests and root static checks. The 88 requirement statuses
are 69 PASS, 15 PARTIAL, three NOT_TESTED and one REFERENCE_ONLY, plus the separate BLOCKED full
Wazuh deployment gate. Counts and source fingerprints are in
[verification summary](verification-summary.json); historical failures remain local.

The test host is Linux x86_64 with rootless Docker 29.9.2, Compose 2.40.3, three Docker CPUs,
roughly 9.7GiB Docker-reported memory and an actual 8GiB task cgroup, a 63GB disk and slow `vfs`.
NOFILE is 16384. Langfuse was staged with a 2GiB ClickHouse server budget and finite threads;
the full product set was not certified to run concurrently. Shared-cgroup resource statistics
cannot prove per-container enforcement. Core preflight requires 2GB memory/3GB free and the
Langfuse preflight 7GB Docker memory/10GB free; these are guardrails, not measured minima.
`vm.max_map_count=65530` blocks the Wazuh indexer prerequisite of 262144. No host setting was altered.

Cleanup verified zero remaining P009 containers, networks, named volumes and runtime credentials.
The legacy Redis image-created anonymous volume was removed only after proving its exact owned
container/mount association and absence of other users. Two unrelated anonymous volumes and
`p001-workload:local` were preserved; images and build caches were retained. The native archive
snapshot and both native case archives still verify, while historical local evidence is retained.
No global cleanup occurred. Final source scope checks preserve P001–P008.

The [learner workbook](learner-workbook.md) contains questions/tasks without solutions.
G1 architecture, G2 correlation, G3 integrity/privacy, G4 monitoring and G5 evidence defense all
remain NOT DEMONSTRATED. Codex implementation/testing does not establish learner competence,
independent human reproduction or external human review.

No additional user step is required for the authorized source commit/push/merge. Further product
assurance requires these distinct tasks:

1. On a separate compatible host, engineer and verify the secured Wazuh indexer/dashboard
   deployment profile; the current full profile deliberately refuses startup.
2. Cold-replay the final Langfuse named-volume layout, verify graphical/session access and a
   second project with cross-project denial, then test native per-record retention/deletion.
3. Measure native Collector rejection/exporter outage counters, queue saturation, retry exhaustion,
   loss and downstream readiness under controlled failure; verify enforceable resource accounting.
4. Collect an authorized live P006 source without inventing missing context, select an actual
   P007-owned run root to verify its bytes, and import a real P008 generated handoff if available.
5. Independently reproduce source canaries, archive/export integrity and deletion boundaries;
   perform image/license review before redistribution or client use.
6. Have a human perform and defend workbook G1–G5 and arrange independent review before making
   production or consultancy-readiness claims.
