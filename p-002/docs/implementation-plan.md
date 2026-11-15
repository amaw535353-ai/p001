# P-002 implementation plan

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Build only P-002, inside `p-002/`, preserving P-001. The implemented P-001
contract was inspected: `/objects/fixture-[a-z0-9-]{1,40}` accepts only the fixed
`P001-SYNTHETIC-ONLY` marker; arbitrary document upload is not supported.
The four named career/taxonomy source documents are absent from this workspace.
Risk numbers therefore come from the supplied build request, with wording unconfirmed.

1. Implement Pydantic versioned graph models, strict cross-record validators,
   deterministic rules generator, explicit temporal policy evaluator and oracle.
2. Export canonical JSON, per-table JSONL/CSV, labelled documents with hashes,
   manifest, import plans, event timeline and traceability. No network in core.
3. Implement twelve declarative scenarios, immutable baseline, owned snapshots,
   opt-in inconsistent states, diff and repeatable reset.
4. Implement fixed loopback adapters with redirect refusal, private credentials,
   ownership journals, readback hashes and separate actual observation records.
   Inspect official upstream source when documentation hosts are blocked.
5. Run optional services sequentially on internal Docker networks with a guarded
   loopback bridge if rootless Docker cannot publish internal-network ports.
   Pin verified registry digests; never modify cgroups or elevate privileges.
6. Evaluate SDV single-table Community using wholly generated seed records.
   It may synthesize bounded invoice amounts only; identity and permissions stay
   deterministic. SDV is BSL 1.1 source-available, not an unconditional OSS claim.
7. Execute unit/property/schema/security/lifecycle tests, real adapters where
   supported, P-001 contract tests, lint/type checks and sanitized test evidence.
8. Produce factual architecture, operations, limitations, blank consultancy
   template and G1–G4 workbook (all NOT DEMONSTRATED).

Required: offline core and honest integration outcomes. Optional: SDV, native
ACL semantics absent from Community products, full Kubernetes lifecycle.
Current host: Linux x86_64, Python 3.12.14, Docker 29.9.2 rootless with no cgroup
driver, 5 CPUs / 33 GiB reported memory, approximately 41 GiB free initially.
Run one integration at a time; stress generation is bounded and opt-in.
No real cloud, email, paid APIs, model calls, production targets or public listeners.
Risks: API drift; rootless port publishing; absent taxonomy files; unsupported
classification/deny/delegation mappings; SDV resource cost. Report each limitation
instead of silently treating an oracle as native enforcement.
