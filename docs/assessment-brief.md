# Fictional client assessment brief
Synthetic lab / not a real client engagement / no independently verified findings yet.

Fictional client Northstar Example Services is preparing a two-tenant assistant
platform. The engagement is to assess the intended identity, isolation, runtime,
supply-chain and recovery properties of its local reference environment.

Authorized assets: only p001-owned local kind cluster, tenant-a, tenant-b, emulator,
lab APIs, deterministic mock endpoints, fake object buckets and recorded build inputs.
Exclusions: host administration, unrelated containers, third parties, real AWS,
external scanning, real personal data, paid services and production systems.

Objectives: reconstruct architecture and trust boundaries; develop reproducible
positive/negative tests; evaluate intended caller isolation, least privilege, egress,
resource bounds, artifact provenance and safe recovery. Candidate risks #1, #15, #18,
#35, #36 and #37 are future hypotheses, with rationale in threat-scenarios.md; none
is a completed full assessment. Expected properties are specified in security-requirements.md.

Constraints: use synthetic inputs and bounded requests; obtain authorization for scope
changes; preserve evidence and unrelated work; never equate emulator behavior to AWS.
Report confirmed observations separately from hypotheses and false positives.
Builder baseline tests are available as engineering evidence, not a vulnerability
answer key or proof of independent learner competency.
