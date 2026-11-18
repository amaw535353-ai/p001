# Practical limits

This is a synthetic local engineering platform. The model is deterministic; no provider, real
client, AWS, Kubernetes, host agent, enterprise SIEM or production incident was assessed. No formal
coverage of all 37 risks is asserted. Related P073/P074/P076/P077/P080/P112/P113/P094/P095 projects
may consume evidence later; their assessment methods are not implemented here.

Local Unix owners and the Docker daemon are trusted. Private HTTP is not mTLS. Shared lab producer
credentials, process-local counters and finite in-memory exporter queues cannot establish complete,
lossless, authenticated historical telemetry. Rootless cgroup enforcement must not be assumed.
Digest checks detect inconsistency within the stated threat model, not wholesale privileged rewrites.

P006 authorization/request correlation is partial; live P006 collection is NOT_TESTED. P007 example
artifact bytes are absent; fixture verification is not original source evidence. P008 uses a labelled
contract fixture and metadata-only imports. P010 consumption remains NOT_TESTED. Native Langfuse
isolation/retention and full Wazuh stack gates require explicit results, not configuration existence.
Browser access can be blocked by internal-network publication on this host. See current results.

Full image SBOM/CVE/legal review, other-host reproduction, HA, recovery, natural credential expiry,
external time/signatures, downstream deletion, human reproduction and external review are not
demonstrated by these tests. Never convert these gaps to PASS or a detector observation to a finding.
