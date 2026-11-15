# Testable security requirements
All outcomes are engineering baseline evidence, not independent consultancy findings.
No OWASP AISVS/ASVS control IDs are asserted: primary versioned requirements were not
verified during this build. Candidate alignment can be added after source review.

| ID | Requirement | Baseline / expected behavior |
|---|---|---|
| SR-01 | Local-only operation | DOCTOR, DOCKER-EXPOSURE, RUNTIME-HARDENING: fake credentials, loopback bindings |
| SR-02 | Caller tenant binding | TENANT-DENY / DOCKER-DENY: wrong or missing bearer → 403 |
| SR-03 | Deterministic simulator | INFERENCE: stable response with simulator=true |
| SR-04 | Synthetic separated objects | OBJECTS: marker read/write in fixed tenant bucket; invalid data → 400 |
| SR-05 | Minimal Kubernetes access | RBAC: named ConfigMap get yes; secrets/pod-create no; no mounted token |
| SR-06 | Segmentation | NETWORK: same-tenant works; cross-tenant and unauthorized egress timeout |
| SR-07 | Restricted workloads | STATIC + RUNTIME-HARDENING: caps dropped, nonroot, read-only, resource limits, probes |
| SR-08 | Supply-chain integrity | INSTALL + IAC: artifact hashes, signed providers, locked SDK wheels |
| SR-09 | Sanitized evidence | LOGS: allowlisted fields and correlation IDs; manifest hashes and UTC |
| SR-10 | Recovery and ownership | DRIFT + REBUILD: detect/restore drift; two safe teardowns; clean reprovision |
| SR-11 | Honest cloud assurance | AWS-IAM / LOCALSTACK-IAM: NOT TESTED unless independently demonstrated |

No rate-limit, hostile host protection, cryptographic tenant bearer issuance or
production-grade IAM is claimed by these requirements. Resource cgroups bound the
workload, but performance/denial-of-service behavior needs independent assessment.
