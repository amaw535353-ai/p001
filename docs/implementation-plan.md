# P-001 implementation plan

Synthetic lab / not a real client engagement / no independently verified findings yet.

Use this existing empty checkout as the project root (rather than nesting a second project).
No reference inventories were present under /workspace at inspection. Only P-001 is implemented.

Architecture: loopback caller → tenant-specific API → deterministic mock inference and
LocalStack S3. kind has tenant-a, tenant-b and emulator namespaces. Calico enforces
namespace/pod-scoped policies. OpenTofu owns S3 buckets and Kubernetes resources;
scripts bootstrap the Docker/kind/CNI boundary, without local-exec provisioning.

Ordered tasks: verify tools and official sources; implement services and tests; pin
artifacts; bootstrap cluster/CNI; initialize/validate/plan/apply OpenTofu; functional,
negative, RBAC/network, drift and lifecycle checks; save sanitized evidence and setup.

Required checks are unit, IaC, deployment, positive/negative authorization, actual
network denial, drift and rebuild. Optional checks are third-party scanners and
explicitly authorized future AWS comparison. Missing runtime controls are BLOCKED.

Initial host: Linux x86_64, Python 3.12.14, rootless Docker 29.9.2, ~33 GiB memory,
60 GiB available disk. kind/kubectl/OpenTofu initially absent. Install verified
release binaries locally in .tools/bin. No elevation planned. Rootless nested
Kubernetes may be unsupported here; preserve implementation and diagnose failures.

Official sources consulted: kind v0.33.0 default image source, Calico v3.33.1
manifest, OpenTofu release checksums and changelog, LocalStack IAM documentation
(all via official GitHub repositories). Version pins are recorded in versions.lock.md.
Some documentation/API domains are proxy-blocked; never disable TLS/checksums.
LocalStack IAM authorization remains NOT TESTED; fake emulator credentials are not
federated Kubernetes identities. AWS is an unimplemented, separately gated comparison.
