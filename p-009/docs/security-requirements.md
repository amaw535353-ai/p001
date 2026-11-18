# Implemented security boundaries

Collection uses authenticated private OTLP, fixed exporters, known sources, bounded bodies/batches/
queues/concurrency and source-side content suppression. Schema/version/refusal and privacy counters
are part of the implementation. No payload may choose a URL, shell command, path or exporter.
Source resource attributes alone are not identity; the trusted receiver mapping is authoritative.

Evidence uses private owned roots, no-follow descriptor walks, special-file refusal, exclusive
creation, atomic publication, chained manifests, pre-read verification, tenant roles and auditable
export/deletion. Imported statuses and original report data remain source-owned; unsafe imports
must be refused rather than silently rewritten into successful results.

Monitoring rules have fixed trusted levels, exact preconditions and benign/abnormal pairs.
Internal Docker networks, loopback publications, no-new-privileges, bounded resources and no host
socket/log mounts constrain products. Rootless cgroup enforcement, native product retention, TLS,
HA, incident authenticity and production guarantees remain separate, explicit verification gaps.
