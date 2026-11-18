# Access control

API bearer tokens map to fixed Principal objects using constant-time digest comparison. Producer,
viewer, exporter and custodian capabilities differ. Reads and queries are tenant-scoped; exports
require exporter/custodian; deletion requires custodian. Unauthorized access/export is denied and
audited. Cross-tenant ingestion and timeline construction fail even with matching trace strings.

The local Unix owner can access filesystem bytes and choose CLI tenant views. That owner is the
custodian trust boundary, not an adversarial tenant. `--tenant` is not authentication. Archive and
runtime secrets use private files; the application runs as UID1000. A narrow rootless initialization
container prepares only labelled native volumes, then exits. Databases have their native generated
credentials. Product initialization capabilities remain internal to rootless containers.

The lab uses private HTTP with internal networks, not production mTLS. The trusted Collector maps
its one demo producer to tenant A; one credential is not multi-tenant producer authentication.
Separate authenticated receivers/project bindings are required before adding untrusted producers.
