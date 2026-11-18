# Retention and deletion

Default traces, metrics and health metadata retain one day; audit/security events retain seven
days; local exports retain one day. Retention uses trusted collection time, preventing a forged
source timestamp from forcing immediate deletion or indefinite retention. Dry run precedes an
explicit custodian apply operation. Other tenants and source artifacts are untouched.

Objects are purged through digest-scoped tombstones. Historical manifests, normalized-source
digests, tombstones and operator audit metadata remain to explain deletion; this minimal custody
metadata currently has indefinite local retention. Tests verify missing bytes, filtered reads,
tenant boundaries and local export removal. Incomplete purge is an integrity error, not success.

The native archive volume is removed only by owned-resource cleanup; offline archives/history
are preserved. Langfuse PostgreSQL/ClickHouse/MinIO/Redis and Wazuh runtime files have separate
lifecycles. No deletion from all downstream databases, backups or copies is claimed without a
verified native lifecycle test. `down` stops services; it does not mean evidence was deleted.
