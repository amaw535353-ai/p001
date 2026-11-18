# Canonical record model

Each envelope stores kind, ID, engagement ID, monotonic version, creating
role, UTC time, classification and typed record data. Every link includes
kind, ID, version and canonical SHA-256. SQLite retains material prior
versions. The JSON schemas in `schemas/` are generated from the Pydantic
models and checked for drift. Service actions also enforce semantic constraints
across the linked records.

| Record | Stored data |
| --- | --- |
| Engagement and source | Scope, assets, window, registry, caveat, original project/contract, byte digest and time |
| Observation and finding | Epistemic state, evidence, authorized reviewer decision, asset, prerequisites, impact, limitations and reviewed severity |
| Evidence | Exact source record, optional artifact size/hash, redaction, byte-verification state and selected excerpt |
| Risk and acceptance | Source risk definition, applicability basis, inherent and residual ratings, treatment, scoped and expiring owner decision |
| Remediation and retest plan | Recommendation, owner, due date, claimed implementation and planned checks |
| Retest | Original and new source results, comparability, evidence and regression state |
| ATLAS mapping | Technique and catalog identity, evidence, confidence and reviewer rationale |
| Report | Frozen top-level and dependency versions, narrative, quality gates, review and approval |
| Redmine binding | Separate synchronization intent, issue identity, fingerprint, timestamps and mapping version |
