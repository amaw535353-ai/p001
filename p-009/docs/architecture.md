# Implemented architecture

The typed Python package owns normalization, bounded pre-persistence ingestion, tenant-scoped
queries, exact-ID correlation, a content-addressed local archive, audit records, retention and
handoffs. The synthetic workflow executes OpenLLMetry decorators around authorization, a real
arithmetic tool and an HTTP call to a deterministic backend. No actual model is evaluated.

```mermaid
flowchart LR
  App[OpenLLMetry synthetic workflow] -->|authenticated OTLP HTTP| C[Collector contrib 0.165.0]
  App -->|W3C context and exact IDs| Mock[deterministic HTTP backend]
  Mock --> C
  C -->|allowlists before batches and queues| A[private P009 archive API]
  C -->|optional supported OTLP endpoint| L[Langfuse 4.80.0]
  A --> O[content objects and chained manifests]
  O --> Q[tenant query and derived timeline]
  Q --> H[p009-handoff-v1]
  S[sanitized synthetic security JSON] --> W[Wazuh 4.14.10 manager]
  W --> R[native alert references]
  R --> O
```

Langfuse requires PostgreSQL, Redis, ClickHouse and S3-compatible MinIO. The optional AI gateway
in its upstream compose file is outside P009's scope. Wazuh manager-only detection is distinct
from its indexer/dashboard stack, which requires a compatible host. Actual verification statuses,
not diagram edges, determine which integrations have been demonstrated.
