# Network trust and loss boundaries

```mermaid
flowchart TB
  Owner[trusted Unix custodian] -->|loopback only when host supports it| API[authenticated archive API]
  subgraph core[p009-core internal network]
    API --- Collector[authenticated Collector]
    Backend[deterministic backend] --> Collector
  end
  subgraph lf[p009-langfuse internal network]
    Collector --> Web[Langfuse web]
    API --- Web
    Web --> PG[PostgreSQL]
    Worker[worker] --> CH[ClickHouse]
    Worker --> S3[MinIO]
    Worker --> Redis[Redis]
  end
  Wazuh[isolated Wazuh manager: network none] --> Local[owned synthetic localfile only]
```

No public/default Docker network is attached. Host publication remains loopback. Internal HTTP
and the local custodian/Docker daemon are trusted; production TLS/mTLS and independent host
assurance are not demonstrated. An archive process on the Langfuse network is an explicitly trusted
operator/probe boundary, not an untrusted frontend. Native datastores use generated credentials.

```mermaid
flowchart LR
  Event[controlled source event] --> Receiver[bounded receiver]
  Receiver --> Rejected[malformed/auth/source refusal metrics]
  Receiver --> Privacy[metadata validation before queue]
  Privacy --> Queue[bounded in-memory queue]
  Queue --> Retry[finite retry on exporter failure]
  Retry --> Store[verified archive acknowledgement]
  Retry --> Loss[retry exhaustion or restart: possible loss]
  Queue --> Saturation[queue-full refusal and counters]
  Store --> Verify[integrity checks before queries/exports]
```

Counters reset with their processes unless separately retained. Neither health endpoints nor an
accepted receiver request prove downstream completeness. Long outages and Collector restarts can
lose in-memory batches. Gaps, duplicates and source sequencing support bounded investigation; they
cannot prove that an event never occurred. Actual measured failures remain in ignored history.
