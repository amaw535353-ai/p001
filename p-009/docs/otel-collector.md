# OpenTelemetry Collector

Inventory #114 uses the official **contrib distribution 0.165.0**, whose upstream component
manifest includes basicauth, filter, transform, resource, batch, memory_limiter, health_check
and OTLP HTTP. The core repository remains the selected technology; contrib supplies the
verified processors/extensions. Exact image digest is in `config/images.lock.json`.

```mermaid
flowchart LR
  R[OTLP HTTP 4318 internal] --> M[memory limiter 128 MiB]
  M --> F[source allowlist]
  F --> P[fixed resource identity and metadata transform]
  P --> B[batch maximum 32]
  B --> E[archive exporter queue 64 and finite retry]
  B --> LF[optional Langfuse trace exporter]
  C[self metrics 8888 internal] --> Operator[scripted diagnostics]
```

`collector/config.yaml` uses four signal pipelines and no sampling. Receiver bodies are bounded
to 65536 bytes. Export queues have one consumer, capacity 64, a 5-second request timeout and
10-second retry budget. Memory limits are application settings; Docker cgroup enforcement must
not be inferred on this rootless host. Queue capacity is batches, not a promise of total events.

Finite retries and in-memory queues can lose telemetry during prolonged failure or restart.
Accepted/refused/export-failed/queue metrics and archive counters must be interpreted together.
Health_check is process health, not proof that all exporters are delivering. Source filtering
can drop unauthorised resource identities; filter metrics are part of loss accounting.
