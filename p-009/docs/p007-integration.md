# P007 read-only import

```mermaid
flowchart LR
  Report[actual ReportExport 1.0] --> Schema[actual merged schema validation]
  Schema --> Handoff[p007-handoff-v1 exact references]
  Handoff --> Root[explicit P007-owned run directory]
  Root --> Bytes[no-follow reads and size/hash validation]
  Bytes --> Preserve[unaltered source report and statuses]
  Handoff --> Ref[REFERENCE_ONLY when run bytes not supplied]
```

The importer reads the actual sibling JSON Schemas without importing a P007 runner. It validates
run identity, handoff shape, safe relative paths, unique references, manifest digest, artifact
sizes/digests and report/manifest agreement. Symlinked components, special files, oversized files
and traversal fail. Fixtures exercise byte verification without executing a P007 test catalog.

PASS/FAIL/BLOCKED/NOT_TESTED/INCONCLUSIVE/NOT_APPLICABLE/FLAKY, expectations, observations, assertions,
runner metadata, definition/compatibility hashes, control status and provenance stay unchanged.
The committed actual example has no accompanying run bytes here and imports as REFERENCE_ONLY.
Nothing is promoted into a client finding, reproduction result or fresh scope authorization.
