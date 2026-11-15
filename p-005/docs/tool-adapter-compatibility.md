# Native tool adapter compatibility

| Tool / software ID | Local version | Native format inspected/validated | Executed | Roundtrip | Status |
|---|---|---|---|---|---|
| OWASP Threat Dragon #122 | Not installed | None | false | false | BLOCKED |
| OWASP pytm #123 | Not installed | None | false | false | BLOCKED |
| Threagile #124 | Not installed | None | false | false | BLOCKED |
| MITRE ATLAS data #125 | 2026.10 / 6.1.0 | Official YAML technique projection, pinned bytes | Parser only | N/A | VERIFIED local catalog import |

`p005 adapters status` emits version, schema_version, executed, exit_status,
source_digest, output_digest, warnings, unsupported_fields, tested_roundtrip,
evidence_ref and verification_status. Absent versions/digests are null, never
invented. A discovered executable alone does not establish compatible schema or
safe execution: it remains blocked. `adapters export` refuses execution.

No Threat Dragon JSON, generated pytm Python or Threagile YAML is emitted. Own
DOT/Mermaid diagrams are available. Native import/export loss and stable identity
mapping need real version-specific fixtures, schema inspection and native tests
before implementation. pytm would require human source review and a networkless,
resource-limited sandbox. No arbitrary Python run is supported.

Outputs from multiple native tools would be transforms of the same model, not
independent evidence that a claim is true. Current blocked adapters have no
outputs to reconcile. Catalog references are not native threat-tool validation.
