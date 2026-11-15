# Versioned contracts

`schemas/` is generated from strict Pydantic models. Use `make schemas` to detect
drift. JSON Schema describes structure; `p005 model validate` also checks semantic
references, provenance, source/tenant/principal constraints and boundary coverage.

| Artifact | Version / interpretation |
|---|---|
| model.json | p005-model-1.0; graph, source hashes, scope and epistemic metadata |
| threats.json | array of p005-threat-1.0; candidates only |
| analysis.json | p005-analysis-1.0; model digest and cross-referenced outputs |
| risk-traceability.json | p005-traceability-1.0; risks/nodes/edges/controls/tests/evidence |
| atlas-mapping.json | p005-atlas-mapping-1.0; versioned catalog and review candidates |
| review-log.jsonl | p005-review-1.0 per line; synthetic editorial records |
| model-diff.json | p005-diff-1.0; graph/threat changes and invalidation |
| run-manifest.json | p005-manifest-1.0; sanitized artifact hashes and limitations |

Public JSON is UTF-8, sorted keys, ASCII escapes, two-space indentation and one
trailing newline. Semantic model/threat outputs are deterministic in the locked
environment. Run clocks and engineering evidence directory names intentionally
vary. Source snapshot hashes are computed *after* redaction; original private
content hashes are not synthesized for publication.

IDs use a type prefix plus full SHA-256 of structured semantic inputs. Threat
inputs include rule/version, edge, tenant, owner and preconditions. A changed
trigger on an unchanged semantic rule/edge retains the ID and requires review;
a changed rule version or precondition changes it. Hashes do not leak names in
identifiers; theoretical collisions fail the unique-ID check. Human-readable
fixture IDs are explicitly synthetic. P-004/P-002 original IDs remain source_id.

CLI output files are confined to this project's generated/ and evidence/ trees.
Existing unowned run directories are refused. Different model digests require a
fresh run. Identical runs can refresh outputs while preserving the review ledger.
No binary/CSV/HTML/SVG export is implemented; Markdown/Mermaid/DOT escape or
remove active syntax. External consumers must not reinterpret labels as code.
