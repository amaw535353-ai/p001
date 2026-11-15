# Input and output safety

Untrusted JSON/YAML is limited to 4 MiB, depth 32, 120,000 values, 32,768-character
scalars, 512 nodes, 1,024 flows, 128 zones and 4,096 evidence references. The DSL
accepts at most 64 unique rules, at most 12 predicates per all/any/exclude clause,
and only allowlisted typed fact fields and eq/ne/in operators. Analysis fails
above 512 generated candidates. Paths have at most four edges. File paths have
at most 16 components below an approved root and 2,048 characters. Run manifests
inspect at most 161 entries / 128 files. No recursive includes or URL resolution.

Duplicate mapping keys, YAML tags/anchors/aliases, executable objects, invalid
references and unsupported schema versions fail closed. Input reads are regular
files within the checkout; no-follow directory descriptors reject symlinked
parents and files. Output writes use exclusive temporary files and atomic replace,
avoiding symlink and hardlink writes through outside resources. Runtime writes
are restricted to generated/ and evidence/. Active same-user compromise is outside
this local CLI's trust model; this is not a multiuser sandbox.

Reports escape imported Markdown/HTML. Diagrams use hashed identifiers and a
lossy label allowlist; links, click directives and HTML cannot be injected. No
rendering engine runs. No spreadsheet export is provided, avoiding formula
interpretation; JSON remains data.

Pattern-based redaction covers credential assignments, bearer/token-looking
values, key-like strings, email-shaped identifiers, credential URLs and private
key blocks; structured secret fields are redacted. Domain authorization-status
enums are preserved as metadata. Redaction occurs before public hashes. Tests
use synthetic canaries. Arbitrary opaque secrets and arbitrary PII cannot be
reliably detected: operators must supply approved sanitized/synthetic inputs and
review exports before publication. Error messages never echo untrusted records.

Manifests detect changed/missing/extra files; derived data must agree with
analysis before manifest regeneration. Hashes are not signatures or proof of
human review. Role labels are unverified caller assertions. No imported document,
model, rule or generated Python is executed. No network-capable runtime module.
