# Version 1.0 evidence and consumer contract

`schemas/*.schema.json` is generated from the actual strict Python models.
`make schemas` checks drift. Unknown fields, unsupported kinds and cross-reference
errors fail validation; semantic hash checks supplement JSON Schema.

| Artifact | Contract |
|---|---|
| snapshot.json | Context plus complete graph, observations, coverage and semantic digest |
| assets/endpoints/identities/flows/trust_boundaries.json | Strict envelope: schema_version, context, snapshot_digest, records |
| observations.jsonl | schema_version, run_id, one typed observation per line |
| coverage.json | Envelope; source/target/status, processed and known_denominator (null when unknown) |
| inventory-diff.json | Added/removed/changed entity records, before/after digest, policy_changed; no-baseline NOT_APPLICABLE |
| architecture.mmd / report.md / assets.csv | Sanitized derived views, formula-safe CSV and constrained diagram labels |
| assessment-record.json | Engagement/offline context, candidate prompt-sourced risk numbers, proposed internal checks, tool reality, learner/publication state |
| evidence-manifest.json | Context, actual invocation category, input file hashes/pointers, output hashes and versions |
| owner.json | Owned filenames/hashes; local cleanup authority, not a signature |

Context includes run ID, immutable live engagement version/digest when applicable,
actual UTC acquisition time, tool version, base Git commit, environment, dataset
seed, mode, outcome and sanitization status. Base commit alone does not identify
uncommitted code: the engineering manifest additionally hashes source/tests/config.
Per claim: stable ID, tenant/environment, source path/hash/pointer/line where known,
method, status, confidence, acquisition clocks, human-confirmation flag, constraints
and allowlisted attributes. `evidence_claims` records each source's status, method
and measured scope; an observed HTTP response never upgrades a declared auth or
control property into a verified one. Evidence retained through conflicts is not overwritten.
Live decision references resolve to policy-decision observations, not a fictitious
on-disk ledger export. Source files remain local; hashes do not disclose their content.

Confidence describes specificity, not probability of a vulnerability: 0.9 direct
HTTP metadata; 0.6 explicit declaration; 0.3 inferred/unverified. OBSERVED says only
what the particular observation measures. Static claims are DECLARED; source route
candidates UNVERIFIED; crossings INFERRED. Coverage does not invent a total for an
unknown application. P-001 manifest entry counts and graph asset counts are different
units and must not be combined into an overall coverage percentage.

Architecture digests ignore run IDs/clocks and include sorted asset/endpoint/flow/
boundary content and provenance. Equivalent sources produce equivalent semantic
hashes; byte-identical full reports are not promised across acquisition times.
Source hash changes count as provenance changes; diffs should be reviewed rather
than automatically prioritized as vulnerabilities. Changed entries report
`changed_fields` and distinguish `provenance-only` from `inventory` changes.

P-005 consumes assets/flows/boundaries for human threat-model input; P-007 compares
snapshots without inferring controls pass; P-009 consumes hashes and provenance;
P-010 consumes the memo/assessment record with its uncertainty. Consumers must
reject unknown major versions, preserve tenant and actor context, and retain
epistemic status. Enterprise projects P-091/092/093/099 receive this same export
contract only. None is implemented by P-004.
