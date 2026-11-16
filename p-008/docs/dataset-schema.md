# Dataset contracts

All contracts use schema 1.0, forbid unknown fields, constrain IDs and SHA-256
digests, bound strings and collections, and reject nonfinite scores. Generated
JSON Schemas are checked against typed models by `make schemas`.

A Bundle combines a card, samples, scenarios, tasks, expected outcomes, scorers
and exact split manifests. Dataset/sample/task/scenario/scorer versions and
references must agree. Duplicate or orphan IDs and incomplete split coverage are
rejected. Each sample has input encoding, provenance, expected-outcome reference,
dimensions, lineage, difficulty, fixture dependencies, limitations and digest.
Expected outcomes include allowed/forbidden actions, required trace tool, basis,
label provenance, adjudication and a private leakage canary.

Frozen storage separates `dataset.json`, `model-inputs.json`, `splits.json` and
`private/outcomes.json`. The manifest binds all file hashes, sizes, sample IDs,
sample hashes and bundle identity; its anchor is stored separately. The card's
manifest_digest is the canonical bundle identity with that field zeroed, avoiding
a self-referential hash; the external manifest has its own distinct digest.

`make validate` also validates all 21 schema documents themselves. Structural
schemas cannot express every reference, lineage or hash invariant; runtime gates
and acceptance tests supply those checks. Examples are regenerated from source
instead of committing sealed labels or runtime traces.
