# Quality gates and split lineage

Seed 20261116 orders 24 lineage groups by SHA-256(seed, group) and assigns groups
round-robin to five named splits. Each group contains two independently identified
cases; scenario/template/construction identifiers keep related examples together.
Exact manifests are stored with every generated version. Changing the seed is
recorded and changes resource identities and potentially split membership.

Quality checks reject schema/reference errors, stale hashes, exact duplicate
inputs, missing or inconsistent labels, ambiguous/disputed adjudication, and
group/scenario/template/construction leakage across splits. Prompt similarity
at ratio >=0.80 is a review signal, not automatic proof of duplication/leakage.
Coverage reports reconcile family, split, difficulty, modality and outcome counts.
Risk counts describe only mapped examples and need not sum to total samples.

The shipped generator's 48 examples produce 10/10/10/10/8 split counts. Tiny
lineage pairs and a shared policy mean these are mechanics demonstrations, not
statistically independent training/test populations. Metadata lineage can be
wrong at creation; semantic contamination and real pretraining exposure require
additional investigation. A critical gate cannot be hidden in an average quality
score; every error is emitted individually.
