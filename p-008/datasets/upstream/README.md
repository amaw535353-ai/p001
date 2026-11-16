# Reviewed upstream references

`source-lock.json` pins all four inventory technologies and their inspected release
commits. Python wheels are hash locked separately; npm transitive packages retain
registry integrity hashes. A release tag is a repository reference, not a trusted
signature. Installed code behavior was checked in actual local runs.

No upstream benchmark dataset is redistributed. Inspect Evals' `strong_reject`
task is imported and its record converter is run on clearly marked P-008 synthetic
records. Its network dataset acquisition and hosted model judge remain NOT_TESTED.
The underlying StrongREJECT data license has not been approved for redistribution.
AgentDojo executes P-008's in-memory environment through its actual runtime and
task predicates; official benchmark suite coverage is not claimed.
