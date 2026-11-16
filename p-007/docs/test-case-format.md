# Test-case and control contracts

The canonical definitions are `src/p007/models.py` and generated Draft 2020-12
schemas in `schemas/`. Unknown fields, wrong types, excessive strings, invalid
references, duplicate IDs and conflicting versions fail validation. The catalog
contains 26 test definitions, six controls and four target registrations.

Cases record stable IDs/versions; title/objective/category; local threat/control
and requirement references; target/environment; exact operation and authorization
class; fixture/setup/preconditions; pinned adapter; exact-value/absent-marker oracle;
CPU/time/memory/output/request/concurrency bounds; redaction, cleanup, limitations,
ownership/lifecycle, CI/offline/operator flags and repetition policy.

The small fixture set is `fixtures-v1`; baseline/remediated/regressed policy versions
are explicit. Only the policy variants change in the demonstration. A stable test
ID does not make changed test content comparable. The plan contains the complete
selected definitions and a digest, so editing an in-memory nested input is detected.

`make schemas` checks drift. The separate handwritten
`p006-target-adapter.schema.json` defines a contract without inventing endpoints.
Retired cases may be explicitly NOT_APPLICABLE; missing runner capability is BLOCKED.
