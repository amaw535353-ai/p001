# Requirements, evidence and traceability

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

`generated/standard/traceability.jsonl` links enterprise, tenant, actor, asset,
operation, policy, risk number, P-ID, scenario and executable test ID to expected
results and initially empty observation/human fields. Native results live in separate
append-only evidence records and include the actual canonical resource/task mapping.
The dataset reproducibility manifest and each run fingerprint identify their precise
versions. A previous failed run remains evidence even after a corrected passing run.

| Requirement | Actual verification mechanism |
|---|---|
| Synthetic-only inputs/domains and no credentials in fixtures | typed reserved domains, fixture/export assertions, narrow source scan |
| Deterministic repeat; different seeds | complete file-byte map comparison; property tests over 12 seeds |
| Referential integrity/uniqueness/ownership/tenant/chronology | model and graph validators plus negative mutations |
| Effective grants and precedence | independent fixed allow/deny cases and temporal evaluator tests |
| Classification, labels, document versions and hashes | schema, label-set, annotation and latest-version checks |
| Membership/deletion/approval lifecycle | before/after policy cases and all 12 snapshot tests |
| Baseline immutability/scoped idempotent reset | hash manifest before/after; repeat reset and nonowned-path negatives |
| Formula/HTML/untrusted content handling | CSV negative cases; markup escaping; inert unsafe artifact assertions |
| Export manifests/schema/checksums | JSON Schema validation, export and file-map hash checks |
| Idempotent import | repeated real imports with collision checks and native readback |
| Local target/redirect/secret gates | invalid URL/path tests, actual redirect server, private-file/journal tests |
| Native create/read/update/permission subset | separately enabled live integration runs; ordinary accounts for ACLs |
| Honest unavailable outcomes | unavailable adapters are BLOCKED with denominator, exit 2 |
| Offline development | clean core-only dependency installation and no-service test run |

This is engineering verification, not certification or a security assessment. No
formal OWASP AISVS/ASVS identifier mapping is asserted: the named source files are
absent and those published identifiers have not been validated in this task. No MITRE
ATLAS technique number, vulnerability severity, finding or human competence is inferred
from a scenario. Later P-031/P-037/P-091-style connector authorization and retrieval
assessments remain separate independent work.

The advisory lookup is limited to published PyPI release metadata for pinned Python
dependencies (base release metadata for CPU torch); it does not audit container OS
packages, native plugins, malicious packages or all advisory databases. Secret scans
use narrow high-risk patterns, never a claim that no secret or vulnerability exists.
