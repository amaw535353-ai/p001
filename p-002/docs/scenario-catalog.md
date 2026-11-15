# Scenario catalog and stages

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

The strict versioned JSON files in `config/scenarios/` are the catalog source of truth.
They specify assets, clock, starting entitlements, boundary, assumptions, mutations,
positive/negative oracle expectations and stop/reset behavior. Unknown operations or
extra fields are rejected; YAML is deliberately unsupported, never evaluated.

| ID | Prepared business case | Risk numbers from supplied request | Opt-in inconsistent artifact |
|---|---|---|---|
| S01 | Department collaboration positive control | 3 | No |
| S02 | Cross-tenant read/update boundary | 35 | No |
| S03 | Peer department with known resource ID | 3,35 | No |
| S04 | Membership revocation timeline | 3 | No |
| S05 | Deleted source and stale derived index | 3,13 | Yes |
| S06 | Service delegation scope and expiry | 1,2 | No |
| S07 | Exact invoice approval binding | 2,7 | No |
| S08 | Inert lower-trust instruction text | 5 | Yes |
| S09 | Derived citation/provenance conflict | 13,19 | Yes |
| S10 | Confidential synthetic canary | 4 | No |
| S11 | Private ticket and attachment metadata | 3,35 | No |
| S12 | Derived annotation divergence | 19,26 | Yes |

Risk wording/crosswalk references were not attached; numbers are not a claim of
validated taxonomy semantics. P-002 prepares data for later assessment. There is no
automatic exploit, RAG query, connector sync, payment, exfiltration or remote tool call.
For integrity cases, the measurable result is an intentionally different derived
artifact while canonical hashes/annotations remain unchanged; an access verdict alone
would not demonstrate that integrity property. Lifecycle tests assert the discrepancy.

PREPARED means a design/fixture exists. SEEDED means a named owned snapshot was made.
EXECUTED means an authorized test was actually run. OBSERVED requires recorded actual
behavior. ASSESSED requires independent human analysis; RETESTED requires an actual
human-verified follow-up. The generator moves only PREPARED -> SEEDED. It never fills
human finding, remediation, retest, residual risk or verifier fields.
