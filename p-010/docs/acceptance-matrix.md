# P-010 acceptance matrix

The brief defines 118 requirements. Evidence describes the layer each case exercised.
The engineering test count also includes parameterized regressions.

| Category | PASS | PARTIAL | NOT_TESTED | Total |
| --- | ---: | ---: | ---: | ---: |
| Repository and ownership | 10 | 0 | 0 | 10 |
| Canonical schemas and provenance | 10 | 0 | 0 | 10 |
| P-003 and P-005 | 9 | 1 | 0 | 10 |
| P-006 to P-009 | 11 | 1 | 0 | 12 |
| Finding lifecycle | 12 | 0 | 0 | 12 |
| Severity and risk | 12 | 0 | 0 | 12 |
| Evidence | 10 | 0 | 0 | 10 |
| Redmine | 10 | 0 | 0 | 10 |
| OSCAL and ATLAS | 10 | 0 | 0 | 10 |
| Langfuse and privacy | 9 | 0 | 1 | 10 |
| Report, audit and retention | 12 | 0 | 0 | 12 |
| Overall | 115 | 2 | 1 | 118 |

[Machine-readable requirements, evidence and status](../data/acceptance-matrix.json)

| ID | Status | Verified evidence or gap |
| --- | --- | --- |
| A01 | PASS | test_delivery: approved base ancestry and live git ls-remote |
| A02 | PASS | test_delivery: scope check and staged diff |
| A03 | PASS | test_delivery: sibling trees and staged diff |
| A04 | PASS | Clean initial git status and branch switch from approved tip |
| A05 | PASS | Direct user authorization for commit, push and merge. Local Redmine fixture only |
| A06 | PASS | test_delivery: git check-ignore and staged inventory |
| A07 | PASS | test_sources: actual sibling schemas and contracts |
| A08 | PASS | Current P-006 hardened/profile/inventory and merged validation inspected |
| A09 | PASS | test_delivery: missing P-009 input is explicit. The approved contract present |
| A10 | PASS | Root make unit and make static |
| B01 | PASS | test_workflow: engagement roundtrip |
| B02 | PASS | test_workflow and test_delivery: unknown fields and schema closure |
| B03 | PASS | test_workflow: ID, digest, UTC, enum and integer constraints |
| B04 | PASS | test_sources: provenance envelope |
| B05 | PASS | test_sources: exact raw and schema hashes |
| B06 | PASS | test_sources: absent source commit and source timestamp |
| B07 | PASS | test_sources: distinct original/import clocks |
| B08 | PASS | test_sources: protected fixture bytes and mtime |
| B09 | PASS | test_sources: incompatible P-003, P-007, P-008 and P-009 versions |
| B10 | PASS | test_sources: transformation version and exact report manifest links |
| C01 | PASS | test_sources: approved actual engagement |
| C02 | PASS | test_sources: scope, window, ROE, evidence policy |
| C03 | PASS | test_sources: expiry, revocation, before window and historical context |
| C04 | PASS | test_sources: training notice and non-bearer caveat |
| C05 | PASS | test_sources: reject P-003 draft under official AP schema |
| C06 | PASS | test_sources: actual P-005 model |
| C07 | PASS | test_sources: exact hypotheses and IDs |
| C08 | PASS | test_sources: source NOT_TESTED and refusal of executed claims |
| C09 | PARTIAL | test_sources: risk provenance and rule/review fields. Upstream ATLAS association validation remains partial |
| C10 | PASS | test_workflow: a versioned hypothesis alone cannot confirm |
| D01 | PASS | test_sources: actual P-006 profile and inventory |
| D02 | PASS | test_sources: proposed applicability and architecture limitations |
| D03 | PASS | test_sources: actual P-007 ReportExport |
| D04 | PASS | test_sources: P-007 handoff version and provenance mismatch |
| D05 | PASS | test_sources: original results and allowed runner metadata |
| D06 | PASS | test_sources: parent, absolute, noncanonical and symlink refusal |
| D07 | PARTIAL | test_sources: byte-verified manifest fixture. Original published run absent |
| D08 | PASS | test_workflow and demo: P-007 FAIL remains unconfirmed |
| D09 | PASS | test_sources and demo: actual P-008 exporter output |
| D10 | PASS | test_sources: 48 aggregate, 38 non-sealed, 10 omitted |
| D11 | PASS | test_sources: private prompt omission and prohibited row keys |
| D12 | PASS | test_sources and demo: P-009 v1 and exact native exporter fixture joins |
| F01 | PASS | test_workflow: evidence-linked candidate transition |
| F02 | PASS | test_workflow: source fail and observation do not create finding |
| F03 | PASS | test_workflow: role-gated independent review |
| F04 | PASS | test_workflow: empty and placeholder rationale rejected |
| F05 | PASS | test_workflow: inactive scope refusal |
| F06 | PASS | test_workflow: distinct false-positive disposition |
| F07 | PASS | test_workflow: distinct inconclusive and not-reproducible states |
| F08 | PASS | test_workflow: threat metadata cannot be direct evidence |
| F09 | PASS | test_workflow: supporting trace evidence cannot confirm |
| F10 | PASS | test_workflow: supporting alert metadata cannot confirm |
| F11 | PASS | test_workflow: audited revisions |
| F12 | PASS | test_workflow: retrieve previous version after edits |
| R01 | PASS | test_workflow: exact rubric digest |
| R02 | PASS | test_workflow: severity requires rationale |
| R03 | PASS | test_workflow: unknown dimensions or low evidence yield UNRATED |
| R04 | PASS | test_workflow: confidence and severity independent |
| R05 | PASS | test_workflow: upstream failure independent from finding state |
| R06 | PASS | test_workflow: technical/business explanation preserved from author |
| R07 | PASS | test_workflow: rubric suggestion has no finding effect |
| R08 | PASS | test_workflow: override preserves rating and suggestion |
| R09 | PASS | test_workflow: explicit applicability rationale |
| R10 | PASS | test_workflow: unknown taxonomy or missing basis refused |
| R11 | PASS | test_workflow: accountable decision separate from selected treatment |
| R12 | PASS | test_workflow: owner, version, scope and expiry gate |
| E01 | PASS | test_workflow: exact reproduction source ID |
| E02 | PASS | test_workflow and test_sources: no verified metrics for reference-only bytes |
| E03 | PASS | test_sources: size and digest tampering |
| E04 | PASS | test_sources: missing artifact unavailable |
| E05 | PASS | test_workflow: required expected/observed preconditions and steps |
| E06 | PASS | test_sources and demo: read-only source bytes, no source runner invoked by P-010 |
| E07 | PASS | test_workflow: explicit excerpt selection and redaction |
| E08 | PASS | test_workflow: evidence appendix limitations |
| E09 | PASS | test_workflow: hash limitation statement |
| E10 | PASS | test_workflow: modified package and record chain rejected |
| M01 | PASS | verify-redmine.py: isolated native start and cleanup |
| M02 | PASS | verify-redmine.py: native issue count stays zero during dry run |
| M03 | PASS | verify-redmine.py and test_redmine: idempotent and lost-reply cases |
| M04 | PASS | verify-redmine.py and test_redmine: exact issue readback and binding |
| M05 | PASS | verify-redmine.py: actual native read-only account cannot create |
| M06 | PASS | test_redmine: outage, ownership and malformed listing |
| M07 | PASS | verify-redmine.py: edited issue preserved and retry refused |
| M08 | PASS | test_redmine: remote closure leaves canonical finding unchanged |
| M09 | PASS | test_redmine: invalid destination and exact write confirmation |
| M10 | PASS | test_redmine and native fixture: ignored secrets, private container tokens, exported field inspection |
| O01 | PASS | test_frameworks: five byte-pinned official schemas with release identity |
| O02 | PASS | test_frameworks: actual official Assessment Results schema and linked local context |
| O03 | PASS | test_frameworks and demo: labelled missing-context mapping draft |
| O04 | PASS | test_sources: reject P-003 draft promotion |
| O05 | PASS | test_frameworks: structured validation assurance limitation |
| O06 | PASS | test_frameworks: exact ATLAS version, digest, source commit and IDs |
| O07 | PASS | test_frameworks: technique identity, evidence and reviewed acceptance |
| O08 | PASS | test_frameworks: mapping leaves finding unchanged |
| O09 | PASS | test_frameworks: unresolved historical reference retained |
| O10 | PASS | test_frameworks: explicit unsupported framework fields |
| L01 | NOT_TESTED | Native Langfuse service unavailable for P-010 in this delivery. The endpoint contract double passed. |
| L02 | PASS | test_frameworks: reference-only default and unavailable profile status |
| L03 | PASS | test_frameworks and test_sources: omit prompts, completions and arbitrary response content |
| L04 | PASS | test_frameworks and Git inventory: no hosted client, Langfuse keys private |
| L05 | PASS | test_workflow and demo: secret canary not exported |
| L06 | PASS | test_workflow and demo: PII canary redacted |
| L07 | PASS | test_frameworks: active Markdown/HTML syntax neutralized |
| L08 | PASS | test_workflow and test_sources: field allowlists, prohibited fields refused |
| L09 | PASS | test_workflow: simulated redaction gate failure blocks approval |
| L10 | PASS | test_workflow: manifest includes privacy policy version |
| Q01 | PASS | test_workflow: unresolved content and review block approval |
| Q02 | PASS | test_workflow: every confirmed example has reviewer and inspected evidence |
| Q03 | PASS | test_workflow: severity rationale and rubric required |
| Q04 | PASS | test_workflow: reports retain NOT_TESTED and other coverage limits |
| Q05 | PASS | test_workflow: generated summary uses typed counts and supplied narrative |
| Q06 | PASS | test_workflow: narrative and review provenance |
| Q07 | PASS | test_workflow: approval lease and independent attributed reviewer |
| Q08 | PASS | test_workflow: approved historical versions protected |
| Q09 | PASS | test_workflow: audit mutation or missing version detected |
| Q10 | PASS | test_workflow: eligible scope and atomic retention, source bytes unchanged |
| Q11 | PASS | verify-redmine.py and test_redmine: label-scoped cleanup and sibling inventory |
| Q12 | PASS | test_workflow and test_redmine: source preservation and no Redmine deletion operation |
