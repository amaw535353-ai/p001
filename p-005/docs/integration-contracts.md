# Predecessor contracts and future handover

All adapters are local/read-only. VERIFIED means actual local schema/content
validation and an executed metadata import, never runtime security validation.
CONTRACT_ONLY means a contract exists but this run has not imported an artifact.
NOT_TESTED, BLOCKED and INCOMPATIBLE stay distinct. CLI errors never silently
fall back from malformed or incompatible data.

| Source | Actual interface and safety limit |
|---|---|
| P-001 | Explicit resources.json/bootstrap.json paths; allowlisted kind/name/namespace only; never state, Secrets or live queries |
| P-002 | Actual Dataset validator, fixtures mode only; human/workload/group/resource IDs remain distinct; grants retain declared effects; separate generated oracle records retain expected decisions and untested enforcement |
| P-003 | Actual sealed Engagement validator and verified digest; exact source-ID or exact URL match within the same tenant, exclusions and version/window retained; unmatched assets require new authorization |
| P-004 | Actual Snapshot 1.0 validator plus its architecture digest; source evidence claims and stable IDs retained; endpoints become declared/observed surface strings; unknown zones stay unknown |

P-004 snapshot.json is the aggregate export contract. Its split envelopes are
not separately reconstructed in this release: use the actual snapshot. Raw
observations/passive alerts are not promoted to findings; retain the sanitized
source snapshot to inspect them. A missing snapshot can use an explicit
--fallback-fixture and produces NOT_TESTED. A malformed snapshot is rejected.
Original detailed trust boundary/coverage/observation tables remain in that
source; P-005 derives new candidate crossings with unknown imported zone trust.

P-003 imports context only. No current ledger/revocation check or target-specific
preflight is performed because P-005 never runs live tests. Even accepted plans
need a fresh authorized executor. The supplied P-003 health-only scope does not match the independent reference
fixture. Its matching P-004 declaration can retain modeling scope only; explicit
URL exclusions override inclusion, and tenant mismatches never inherit scope.

`make demo-integrations` runs the real sibling generators/parsers entirely
offline and records `generated/integrations/integration-results.json` with exact
run paths. Per-run status files describe only that run. It is independent of the
baseline fixture run, whose unused predecessors remain NOT_TESTED.

Future consumers P-006, P-007, P-009, P-010 and P-083 should pin schema versions,
verify manifests, keep MODELLED_THREAT/NOT_TESTED distinctions, and obtain human
review plus fresh P-003 scope before any execution. P-091/P-092/P-093/P-099 may
consume the same contracts; none is implemented here. External requirement IDs
remain null/UNMAPPED_PENDING_P083 until a verified requirement catalog is loaded.

P-004 original boundary IDs, coverage and observation status summaries are retained
in source_context. P-002 retains document trust, scenario IDs/states/expectations
and logical time without exporting document bodies. P-003 source_context retains
window, exclusions and activity classes separately from executable authority.
