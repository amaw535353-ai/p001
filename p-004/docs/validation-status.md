# Actual validation — 2026-11-15

P-004 offline core and guarded synthetic local HTTP are working. The full project
remains **PARTIALLY IMPLEMENTED** because optional browser/ZAP/vendor/cluster live
gates below are unmet. A COMPLETE individual offline run does not mean all project
integration gates are complete.

## Executed checks

| Working directory / exact command | Actual outcome |
|---|---|
| p-004: `P004_OFFLINE=1 make install` | PASS; repeat editable install from hash-verified local wheel cache, pip check clean |
| p-004: `make verify` | PASS; all 7 recorded command groups exit 0 |
| verification pytest | **128 PASS, 0 FAIL, 0 ERROR, 3 SKIPPED** |
| verification lint / format / mypy / schema drift / pip check | PASS |
| repository root: `make unit static` | PASS; 7 foundation unit/HTTP tests plus static checks |
| p-004: `PYTHONPATH=tests/no-network .venv/bin/python -m pytest tests -m 'not local_network' --junitxml=.runtime/offline-pytest.xml` | **118 PASS, 3 SKIPPED, 10 DESELECTED**, exit 0; Python socket/DNS denied |
| p-004: `PYTHONPATH=tests/no-network .venv/bin/python scripts/demo.py --diff` | PASS; real P001/P002/P003 offline imports and controlled delta |
| installed entrypoint / doctor / inventory / graph / report / diff / correlate / retained reset | All 8 operator checks exit 0; graph/memo bytes match generated exports |

Counts are separate executions, not additive coverage totals. The 10 deselected
cases in the offline-only command are the guarded loopback cases executed in the
complete suite. Three skipped cases are live Playwright (BLOCKED), installed ZAP
(NOT TESTED) and live Kubernetes (BLOCKED). Onyx/OpenHands vendor APIs remain NOT
TESTED; their contract/absence tests passed, which is not a vendor integration pass.
Refusal cases intentionally produce CLI exit 3; partial/invalid offline inputs
produce exit 2 in tests. No unresolved test failures remain.

## Actual files and hashes

- Engineering evidence: `evidence/engineering-1794745220729844686/manifest.json`.
  It records exact commands, current JUnit counts, versions, input/code hashes and
  underlying exit codes. JUnit: same directory's `pytest.xml`.
- Successful real-P003 local HTTP report: same directory's `local-http-run/`.
  This is a disposable synthetic loopback observation, not a client engagement.
  The fixture has been stopped. P003 decisions and the sanitized endpoint are
  retained; response bodies, cookies and raw headers are not.
- Aggregate operator evidence: `evidence/delivery-summary.json`.
- Offline report: `reports/demo-1794745109021761928-A/report.md`.
- Diagram: same run's `architecture.mmd`; snapshot, strict JSON envelopes,
  assessment record and source/output hashes are alongside it.
- Offline architecture digest:
  `5049ef276590240c089c031ddbc85cd9ed712bb84748bf0c59988aebdd669ed7`.
- Actual inventory: **157 assets, 13 endpoint method keys, 52 flows,
  49 candidate trust crossings**. These are known synthetic/declarative source
  counts, not a percentage of an unknown attack surface or confirmed controls.
- Controlled diff: `reports/release-diff.json`; baseline/changed source runs are
  `reports/demo-1794745109021761928-baseline` and `...-changed`. One new telemetry
  asset is an inventory addition; unchanged entities also have explicitly labeled
  provenance-only changes because the controlled source file/hash changed.
- Correlated mixed evidence run: `reports/correlated-release/`; separate origins
  stay separate. Both this and the offline run verified 14 owned output hashes.

The engineering manifest hashes files present when verification ran. This status
document and delivery-report.md were finalized afterward from recorded results;
they are descriptive handover, not additional executed tests. Tested source,
schemas, fixtures and scripts were rechecked against the manifest hashes.

## Verified versions and remaining gates

Python 3.12.14; p004 1.0.0; Pydantic 2.12.5; PyYAML 6.0.3; jsonschema 4.26.0;
pytest 9.0.3; Hypothesis 6.151.9; ruff 0.15.6; mypy 1.19.1. Dependency license
metadata and license-file hashes for 27 installed distributions are in
`dependency-inventory.json` (runtime packages MIT; Hypothesis MPL-2.0; regex
Apache-2.0 AND CNRI-Python; inspect all metadata/files before redistribution).

P001: static source only in this module. P002: real generator/validator. P003:
real ledger/review/evaluator with synthetic review transitions and actual guarded
HTTP tests. Playwright's adapter is disabled, ZAP's real process/importer is absent,
Onyx/OpenHands interfaces are contract-only, and Kubernetes live inventory is
disabled. Independent browser containment, a version-verified ZAP passive-only
implementation, vendor-specific interfaces and a reviewed namespace identity need
separate implementation/verification. Merely supplying a setting does not enable
the disabled browser/cluster entry points.

Remote CI, publication and reconstruction in a fresh cloud task are NOT TESTED.
No push, commit, automatic approval, paid service or real AWS action occurred.
G1–G4 remain NOT DEMONSTRATED. See verification-matrix.md for all 35 requested
scenario mappings and known-limitations.md for the full claim boundaries.
