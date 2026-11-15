# Engineering test results

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

The final actual command report is recorded after implementation validation. See
evidence/engineering-*/manifest.json and evidence/demo-*/manifest.json, ignored local
artifacts with real statuses, timestamps, commands, tool versions and hashes. The
handoff section below is populated only from the executed runs, not anticipated
results. Earlier development failures (requirement-ID pattern, Unicode OSCAL regex
support, missing literal export notice) were diagnosed and corrected; they are not
claimed as passed runs.

Scope: governance mechanics and offline source/data contracts. Live Redmine,
independent human assessment, real legal authority, external execution-tool compliance
and P-003 runtime Kubernetes enforcement are not established by these tests.


## Final observed run, 2026-11-15 UTC

- P-003 pytest: **163 passed, 0 failed, 0 errors, 0 skipped**.
- Lint, format, type check, pip dependency consistency: **PASS**, all exit 0.
- Foundation regression: `make unit static` **PASS**, 7 unit/HTTP tests plus structural/narrow-secret checks.
- Complete CLI demonstration: **23/23 expected command outcomes**, including explicit simulated approval, positive/negative decisions, exports, amendment, suspension, archive/reset and reconstruction.
- Fresh wheel/venv reconstruction outside the checkout: **17/17 expected command outcomes**, installing dependencies with hashes and `--no-index`, then the actual built wheel.
- P-001 declarative source adapter and P-002 validated-data adapter: actual sibling tests **PASS** within the 163-test suite. No live target claim follows.
- Optional Redmine: stub contracts **PASS**; live instance **NOT TESTED**, loopback probe connection refused (curl exit 7 / HTTP 000). No token was requested or printed.
- OSCAL: labeled draft **REJECTED by the official 1.2.3 AP schema as expected**, not valid OSCAL.
- P-001 cluster runtime under P-003: **NOT TESTED**; existing foundation host limitation is rootless Docker without delegated cgroups. No deployment attempted.

| Run | Actual local evidence | File SHA-256 |
|---|---|---|
| engineering | `evidence/engineering-1794740097436678242/manifest.json` | `4ab5d5b1214c95c650c1233c400e2f3958fd8d49be05474c72e1e1f6e3c7ec6b` |
| demo | `evidence/demo-1794740098873216472/manifest.json` | `88520b384e47ff8f3d42b983b7bdd7e493b309a770ebee07cc7dbf6898fc9fa4` |
| reconstruction | `evidence/reconstruction-1794740097526750796/manifest.json` | `8cac12e9663e86c42857d3381eaf880e2cab0c549bd0024319daab076c4215db` |

Tested source/schema/test/script/example manifest SHA-256:
`f172b5b1662897d9de441810272b3dba508fb34da95f7673e6ed5ad41771ee9e`.
Seed-42 engagement fixture file SHA-256:
`9409b5f4dddd2b055cc62cefd93a93b6fb95f5daf4e77a46fa2d85d9ff162734`.
The final source manifest was compared byte-for-byte against the current code files
and matched. Manifest source identity is the base Git HEAD plus this code hash;
validation preceded the P-003 local delivery commit.

Exact commands (working directory `/workspace/p001/p-003`, unless stated):

```bash
./scripts/setup
./scripts/verify.sh
.venv/bin/python scripts/demo-workflow.py
.venv/bin/python scripts/clean-reconstruction.py --offline
# Root regression, also run by verify:
make -C /workspace/p001 unit static
```

The verifier's nested commands, working directories, underlying exit codes, bounded
excerpts and tool versions are in the engineering manifest. Python 3.12.14,
P-003 1.0.0, Pydantic 2.12.5, PyYAML 6.0.3, jsonschema 4.26.0, regex 2026.11.9,
pytest 9.0.3, Hypothesis 6.151.9, Ruff 0.15.6 and mypy 1.19.1 were executed.
Dependencies and licenses are inventoried in dependency-inventory.json; the complete
lock SHA-256 is `8a7b13fde41138a6abd173c818446630aad6684a0ea18bcdf7d09ae9b378e255`.

Sanitization evidence: known-secret input rejection and safe error/export tests
passed; Markdown active HTML is escaped; generated plans label results unverified;
all training samples carry the synthetic warning. Root narrow-secret scanning passed.
These controls are not comprehensive PII/DLP detection. Review contents and private
state remain ignored rather than committed. Vendored official whitespace is preserved
for exact source hashes via narrowly scoped .gitattributes entries.

No learner competency, legal authority, true signatory identity, trusted real usage
telemetry, actual DNS ownership or external execution-tool enforcement was verified.

Final staged sanitization/scope review: **PASS**, 98 P-003-only files. Evidence: `evidence/final-review-1794740446762366460/manifest.json`; file SHA-256 `948b5dac2da97d6436c43ec0812c7092cac77c17cf84b434e18d241485f37305`. No private state was staged.
