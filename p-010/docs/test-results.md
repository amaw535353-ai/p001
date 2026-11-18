# Verification transcript

The following were executed with Python 3.12.14 inside the managed
Linux workspace.

| Command or check | Observed result |
| --- | --- |
| `./scripts/setup` | 24 hash-locked packages, installation succeeded |
| `uv pip check --python .venv/bin/python` | All 24 packages compatible |
| `make verify` | 31 schemas match, Ruff and mypy pass, 163 tests passed with sockets and DNS disabled |
| `make demo` | Deterministic review-ready training report, 25 gates, canary check passed |
| `p010 demo --p008 … --p009 … --events …` | Actual upstream synthetic handoffs import, 38 non-sealed rows, 10 omitted, five P-009 event references |
| `PYTHONPATH=src .venv/bin/python scripts/verify-redmine.py --confirm p010-owned-resources` | Native Redmine created/read back issue 1, repeat unchanged, update reused issue 1, reader denied, conflicting edit preserved, owned cleanup passed |
| `make unit` at repository root | Seven tests passed |
| `make static` at repository root | Structural and narrow secret checks passed |

The closed failure of the initial Redmine readback was caused by
CRLF normalization. Retrying with normalized readback reconciled the
existing issue without a second POST. A subsequent clean deployment and
native verification passed. The OSCAL validator rejected an incorrect
`control-id` target during development. The verified version uses a
catalog and AP-selected statement ID. No native Langfuse pass is claimed.
