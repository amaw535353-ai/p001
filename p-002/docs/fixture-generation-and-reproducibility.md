# Generation and reproducibility

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Default seed `2026`, clock `2026-01-15T12:00:00Z`, schema `1.0`, generator `1.0.0`.
All timestamps are UTC; validity starts `2026-01-01` and normally ends `2027-01-01`.
The logical clock is independent of the wall-clock execution timestamps in evidence.
No UUIDs or runtime timestamps enter baseline fixture serialization. Scenario snapshots
have independent run UUIDs and are outside the byte-repeatability claim.

| Profile | People / department | Documents / department | Activation |
|---|---:|---:|---|
| tiny | 3 | 4 | default-safe |
| standard | 6 | 10 | default-safe |
| stress-local | 24 | 80 | `--allow-stress` required |

The six departments and two tenants are fixed. Distributions are deliberately
structured: role mixes, a terminated user per department, four classification values,
three document kinds, task labels and skewed remainders. Size is bounded by the three
presets; no unlimited record-count switch exists. Actual timing, RSS and output sizes
are recorded in the validation report. No generation mode needs a GPU or paid API.

`reproducibility.json` lists every export hash, content-root hash, dataset hash, seed,
clock, profile, mode, library and generator version, and source/config code fingerprint.
The root hashes the sorted filename -> SHA-256 map; the manifest excludes itself.
The ownership marker is outside that map and is checked independently. Validation
rejects extra files, symlinks, damaged files, duplicate IDs and inconsistent graphs.
Repeat generation compares complete file byte maps in tests; another seed must change
the dataset while retaining invariants. Runtime logs, secrets and native instance IDs
never enter deterministic exports.

Optional SDV Community 2.2.0 uses its current `Metadata.detect_from_dataframes`,
`GaussianCopulaSynthesizer`, dictionary-of-DataFrames `fit`/`sample` API, and only
self-created invoice amount seed rows. Numerical values are bounded and rounded;
request parameters and approval hashes are rebound deterministically. All identity,
tenant, grant, document and delegation structure is fixed. The report records seed
input hash, generated table/field, row count, distribution and corrections. Only
schema/statistical consistency is claimed for SDV; no privacy/anonymity guarantee.
SDV is **BSL 1.1 source-available**, subject to its Additional Use Grant, not an
unqualified open-source service license. See the official-source inventory.
