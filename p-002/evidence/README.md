# Execution evidence

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Actual run JSON files are excluded from Git. `make test` records each pytest result;
`p002 adapters verify` and `scripts/integration-test` record actual HTTP outcomes.
`make evidence` lists artifacts and SHA-256 values. UTC execution time is not the
fixture logical time. Each result carries precondition, expectation, observed result,
command, versions, commit, uncommitted source hash, evidence path and blank human verifier.
Generated oracle decisions are stored separately and never counted as observed native
permissions. Failed runs are retained rather than rewritten after corrections.
