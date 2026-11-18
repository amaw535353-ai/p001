# Audit and integrity

Canonical records and audit writes use one SQLite transaction. An
event includes sequence, previous event digest, time, actor, operation,
rationale and old/new version references where applicable. Verification
checks the hash chain, sequence and record/version coverage. Changed
bytes or a missing retained version fail verification. Complete
privileged rewriting and database rollback remain detectable only
with a separately held checkpoint. Reports record dependency hashes
and their own file digests.
