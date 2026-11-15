# Evidence, retention and sanitization

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

Only minimal fictional fixtures belong in Git. Review evidence, SQLite stores,
tokens, generated exports, run manifests and JUnit are ignored. Stores require 0700
and files use 0600 where they hold audit/review state. Symlink paths are refused for
input/output/store access. Exports are restricted to the component generated/
directory and refuse overwrite. Reset archives the complete owned store under its
parent; no unrelated deletion, Redmine deletion or infrastructure teardown exists.
Do not reset while another process is using that store.

EvidencePolicy specifies synthetic-only classification, storage IDs, access roles,
retention days, redaction, deletion instructions, incident notification and custody
references. Deletion/notification are human procedures, not automatic outbound tasks.
The demo policy uses 30 days and private storage. A data breach, missing contact,
redaction failure or unapproved storage makes the decision DENY.

Decision logs contain references, reason codes and request digests rather than raw
request/evidence bodies. CLI validation failures omit original values because
Pydantic error strings may echo input. Known private-key/token patterns are rejected;
this is a narrow gate, not a complete DLP or PII detector. Arbitrary real personal
names cannot be inferred from text; users must keep actual data out.

Event content digests cover canonical JSON, not file whitespace. Review evidence
additionally uses file-byte hashes. Manifest entries use explicitly labeled content
or file hashes. Markdown footer hashes bytes before its separator. Run evidence
includes actual command exit status, code/fixture/lock/source hashes and tool
versions. Hash equality is not a human witness or legal chain of custody.

Unknown or missing engagement requests still receive a sanitized DENY audit under
the reserved P003-UNBOUND ledger reference. Raw identifiers/bodies are omitted.
Without an independently retained chain head, an owner capable of replacing the
whole database can also truncate or reconstruct its history. The local hash chain
does not solve that trust problem.
