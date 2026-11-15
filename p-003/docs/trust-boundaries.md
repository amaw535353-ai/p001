# Trust boundaries

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

| Boundary | Untrusted input | Guard | Residual risk |
|---|---|---|---|
| Client draft -> models | Claimed owner, scope, purpose | Strict schema, synthetic-only mode, digests | Claim truth is human-verified |
| Actor label -> workflow | --actor string | Role/client filtering | OS user can impersonate labels |
| Review file -> approval | Checklist and evidence bytes | Exact version/hash, separate action | File author is not authenticated |
| Ledger -> evaluator | Event sequence and status | Replay, role/digest checks, transaction | Store owner can rewrite whole history |
| Target text -> scope | URLs/IPs/selectors | Offline conservative canonicalization | Actual network ownership unverified |
| P-001/P-002 -> draft | Inventory and synthetic context | Source/data validation; proposal only | No live target assertion |
| Redmine -> governance | Issue statuses and text | Tracking-only; no approval importer | Redmine notifications/permissions external |
| Export -> future runner | Snapshot with approval | Explicit non-capability warning | Runner may ignore it or replay stale output |
