# State transitions and amendments

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

| Event | From | To | Required fictional role |
|---|---|---|---|
| create | absent | DRAFT | requestor |
| submit | DRAFT | SUBMITTED | requestor |
| approve | SUBMITTED | APPROVED | separate reviewer + exact simulated evidence |
| activate | APPROVED | ACTIVE | owner; valid review, contact and both windows |
| reject | SUBMITTED | REJECTED | reviewer |
| suspend / revoke / close / expire | any nonterminal current version | SUSPENDED / REVOKED / CLOSED / EXPIRED | owner, reviewer or assessor |
| amend | DRAFT/SUBMITTED/APPROVED/ACTIVE | new DRAFT; old SUSPENDED | requestor; old digest parent |
| approve new version | new SUBMITTED | new APPROVED; prior SUPERSEDED | fresh reviewer evidence |

A stop is immediate and permanently prevents resume/amend/activation of that
engagement in this conservative implementation. Start a distinct engagement for a
new human-reviewed exercise. REJECTED, REVOKED, CLOSED and EXPIRED are terminal.
All edits, including reductions, require a new version and fresh approval. Pending
amendments pause the previous scope. Scope, targets, techniques, authorizer, windows
and policy changes cannot reuse an approval. Exceptions are modeled as denied
requests for a new version; there is no bypass API or high-impact activity mode.

Time windows are half-open [start,end), strict timezone-aware UTC represented with
Z. Invalid dates, other offset forms and backdated ledger events are refused. Policy
checks also deny before activation, outside windows, or after a current stop even
when a caller supplies a historical request time. No scheduler changes state to
EXPIRED: clock-based denial applies regardless of a stale ACTIVE display; explicit
expire records an auditable lifecycle event. Demos use a fixed 2026-11-15 UTC clock.
