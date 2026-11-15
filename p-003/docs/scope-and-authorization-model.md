# Model, provenance and approval binding

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

Strict frozen Pydantic models reject extra fields and coercions. They cover Client,
Engagement, Actor, Asset/Selector, Scope, ROE, EvidencePolicy, ReviewEvidence,
Authorization, Amendment, ExceptionRecord, StopEvent, Decision and Event. Published
JSON Schemas cover these artifacts and the complete preflight input. YAML is an
alternate serialization of the same schema, not a separate permissive model.

Top-level artifacts have schema_version, stable UUID or event UUID, source, author,
reviewer distinction, UTC timestamp, synthetic classification, notice and SHA-256
content_digest. Canonical JSON is UTF-8, sorted keys, compact separators, no NaN.
The digest excludes only its own content_digest field. Nested artifacts have their
own digests. `sealed(Model, **fields)` is a builder API; loading never silently fixes
an existing digest. JSON Schema validates shape; typed validation additionally
checks actual dates, referential integrity, role separation, pinned framework text,
canonical targets and digest correctness. `verified()` requires a nonempty seal.

A full immutable engagement specification describes scope and policy. Runtime status,
approval, stops, supersession and history derive from events. Approval records bind
the exact engagement/version/digest, full named targets, activities, window and
review-evidence file hash. A simulated review fixture records fictional claimed
authority and an explicitly simulated checklist, never a legal signature or a
verified human. The approve command requires separate explicit --simulate-review,
--scope-digest and --evidence-ref arguments after submission. Evidence modification
(including whitespace), deletion, an old review file or wrong actor denies.

Requestor, assessor, reviewer and owner use four distinct references per engagement.
References cannot be shared across created engagements. CLI reads/mutations filter
by those labels; the OS user can assert any label. This is not authenticated tenant
isolation. No real or non-local engagement mode is implemented.
