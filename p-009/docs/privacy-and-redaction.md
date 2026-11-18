# Metadata-first privacy

Allowed runtime classes are PUBLIC_SYNTHETIC, SYNTHETIC_SECURITY_METADATA and
SYNTHETIC_TRACE_METADATA. RESTRICTED_RUNTIME_SECRET credentials and SENSITIVE_SOURCE_REFERENCE
content are excluded from the normal demonstration and Git.

The SDK disables prompt/completion capture at source; its guarded exporter fails closed on
content attributes or canary-bearing metadata. Collector transforms allow only explicit IDs,
safe event types and decision metadata; they remove span names/status text, log bodies and
unapproved attributes before batching/export. Archive normalization omits non-contract fields
before queueing and validates the remaining metadata. Debug/content opt-ins are not enabled.

Tests plant access tokens, cookies, provider/Vault keys, prompts, completions, synthetic PII,
private-key markers and raw bodies. Permitted identifiers containing suspicious values cause
refusal, not a redaction that could disguise an outcome. Counters and policy versions remain.
P008 evaluator content/config and all sample rows are omitted. Untrusted tenant/actor/severity
values never become identity. Pattern checks complement allowlists and do not certify arbitrary
real-world data as de-identified; the system is for synthetic sources only.
