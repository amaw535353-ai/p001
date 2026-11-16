# Policy rationale and matrix

Read [authorization](authorization.md). Positive cases: registered user/local-basic; tenant-admin
own operation; platform-admin own platform operation/local-admin. Negative cases: empty input,
unknown subject, wrong tenant, tenant-resource mismatch, unknown role/model/action/provider,
inactive session, over-quota, wrong client/classification/policy version. The registry is immutable
for a running container; a policy/data change requires review, validation, native Rego tests and retest.
No permissive policy fallback, stale authorization cache, UI-only enforcement or wildcard model rule.
