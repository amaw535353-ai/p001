Security checks live in scripts/run-checks.py and the container fallback. NETWORK
requires successful same-tenant requests and timeout-denied cross-tenant and mock
egress routes using numeric Pod IPs. Manifest presence is insufficient. The fallback
validates application authorization and real S3 flows, not Kubernetes controls.
Dedicated secret/vulnerability scanners are optional and currently NOT TESTED;
static-check includes only narrow secret patterns and structural/schema/shell checks.
