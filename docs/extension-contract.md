# Extension contract — not deployed now
Reserve independent modules, namespaces, states and opt-in profiles for P-002–P-010,
P-091, P-092, P-093 and P-099. Do not silently expand P-001 scope.

Adapters should accept an explicit local URL, correlation ID, tenant context and
request budget, with fail-closed endpoint configuration. Keycloak may replace test
bearers after token issuer/audience verification is designed. OpenFGA/OPA may attach
an authorization decision boundary. RAG attaches tenant-labelled synthetic stores;
MCP servers and model gateways attach through explicit egress policies and separate
service accounts. Telemetry must use an allowlisted schema with no prompts/secrets.
Additional assessment namespaces need independent default-deny policies, quotas,
fixtures, cleanup ownership and positive/negative tests. No adapter inherits IAM
federation, tenant authorization or network trust merely by joining the cluster.
