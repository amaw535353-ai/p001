# Architecture and enforcement ownership

Browser → Open WebUI → P006 PEP → LiteLLM → deterministic local backend.
Keycloak authenticates the human. Open WebUI forwards that human's OAuth access token using its
supported `system_oauth` connection. The PEP verifies RS256/issuer/audience/time/claims, compares
the stable subject, tenant and roles with the server-side registry, and introspects the current
session. It asks the real OPA policy for a fresh decision, reserves bounded user/tenant quotas,
retrieves a gateway credential from Vault through a short-lived AppRole token, and reconstructs
the allowed request. The LiteLLM callback checks that request's timestamp, nonce and HMAC proof.
Only LiteLLM can reach the separately authenticated model backend from the application network.

The mock returns a digest of synthetic messages; it never evaluates a real LLM or tool behavior.
The PEP projects a small known response shape and never forwards arbitrary upstream errors,
metadata, headers, secrets or traces. Audit events contain synthetic stable subject/tenant,
PEP-generated decision ID, policy version, safe model label and reason. Prompts/tokens are excluded.

The Python PEP is necessary because login, a shared gateway key and UI model visibility do not
bind end-user authorization to the actual model/tenant request. OPA owns the policy decision;
the PEP owns enforcement. Vault owns secret ACLs/leases; LiteLLM owns the fixed local routing
with a P006 callback for authentication and proof binding. Rate/quota accounting is at the PEP,
not a claim about unconfigured LiteLLM commercial or distributed budget features.

Diagrams are declarations. Runtime verification is reported separately. See the ten `.mmd` files,
[data inventory](data-flow.md), [boundary matrix](trust-boundaries.md) and [deployment](deployment.md).
