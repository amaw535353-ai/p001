# Open WebUI integration

Pinned upstream release, unmodified UI/branding. The `system_oauth` connection in upstream
`backend/open_webui/utils/headers.py` obtains the user's stored/refreshable OAuth access token.
The PEP validates that actual Keycloak token. Plain forwarded user/tenant headers are disabled
and explicitly rejected. A shared application key is never accepted as end-user identity.

OIDC runs against the fixed internal discovery endpoint with dynamic Keycloak backchannel URLs;
browser issuer/callback URLs remain exact loopback URLs. A scripted HTTP flow follows real login
forms and the real OAuth callback using only two fixed origin translations inside the trusted tester.
It does not bypass state, code, client secret or PKCE checks and does not insert a fabricated UI session.
A separate graphical browser assessment is NOT_TESTED. Runtime results decide whether system_oauth
worked; a configuration entry alone never establishes it.

Self-registration/password login, API keys, direct connections, Ollama, user model configuration,
functions/tools/skills access, web/code execution, file/web uploads and external connectors are disabled
by default for ordinary users. Admin APIs still require native admin roles. PEP also rejects tools,
provider URLs, identity metadata and oversized/unsupported request fields on direct calls.
No gateway or Vault secrets are configured in the UI. OAuth client secret/UI signing key stay server-side.

Startup uses a real platform-admin OAuth session to create the two fixed model records through the
native API. local-basic has authenticated-user read access; local-admin remains owner/admin only.
The ordinary-user model list and chat path are tested after these native grants exist.
