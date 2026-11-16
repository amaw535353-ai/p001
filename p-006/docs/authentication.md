# Identity and session model

Dedicated realm `p006`; human client `open-webui`; introspection client `p006-pep`; synthetic
operator client `p006-operator` is held outside application containers and can manage only this
realm's fictional user lifecycle. At least two users and one tenant administrator per tenant,
plus a separate platform administrator, are defined in `config/hardened.json`.

Authorization Code + S256 PKCE; no password grant; exact loopback callback/origin; no wildcard.
No realm self-registration. OIDC provisioning is restricted to this closed realm and its explicit
client roles. No account merge by email. Email is display/SSO provisioning data, never a PEP identity.
A randomly credentialed bootstrap UI account prevents Open WebUI's upstream first-user admin
promotion from granting the first ordinary SSO user administration. Password login/API keys are disabled.
The bootstrap identity is synthetic and its credentials are not printed or committed.

Trusted claims: `sub` stable registry ID; `iss` exact loopback realm; `aud` PEP; `azp` open-webui;
`tenant` and `p006_roles` equal the server registry; `exp`, `iat`, `nbf`, `sid`, `jti` required.
Keycloak's explicit mapper supplies `nbf=0`; token lifetime still has strict expiry and issued-at
validation. Access lifetime 120 s; refresh reuse revoked, idle 300 s, maximum realm session 600 s;
UI JWT lifetime 5 m. Refresh tokens stay encrypted in UI memory-backed state. The PEP introspects
every request and caches no active/session decision. Keycloak outage denies safely.

JWKS is fetched only from the configured internal endpoint; fixed issuer/audience; RS256 only;
RSA >=2048 bits; reject untrusted key URLs/headers. 30 s key cache; unknown key can trigger refresh
at most once per 2 s; no stale-key use after a required refresh fails. Existing known keys can be
used inside the documented cache interval, but token activity is independently rechecked online.
Key rotation outside that interval fails closed. Distributed key/session availability is outside this lab.

Loopback HTTP uses HttpOnly and SameSite=Lax cookies without Secure. TLS, Secure cookies, reverse
proxy validation, CSRF/session fixation browser assessment and federation require a separate deployment.
See actual logout/deactivation observations in validation status; unit fixtures alone prove neither.

Keycloak 26.8 administrative tokens explicitly request the assigned optional `kc-admin-api` scope.
Its native mapper supplies the realm Admin API audience. The ordinary user client does not receive
that scope; admin API audience checks stay enabled. Native deactivation and logout were verified.
