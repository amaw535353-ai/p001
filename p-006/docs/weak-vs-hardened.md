# Controlled comparison

`INTENTIONALLY INSECURE — LOCAL SYNTHETIC LAB ONLY`

The weak fixture intentionally trusts X-Tenant-ID and permits any synthetic model label without
server authorization. It returns a fixed synthetic response, has no Keycloak/Vault/provider credentials,
and never executes a tool or calls an external backend. Explicit CLI confirmation plus a separate
Compose profile are required. Its UI and health/response repeat the warning. It lives only on its
internal weak bridge with a loopback publication.

W01: caller selects tenant-b/local-admin in the weak fixture and receives a labelled synthetic response.
W02: same header is rejected before hardened identity use; a valid Tenant A token on Tenant B path is
independently denied by real OPA/PEP. P03 separately denies normal user/local-admin. W03: default startup
omits weak service; factory/CLI reject missing opt-in. W04: hardened engine refuses weak configuration.
`make compare` is an in-process comparison; native-profile outcomes appear separately in live evidence.
The weak fixture is a deliberately limited comparison service, not an entire insecure copy of all five
products. The hardened real-product integration is the architecture target.

After explicitly starting the weak profile, `make compare-live` performs the actual container comparison
and tests the weak namespace routing table/blocked off-network destination. `make compare` remains
the independent in-process regression comparison. Neither command enables the weak profile.
