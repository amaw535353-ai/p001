# Vault lifecycle and ACLs

Non-dev Vault server with in-memory storage, one-share local initialization and TLS disabled only
on the isolated synthetic bridge. Root and unseal material exist only in the transient bootstrap
process, then root is revoked. They are never written to disk or exported. This is not production
Vault: durable encrypted storage, TLS, HA, audit devices, recovery, seal design and operator separation
remain outside scope.

KV v2 `p006/data/gateway` contains independently generated dummy gateway and provider keys.
`p006-pep` and `p006-gateway`: read only this path and revoke-self. `p006-rotator`: read/create/update
only this path and revoke-self, held by local operator. `p006-unrelated`: only revoke-self, cannot read
credentials. AppRoles have no default policy; 60 s tokens, 60 s max; SecretIDs expire after 1 h.
Application reads log in, verify the expected policy/lease, read one path and revoke-self. There is
no secret cache/fallback. Expired SecretID requires a fresh local stack bootstrap and fails closed.

Bootstrap AppRole credentials travel through a captured private IPC pipe with container logging
disabled. The operator writes them into host-private `.runtime/` (0700). Individual 0755 role directories
and 0444 files permit subordinate UIDs under rootless Docker to read direct read-only mounts; the host
parent prevents other host users traversing those paths. Only the intended role directory is mounted
into each service. Never relax the host parent or bind the whole runtime tree into applications.

Live rotation uses CAS to update the gateway key; PEP and callback read the new Vault version on the
next request. Provider-key rotation needs a coordinated backend key update and gateway restart and
is NOT_TESTED, not an automatic feature. Never return gateway/provider values to the UI. Narrow secret
scanning has a disposable planted-marker negative control; it is not a complete DLP/vulnerability scan.
