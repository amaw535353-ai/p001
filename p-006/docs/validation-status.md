# Validation status — 2026-11-16 UTC

Codex implemented/tested; synthetic local reference, not production certification.
[Reviewed machine-readable summary](verification-summary.json) includes actual test IDs, observations,
commands, source/config/policy hashes and cleanup evidence. Historical failures/blocked runs remain
under ignored evidence/; they were not overwritten.

| Layer | PASS | FAIL | BLOCKED | NOT_TESTED | INCONCLUSIVE |
|---|---:|---:|---:|---:|---:|
| tests.test_config | 28 | 0 | 0 | 0 | 0 |
| tests.test_enforcement | 38 | 0 | 0 | 0 | 0 |
| tests.test_identity | 19 | 0 | 0 | 0 | 0 |
| tests.test_weak | 5 | 0 | 0 | 0 | 0 |
| Actual hardened integration | 54 | 0 | 1 | 0 | 0 |
| Actual weak/hardened comparison | 3 | 0 | 0 | 0 | 0 |
| Native OPA assertions | 3 | 0 | 0 | 0 | 0 |
| Root unit assertions | 7 | 0 | 0 | 0 | 0 |

Offline total: **90**, with sockets/DNS disabled. Fixtures are not native proof and counts are not
combined across layers. Ruff, mypy, schema drift, strict profile/deployment checks and root
`make unit static` passed on approved base 50a61a8 with P008 preserved. No sibling source was changed.

All five products actually ran: Open WebUI0.13.3-slim, Keycloak26.8.2, OPA1.22.4, Vault2.2.2,
LiteLLM1.109.1. P006 Python services ran. The backend alone was deterministic/mock; no actual model,
paid provider, AWS or Kubernetes security behavior was evaluated.

U01/U02: real Open WebUI Code/PKCE login, native model records/access grants, ordinary model listing
and chat succeeded. Sanitized PEP audit confirmed Ben's stable subject across the UI path. A11/A12:
real Keycloak logout/deactivation denied previously issued tokens. The operator needs the native
kc-admin-api scope and audience in Keycloak26.8; audience checks stay enabled.
P03/P04/P05/P06/P09/P10: actual model/tenant/admin/bypass/proof replay/substitution denials passed.
V02/V03/V04/V06: narrow/unrelated Vault ACLs, revocation and gateway-key rotation passed. P07/V05/L07:
actual dependency disconnects denied safely, and fresh requests succeeded after reconnection.
N01–N06: measured routing/reachability/loopback bindings passed. UI, gateway and weak namespaces
had no IPv4 default route and denied a reserved unapproved off-network connection. Actual weak W01
trusted the synthetic tenant/model header; hardened W02 denied it, and the warning was displayed.

Separate environment gates: all three configured host loopback publications (8086/8087/8088) were
**BLOCKED** on this managed rootless internal-network host. Scripted real application/OAuth HTTP tests
ran inside the isolated network; no graphical browser result is claimed. P007 descriptor validation
passed, but its actual adapter is hard-coded unavailable and v1 cannot express READY: live integration
is **BLOCKED**. No P007 source/schema/status was changed to hide that limitation.

Gate A architecture: PASS for declared/observed path. B identity: PASS for actual scripted UI/API.
C authorization: PASS. D secrets: PASS for tested ACL/read/revocation/gateway rotation; natural expiry
and provider-key rotation NOT_TESTED. E gateway: PASS for measured local controls. F egress: PASS for
measured Docker IPv4 scope, no cloud/Kubernetes claim. G application: PASS for measured OAuth/chat/
admin/function/model flow; graphical browser behavior NOT_TESTED. H comparison: PASS. I P007:
descriptor PASS, live BLOCKED. J deliverables: implemented; independent consultancy/production
readiness and human competency NOT_DEMONSTRATED.

Other NOT_TESTED gates are enumerated in the JSON and limitations. G1–G5 and external human review
remain NOT_DEMONSTRATED. Cleanup removed all owned P006 containers/networks and runtime credentials;
six retained artifact hashes verified. P001 image remained unchanged. Tools/reports/evidence stay ignored.
