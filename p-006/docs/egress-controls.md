# Network enforcement and listener inventory

Every declared Docker network is `internal: true`; no internet-enabled attachment, host networking,
privileged container, NET_ADMIN capability, Docker socket or host firewall change. UI: only ui and
identity bridges. PEP: ui, identity, policy, secrets, gateway. OPA: policy only. Vault: secrets only.
LiteLLM: gateway, secrets, model. Backend: model only. Weak service: its own isolated weak bridge.
The trusted ephemeral tester joins all networks only for explicit operator checks and is never a
default service. Network membership is validated against the strict profile.

Host publications are only 127.0.0.1:8086→WebUI, :8087→Keycloak and opted-in :8088→weak UI. PEP8080,
OPA8181, Vault8200, gateway4000, backend8000 are internal. Control API authentication remains necessary
within each shared bridge. This is segmentation by network membership, not a claim of per-port mesh ACLs.

Live tests inspect the actual routing table, attempt a connection to a reserved off-network address,
and check UI reachability to allowed PEP/identity and denial to OPA/Vault/gateway/backend. This proves
the tested network namespace's absent default route and denied paths, not every host/DNS covert channel.
No public internet scanning is performed. Host port publishing may be suppressed by rootless Docker
on internal networks; a configured loopback publication is not proof a browser can reach it.
Kubernetes NetworkPolicy and AWS egress are NOT_TESTED. See current validation results for runtime scope.
