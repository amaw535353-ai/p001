# Operations and troubleshooting
Use scripts/install before lab-up. Binaries live in .tools/bin; lifecycle scripts set
PATH explicitly. Wheel downloads use the host's verified TLS trust, then Docker builds
offline with --require-hashes. This avoids importing host proxy trust into images or
disabling certificate verification. No secrets enter build context (.dockerignore).

If doctor reports real credential/profile bindings, open a clean shell or unset the
reported names without printing their values. Providers have fixed emulator endpoints.
LocalStack host URL is 127.0.0.1:4566; pods use its Kubernetes service DNS, never localhost.

**Observed blocker:** kind v0.33.0 rejects this host: `running kind with rootless
provider requires setting systemd property "Delegate=yes"`. Official rootless guide:
https://github.com/kubernetes-sigs/kind/blob/v0.33.0/site/content/docs/user/rootless.md
Use a compatible, user-administered Docker host. Any systemd/cgroup changes require
separate host authorization; the scripts do not elevate or bypass compatibility checks.
Mac/WSL2 Docker VM configuration is untested. No host support is inferred from binary download.

Inspect .runtime/forward-*.log for forwarding failures; namespaces/pods via dedicated
kubeconfig. Do not dump process environment, kubeconfig credentials or raw state.
Port collisions fail closed. Re-running lab-up reconciles owned resources only.
Calico node daemonset must be ready before workload deployment; test actual denials.

lab-down deletes only the owned named kind cluster and local state/forwarders; images
and shared Docker network/cache remain. Never prune globally. Smoke fallback resources
are separately named/labelled and removed in a finally block. On an interrupted smoke,
inspect ownership labels before manually removing only those exact resources.

A clean cluster rebuild is BLOCKED here. On a compatible host run
`make lab-rebuild-verify`; preserve its evidence and separately record the lifecycle
exit status. No retained live process is assumed to survive cloud snapshot restore.

OpenTofu 1.13.9 unconditionally shims HashiCorp lock entries to its default registry
in memory. With explicit registry.terraform.io sources, -lockfile=readonly then
reports changes even when normal init reproduces identical lock bytes. scripts/tofu-init
runs signed provider initialization and enforces exact before/after lock equality,
restoring and failing on any change. This was tested against the actual lock; it does
not alter expected checksums or bypass provider signature verification.

LocalStack DNS, telemetry and test-certificate download are explicitly disabled with
supported config flags (DNS_ADDRESS=0, DISABLE_EVENTS=1, SKIP_SSL_CERT_DOWNLOAD=1).
The lab uses HTTP on its local-only boundary; no artifact/TLS verification is disabled.

Docker injects proxy configuration into new containers on this host. SDK and mock
HTTP clients explicitly bypass ambient proxies only for their hardcoded local targets.
No external endpoint is accepted. The fallback uses docker exec HTTP probes because
internal networks do not publish ports on this rootless daemon; host port-forward
behavior still requires Kubernetes verification. Startup detects exited containers.
Read-only source is copied into the image with explicit readable permissions for UID
10001. Rootless Docker's cgroup driver is none here: container resource flags alone
are not evidence of enforced resource bounds.
