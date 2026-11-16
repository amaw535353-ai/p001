# Framework security requirements and residual limits

Default offline, fixed adapter registry, exact loopback origin/routes, P003 ledger
preflight, effective-destination and peer checks, deny-all redirects, one concurrent
request, and strict payload/path/schema bounds are enforced in code. No privileged
containers, Docker socket, cloud provisioning, eval, shell=True or arbitrary plugin
loading are used. Processes inherit a credential-free environment with fixed tool
paths and timeout/cancellation cleanup. Secrets and raw browser state are not exported.

CPU/file-size resource limits and sampled Linux process-group RSS/CPU/stdout budgets
bound subprocess tools; process groups are killed on exhaustion/cancellation. This
is not a delegated cgroup hard memory fence: brief RSS overshoot is possible, shared
RSS is counted conservatively and tools that detach are outside the supported contract.
The in-process browser path uses tool heap limits, browser timeouts and the guard's
request/time/concurrency caps; no hard browser RSS enforcement is claimed. Use an
isolated, disposable low-privilege host. Unsupported hosts fail rather than gaining
privileges. Full hard-resource isolation is a remaining host-hardening gap.

Evidence paths reject traversal/symlinks, publish atomically and refuse collisions.
The filesystem is a single-user trust boundary, not a defense against a privileged
concurrent attacker replacing parent directories. Cleanup needs explicit confirmation,
verifies ownership and hashes, protects baselines and uses symlink-safe removal.
It never operates on P001-P006 data, arbitrary directories or Docker resources.

The browser sandbox is unavailable on this managed host; the explicit profile is
restricted to trusted synthetic pages fulfilled through the broker. Real credentials,
untrusted browser content, third-party/production targets, destructive testing and
active scans are outside implemented capabilities. Dependency license metadata is
not a security audit. Legal authority, signing identity and human competence remain
unverified; see validation and publication documents.
