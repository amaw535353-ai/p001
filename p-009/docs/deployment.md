# Local deployment

Test target is Linux x86_64, Python3.12.14, Docker29.9.2 rootless and Compose2.40.3. The observed
host has 3 Docker CPUs, 9.7GiB Docker-reported memory and a 63GB disk with the slow `vfs` driver.
The task parent cgroup is actually limited to 8GiB. Docker statistics share that parent and do
not independently establish per-container enforcement. The file-descriptor limit is 16384.
Check `make doctor`
before heavy profiles. Core requires approximately 2GiB/3GB free; staged Langfuse budgets at least
7GiB Docker memory and 10GB free before image expansion. These are guardrails, not proven minimums.

`scripts/setup` installs the hash-locked Python environment using task-local uv caches. Docker
build copies that verified Linux/Python3.12 environment and owned source/config into a pinned Python
base; it performs no package network installation. Rebuild after code/dependency changes. The
application image is a local build, not a remote published artifact.

Run core first, then staged native checks. All resources carry `io.p009.owner=p009`; collisions
with unowned names fail. Full Wazuh indexer/dashboard startup is blocked by this host's kernel
prerequisite; no sysctl, privileged container or public network is introduced. Other operating
systems/architectures, graphical UI, Kubernetes and cloud deployment are NOT_TESTED.
