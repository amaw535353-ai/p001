# Operations and troubleshooting

Use Python 3.12 on Linux. `./scripts/setup` installs the core from hash-locked wheels
and local sibling projects. `--tools` additionally installs optional runners; Java 21,
Node >=22.22 and the reviewed Chromium profile are needed for all gates. Default
commands need no Docker, Kubernetes, AWS, GPU, account or model key. P001's rootless
kind/cgroup limitation is unchanged and no Kubernetes result is inferred here.

After populating local wheel caches, `P007_OFFLINE=1 ./scripts/setup` reconstructs
the core without downloads. A fresh offline host must receive those reviewed caches
separately. The npm/archive optional installation path also needs its caches; default
CI installs core only and cannot prove optional vendor gates by skipping tests.

`make run` defaults to offline-demo. Use README commands for tool profiles. Network
runners without `--local-demo`, exact target, actual P003 and lease remain BLOCKED.
The demo's reviewer is simulated, not human. Active ZAP always refuses: there is no
compatible active activity in P003 and no enforced per-rule scanner request ceiling.

Missing executable/version/browser is BLOCKED. Timeout/provider/missing observation
is INCONCLUSIVE. Doctor discovers packages and executable versions; it is not proof
of browser or scanner execution. Chromium version mismatch requires a reviewed profile,
not automatic fallback. Sandbox-disabled mode is documented for this host only.
ZAP uses pinned add-on syntax, silent operation and a fresh private home per run.

Source drift blocks reproduce. Use recorded source/lock hashes, an appropriate
revision and original fixtures, then generate a new run. Hash verification failure
must be investigated rather than rewriting a baseline. Reports preserve failed,
blocked, flaky and inconclusive cases. Cleanup is deliberately confirmed and scoped.
Interrupted partial runs are not valid evidence; inspect the owned runtime locally
instead of treating an absent manifest as a pass.
