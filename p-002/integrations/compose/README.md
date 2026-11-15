# Isolated deployment equivalent to Compose profiles

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

`scripts/lab up nextcloud|redmine|label-studio|p001` implements mutually exclusive,
selectively enabled deployments. No all-services default exists. Actual Docker image
digests are pinned in `src/p002/lab.py` and `images.lock.json`. Each deployment uses
fresh anonymous volumes/container storage, owned labels and an internal network.
The fixed helper makes genuine HTTP requests with redirects disabled, via stdin,
instead of exposing a port that this rootless daemon cannot reliably publish on an
internal network. Direct HTTP adapters accept only their exact loopback URL and require
`--target lab`; they do not turn an arbitrary production URL into a lab target.

No cgroup memory enforcement is claimed. Startup checks available disk for new allocations (8 GiB cold / 2 GiB cached), verifies
ownership and forbids simultaneous unrelated optional labs. Teardown uses exact names
and labels, never global cleanup. See operations for bootstrap, checks and confirmation.
