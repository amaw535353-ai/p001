# Operations and reconstruction

Use the existing checkout and Python 3.12. Never create a worktree unless requested.
`make install` is idempotent for the locked environment; `P004_OFFLINE=1 make install`
uses cached, hash-verified wheels only. Runtime live processes do not survive an
environment snapshot; the local fixture must be started explicitly when needed.
No script modifies P-001–003 infrastructure or approval state.

`make demo-offline` refreshes a deterministic generated P-002 input in ignored
`.runtime/`, then creates a fresh owned run. `make demo-diff` also creates a bounded
base/changed synthetic architecture pair and a delta inside the changed run.
`.runtime/latest-demo.json` gives exact paths. Reports/evidence never overwrite
existing outputs. Use fresh names for repeated explicit CLI commands.

Live context is the schema in `schemas/discovery-policy.schema.json`: engagement,
approved version/digest, actor, tenant, source identity, storage, checkpoint/contact/
redaction assertions. Obtain those from an independently reviewed P-003 store;
do not substitute the invalid example or an exported policy file. Every target
path must be an exact included URL asset with GET allowed, synthetic ownership,
current review and ACTIVE state. A P-003 demo profile name grants nothing.

The separate fixture command emits an ownership manifest with its ephemeral
instance ID and exact local origin/paths. Keep this file private, supply it with
the P-003 context, and stop that process with Ctrl-C when finished. Global HTTP(S)
proxy environment variables cause live observation to refuse. Run the owned
local fixture workflow from a shell without those variable bindings; never
disable TLS checks or alter the platform's system proxy configuration.

Observation uses actual UTC, not the fixed historical P-003 example clock. Expired
fixtures fail. A live refusal still writes a BLOCKED/PARTIAL report and exits 3;
invalid offline input exits 2 (independent valid sources remain in a PARTIAL
report). CLI syntax errors exit 2. Success exits 0. A failed connection consumes
a reserved request attempt conservatively. No automatic retries or automatic
resume after denial occur.

`verify-artifacts` checks ownership hashes and snapshot semantics. These local
manifests are not signed/tamper-proof chains; a local filesystem owner can replace
them. `reset-owned` retains evidence unless `--delete-evidence` is explicitly
given with `--confirm p004-local`, then removes only recorded, hash-matching files.
Unlisted files and other projects remain. Do not use global cleanup tools.

For a clean reconstruction, populate `.runtime/wheels`, create the venv with
`P004_OFFLINE=1 ./scripts/setup`, run `make verify` and the network-disabled demo.
Publication/restoration in a new cloud task has not been independently tested.
