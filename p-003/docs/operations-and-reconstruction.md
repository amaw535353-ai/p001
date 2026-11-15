# Operations, clean reconstruction and recovery

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

Use the existing checkout; no worktrees unless explicitly requested. scripts/setup
creates p-003/.venv, installs the binary wheel hash lock and editable package, and
runs pip check without changing sibling manifests or lockfiles. Core policy, demos,
exports, tests and schemas need no services after installation. No privileges, GPU,
SSO, AWS account, real client credential or model endpoint are needed.

Run scripts/build-contracts.py to deliberately regenerate schemas and deterministic
JSON draft fixtures after a model change. JSON Schema cannot express every domain
constraint; always also use typed validation. The generated YAML example must remain
semantically equal to the JSON version. Tests exercise both formats.

scripts/demo-workflow.py uses a fresh owned .runtime store and unique generated/
output directory, so repeated runs preserve prior evidence. It performs separate
explicit fictional submit/approve/activate operations and records their real CLI
statuses, then tests amendment, stop, archive and clean reconstruction. Reset only
archives a validated owned store. It neither deletes the archive nor tears down
another project's resources. Local SQLite corruption fails closed: preserve the
store for review, use a separately initialized store, and never rewrite hashes to
claim old evidence was authentic.

No process is retained by default. Optional Redmine must be separately provided;
P-003 does not deploy it or rebuild foundation infrastructure. Live cluster tests
remain outside P-003. Installation supports the pinned Linux x86_64/Python 3.12
wheel platform; other platforms require a separately reviewed lock.
