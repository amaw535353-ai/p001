# Operations

Verified host: Linux x86_64, Python 3.12.14, Node 24.22.1. No GPU, Docker or model
key is required. Other operating systems/architectures are NOT_TESTED. Initial
dependency installation needs package-registry access; evaluation/demo/tests can
then run offline. uv is the setup prerequisite; no global pip/npm installation is
performed. `./scripts/setup --tools` installs only under P-008-owned directories.
The supported installation is the documented editable source checkout; resources
and source digests are intentionally repository-relative. A relocated standalone
wheel is not a supported distribution in this version. A second Git worktree or
remote clone was not created. A clean source reconstruction from the approved
base Git archive plus the delivered patch passed fresh setup, 78 offline tests
and the full demo with an identical dataset manifest. A separate fresh core-only
environment also reproduced the demo without sibling installations.

Core Pydantic 2.12.5 remains compatible with actual sibling schemas. Inspect AI's
newer requirement is isolated in `.tools/venv`; never change root/P-007 locks to
resolve it. Node must satisfy the recorded Promptfoo engine. Package scripts are
disabled during npm installation. Tool workers set owned XDG/config/cache paths;
read-only home directories are supported.

An existing frozen version/draft/run is never overwritten. Use a new dataset
version or `make demo` for an isolated fresh child registry. Preserve the previous
baseline. A reproduction drift error requires restoring the recorded sources and
lock, not silently editing the manifest. Missing tool/provider or native output
is BLOCKED, never PASS. Inspect mock outputs include zero token usage to prevent
its tokenizer from acquiring a remote encoding.

Run/report paths are in the CLI JSON output. Treat `.runtime/` as private: it has
sealed labels, local dummy secrets and raw tool observations. `.tools/`, caches,
artifacts and reports are ignored. Only a nonbaseline owned run can be cleaned
with the documented confirmation. Do not use global cleanup. No command pushes,
publishes or creates a pull request.
