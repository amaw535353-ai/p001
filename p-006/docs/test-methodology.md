# Test methodology

`make test` runs distinct Python assertions with explicitly fake adapter responses and generated
in-memory signing keys. `PYTHONPATH=tests/no-network:src .venv/bin/python -m pytest tests` disables real
sockets/DNS. `make verify` repeats that suite, Ruff, mypy and root unit/static, retaining JUnit and a
summary in a unique ignored reports directory. `make test-live` drives real pinned services and scripted
Open WebUI HTTP OAuth/chat, then tests actual segmentation and owned dependency disconnect/reconnect.
The OPA native binary also evaluates the versioned Rego tests. Fixture results do not certify Keycloak,
Vault, OPA, LiteLLM, the UI or Docker networking. Real model behavior is never assessed by a digest mock.

Each live output contains test IDs, safe observations/statuses, profile hash and unique run ID. Source
policy/config hashes and command outputs are retained separately; the acceptance catalog supplies
preconditions/action/expected result and reproduction command. No raw prompts/tokens/credentials are
exported. A small SHA256 manifest protects result consistency, not provenance/trusted time. P007 remains
the general evidence/reproduction engine; P006 outputs are only local engineering test records.
