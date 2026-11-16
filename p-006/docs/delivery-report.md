# P006 delivery report

Repository: https://github.com/amaw535353-ai/p001 (private). Base/default: `p001-initial`.
Initial base `2c2ddfe72cb205c89c7b7b6bf7614008dfb4dcc1`; approved final base
`50a61a883b5f943a7a3cd9a00a8b9b55b1581920`. P008 PR #6 merged while paused; the feature fast-forwarded
to that approved default, preserving P008 without edits. P007 PR #5 was observed MERGED on
2026-11-16 09:55:50 UTC at 2c2ddfe and remains unchanged. Feature branch:
`feat/p-006-secure-llm-reference-architecture`. Final commit/push/merge identity is in Git history and
the accompanying PR; an immutable self-referential commit hash cannot be embedded in this commit.
The user's direct request separately authorizes commit, push and merge. No cloud/provider deployment.

Everything added is under p-006/: typed PEP, JWT/activity verifier, real OPA/Vault/LiteLLM adapters,
request-proof callback, deterministic backend, opt-in weak fixture, pinned Compose/Docker build,
21 strict schemas, realm template, Rego policy/data/tests, fixed gateway routes, 66-case acceptance
catalog, P007 descriptor/response schemas, declared architecture/risk inventory, CLI/setup/cleanup,
90 offline tests, actual integration/egress/fault/comparison probes, ten diagrams, security/operation/
license/limitation matrices and questions-only learner workbook. No sibling source changes.

Actual path: user → Open WebUI → Keycloak Code/S256 PKCE → WebUI system_oauth human bearer → PEP
signature/issuer/audience/registry/activity checks → real OPA decision → narrow Vault AppRole/KV-v2
read → reconstructed request with bound proof → LiteLLM → authenticated deterministic backend →
projected response. Native UI models/access grants are provisioned using a real synthetic platform-admin
OAuth session and supported API. Audit confirmed the ordinary UI user's stable subject at the PEP.
Human and workload identities remain separate; the gateway key never represents the end user.

Versions actually selected/run: WebUI0.13.3-slim, Keycloak26.8.2, OPA1.22.4-static, Vault2.2.2,
LiteLLM1.109.1, Python3.12.14-slim base; Docker29.9.2 rootless, Compose2.40.3, uv0.13.6 on Linux x86_64.
Exact digests: config/images.lock.json. All 39 core wheel versions/hashes: requirements.lock. Installed
metadata includes 40 distributions including pip. Key pins: FastAPI0.163.1, httpx0.28.1, Uvicorn0.54.0,
Pydantic2.12.5, PyJWT2.15.1, cryptography50.0.2, jsonschema4.26.0, PyYAML6.0.3. Product images contain
additional dependencies requiring SBOM/CVE/license review; pins do not certify vulnerability freedom.

Results: 90 socket-disabled offline PASS, no failure/skip; 54 native hardened PASS, zero FAIL and one
P007 BLOCKED; three actual weak/hardened comparison PASS; three native OPA PASS; seven root unit
PASS. Root static, Ruff, mypy, strict schema drift and deployment validation PASS. Exact groups,
observations, hashes and commands: validation-status.md and verification-summary.json. Only the model
backend was mocked. No actual model/provider prompt behavior, AWS or Kubernetes behavior was assessed.

Real OPA default deny/outage enforcement passed. Vault intended/unrelated reads, revocation, outage
without fallback and gateway-key rotation passed; natural expiry/provider-key rotation NOT_TESTED.
LiteLLM approved routing, unknown model/provider restrictions, bypass/proof replay/body substitution
and provider fault/recovery passed. PEP owns the measured local rate/quota/size/concurrency bounds;
no paid/distributed gateway budget claim. Open WebUI login/chat/model/admin/function restrictions
passed. Keycloak logout/deactivation passed with the native kc-admin-api scope/audience enabled.
The actual weak fixture trusted tenant/model metadata; hardened server enforcement rejected it.

Measured UI/gateway/weak namespaces had no IPv4 default route and denied an unapproved reserved
external address. Host bindings were loopback-only but unreachable on this managed rootless host:
interactive browser access is BLOCKED. Scripted internal real-app HTTP/OAuth tests succeeded.
P007 descriptor validates against its unchanged schema, but native adapter is hard-coded unavailable
and v1 cannot express READY: live P007 integration BLOCKED. Sibling matrix preserves actual P001–P008
interfaces; P004/P005/P008 native imports and future P009/P010 consumption remain NOT_TESTED.

The proposed 37-row risk matrix is architecture-derived relevance, not a source-defined formal P006
risk mapping. Missing source risk definitions from the P005 subset remain missing/NOT_TESTED. This
reference alone does not assess all risks; specialist projects retain their ownership and scope.

Host: three logical CPUs, roughly 9.7 GiB Docker memory, 63 GB disk. Full UI layers exhausted vfs
storage; the exact task-pulled unused full image was removed and official slim was pinned. Automatic
approval review rejected a broad cache-deletion proposal; no such cleanup was performed. Both proxy
case variants are cleared inside offline services; per-role read-only mounts/private bootstrap IPC
handle rootless subordinate UID access. No privileged containers, Docker socket mounts, public-network
attachments, host firewall change, global prune or real cloud access was used.

Residual risks: local HTTP, development identity and in-memory single-node Vault, trusted operator/
PEP/host, process-local quota/replay state, writable upstream startup roots, no complete image/CVE/SBOM/
license audit, no other-host or graphical-browser assessment. WebUI branding and Vault BSL terms are
retained; LiteLLM image bundles separately licensed components. Production TLS/HA/mTLS/recovery,
distributed controls and independent review require separate work. Resource estimates are not proven
minimums. See dependency-and-license-inventory.md, limitations.md and the NOT_TESTED gate list.

Actual cleanup removed P006 containers/networks and runtime credentials/state, verified six retained
evidence artifact hashes, and preserved the P001 image ID unchanged. Runtime/tools/venv/evidence/reports
remain ignored; only reviewed code/templates/schemas/synthetic public identities/docs and sanitized
summaries are committed. Historical failures are retained locally, not rewritten as PASS. Source
hashes exclude documentation to avoid self-reference. Exact changed-file inventory is the PR diff.

Manual work: on a host supporting internal-network loopback publication, run setup/doctor/validate/up,
then make test-live. Explicitly opt into weak mode before make compare-live. Review production controls,
browser behavior, image licenses/CVEs and a separate P007 adapter revision. Personally reproduce and
defend G1–G5 before changing NOT_DEMONSTRATED labels. Workbook: docs/learner-workbook.md, questions only.
Codex implemented/tested; human independent reproduction and external human review NOT_DEMONSTRATED.
No additional approval is needed for the requested commit/push/merge; platform/contract blockers stay explicit.
