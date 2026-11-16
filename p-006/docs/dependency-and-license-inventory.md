# Dependency and license inventory

| Core technology | Selected release | License and limitation |
|---|---|---|
| Open WebUI | 0.13.3 official slim | Open WebUI License; branding restrictions retained, review upstream terms before redistribution |
| Keycloak | 26.8.2 | Apache-2.0 |
| OPA | 1.22.4 static | Apache-2.0 |
| HashiCorp Vault | 2.2.2 | Business Source License 1.1; do not assume unrestricted hosted commercial service rights |
| LiteLLM | 1.109.1 | OSS MIT portions; enterprise subtree/add-ons have separate terms; no commercial feature claim |
| Python base | 3.12.14 slim | PSF plus Debian distribution packages; inherited transitive licenses need review |
| P006 PEP/callback/mock | 1.0.0 | Repository licensing applies; no independent licensing certification |

Exact image digests: config/images.lock.json. Core Python versions/hashes: requirements.lock.
Installed name/version/license metadata: python-dependencies.json (metadata can require manual review).
Packages are justified for typed request contracts, HTTP/JWT cryptography, API serving, YAML/schema validation
and engineering checks. No sibling generator/runner/identity provider is reimplemented.

Upstream release commits and configuration source anchors are retained in source-verification.json.
Version existence and hash pinning do not establish vulnerability freedom or supported interoperability.
No complete CVE/container dependency/license audit or signed provenance verification was performed;
these remain NOT_TESTED/REVIEW_REQUIRED. Product images include additional upstream dependencies not
covered by the core wheel lock; record image IDs/digests and obtain vendor SBOMs before production use.
