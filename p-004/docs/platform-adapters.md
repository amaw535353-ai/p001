# Actual adapter contracts

| Adapter | Input and tested behavior | Limits |
|---|---|---|
| P-001 | Actual bootstrap/resources.json, app.py and lab-up declarations; Kubernetes service selectors, service accounts, RBAC/policy digests; reviewed lab API/mock/store/log relations | No runtime IAM, CNI, auth enforcement or full lifecycle claim |
| P-002 | Actual Dataset.model_validate plus seed-2026 tiny generator; tenant/user/workload/resource/grant graph | Intended grants/oracle only; no native platform ACL verification; names reduced to synthetic IDs |
| P-003 | Actual Engagement/verified document import and Store.replay/evidence + policy.evaluate on read-only ledger | Approval created outside discovery; legal authority/actor authentication unverified |
| Onyx #1 | p004-architecture-v1 local reviewed source manifest, optional OpenAPI through generic importer | Samples are contract-only; no installed version, edition, route, connector or permission enforcement invented |
| OpenHands #2 | Same explicit local manifest contract; agent/tool/sandbox facts must cite source | No agent tool/shell execution; container declaration never proves sandbox isolation |
| Playwright #145 | Explicit fail-closed entry point and synthetic traffic fixture | Live browser BLOCKED pending a separate network sandbox; no auth state/HAR/screenshots stored |
| ZAP #62 | Strict p004-zap-passive-import-v1 contract; sanitized p004-zap-alerts-v1 provisional observations | NOT a runnable AF plan; ZAP live NOT TESTED; no invented scanner/rule version |

`fixtures/static/{onyx,openhands}.contract.json` intentionally contain no invented
vendor API paths. A supplied local manifest may record inspected edition/version
and source references; defaults remain NOT VERIFIED. Do not promote fixture
observations to real platform evidence. No optional application's large dependency
stack starts by default.

For IaC, only `p004-reviewed-iac-v1` with `reviewed: true` and a strict architecture
projection is accepted; raw tfstate/outputs are rejected. The review marker is an
operator assertion, not proof of review. `.env.example` values are discarded;
dependency declarations and Dockerfiles are parsed without evaluating build steps.
