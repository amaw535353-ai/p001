# Proposed applicability — not source-defined risk mapping

P006 is foundational and does not assess all 37 risks. Full source taxonomy was not supplied; this matrix
uses only the explicitly labelled P005 subset and preserves missing risk names. Specialist assessments
remain in their dedicated projects.

| Risk | Available description | Proposed relation | Technical rationale |
|---|---|---|---|
| R1 | Workload identity confusion, wrong token audience, over-scoped delegation | DIRECTLY_APPLICABLE | Human/workload identity, audience and role/tenant enforcement. |
| R2 | Tool-level unauthorized external actions / confused deputy | SUPPORTING_ONLY | Architecture enforcement and bounded fixtures support later specialist assessments; no full risk evaluation. |
| R3 | Cross-tenant RAG/document retrieval | PARTIALLY_APPLICABLE | Tenant isolation applies; no RAG/document retrieval implementation exists. |
| R4 | Synthetic secrets or sensitive values in responses, logs and traces | DIRECTLY_APPLICABLE | Narrow Vault retrieval, safe errors and secret-free projected responses/events. |
| R5 | Low-trust retrieved document/tool output influencing high-privilege action selection | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R6 | Autonomous goal drift | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R7 | Approval-to-action integrity/replay | PARTIALLY_APPLICABLE | Request proof resists replay/body substitution; no human approval platform assessed. |
| R8 | Unsafe downstream handling of AI-generated commands or HTML | SUPPORTING_ONLY | Architecture enforcement and bounded fixtures support later specialist assessments; no full risk evaluation. |
| R9 | Coding-agent workspace boundaries | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R10 | MCP trust boundaries | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R11 | Persistent memory manipulation | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R12 | Direct instruction boundary issues where a model exists | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R13 | Retrieval metadata/ranking/corpus integrity boundaries | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R14 | Provider gateway, cache, inference API and routing access controls | DIRECTLY_APPLICABLE | Model/provider allowlist and authenticated gateway request path. |
| R15 | Provider gateway, cache, inference API and routing access controls | DIRECTLY_APPLICABLE | Fixed local inference route and bypass prevention; no cache platform assessed. |
| R16 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R17 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R18 | Rate/token/tool-budget exhaustion | DIRECTLY_APPLICABLE | Bounded size, timeout, concurrency and local user/tenant budgets. |
| R19 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R20 | Inter-agent/A2A message authenticity and scope | OUT_OF_SCOPE | No corresponding specialist feature is implemented or assessed by this local reference. |
| R21 | Evaluator data trust | SUPPORTING_ONLY | Architecture enforcement and bounded fixtures support later specialist assessments; no full risk evaluation. |
| R22 | Guardrail/monitoring limitations | SUPPORTING_ONLY | Architecture enforcement and bounded fixtures support later specialist assessments; no full risk evaluation. |
| R23 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R24 | Retention, privacy and user/tenant isolation assumptions | DIRECTLY_APPLICABLE | Tenant isolation and ephemeral synthetic retention; production privacy unassessed. |
| R25 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R26 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R27 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R28 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R29 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R30 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R31 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R32 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R33 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R34 | SOURCE UNAVAILABLE | NOT_TESTED | Full source risk definition absent from supplied repository subset; no invented name or mapping. |
| R35 | Stale authorization inheritance and tenant isolation assumptions | DIRECTLY_APPLICABLE | Fresh introspection and request-bound decisions; no stale authorization cache. |
| R36 | Agent skill/plugin and model/data dependency provenance | PARTIALLY_APPLICABLE | Pinned artifacts/locks and disabled tools; complete supply-chain attestation/CVE review not performed. |
| R37 | Cascading recovery/kill switches | DIRECTLY_APPLICABLE | Dependency outages deny without permissive recovery/fallback. |
