# Threat rules and DSL

The canonical reviewed rule pack is rules/core.json, byte-equivalent as data to
the packaged rules.json. No executable plugin or expression interpreter exists.
Custom --rules accepts the same bounded v1 DSL; --suppressions accepts rule IDs
with a scope-specific justification of at least eight characters.

| Rule | Trigger predicates (all) | Prompt references |
|---|---|---|
| identity-audience | edge.token_audience eq MISMATCH | R1 |
| broad-delegation | edge.delegation eq BROAD | R1 |
| tool-authority | edge.kind eq executes; target.features.privileged_actions eq True; edge.authorization ne CONTROL_DECLARED | R2 |
| cross-tenant | cross_tenant eq True | R3, R35 |
| sensitive-audit | edge.classification in ['CONFIDENTIAL', 'RESTRICTED']; target.kind in ['TelemetrySink', 'Browser'] | R4 |
| indirect-prompt | source.features.untrusted_content eq True; target.kind in ['Retriever', 'Agent', 'LLMGateway', 'ModelEndpoint'] | R5 |
| goal-drift | source.features.autonomous eq True; edge.kind in ['delegates', 'executes'] | R6 |
| approval-integrity | edge.kind in ['approves', 'executes']; edge.approval_binding ne DECLARED | R7 |
| unsafe-output | source.features.generates_content eq True; target.features.privileged_actions eq True | R8 |
| coding-workspace | target.features.coding_workspace eq True | R9 |
| mcp-boundary | source.kind eq Agent; target.kind eq MCPServer | R10 |
| persistent-memory | target.features.persistent_memory eq True | R11 |
| direct-instructions | target.kind eq Agent; source.kind in ['API', 'Browser', 'HumanIdentity'] | R12 |
| retrieval-integrity | target.kind eq VectorDatabase; edge.kind in ['stores', 'writes'] | R13 |
| provider-routing | target.kind in ['LLMGateway', 'ModelEndpoint'] | R14, R15 |
| budget-exhaustion | target.kind in ['Agent', 'ModelEndpoint', 'MCPServer']; target.features.budget ne DECLARED | R18, R37 |
| a2a-scope | target.kind eq A2APeer | R20 |
| evaluation-data | target.kind eq Evaluator; source.features.untrusted_content eq True | R21 |
| monitoring-gap | target.kind in ['Guardrail', 'TelemetrySink']; target.features.logging ne DECLARED | R22 |
| retention-isolation | target.kind in ['DataStore', 'DocumentCollection', 'Memory']; target.features.retention ne DECLARED | R24, R35 |
| stale-grants | edge.grants_freshness eq STALE | R3, R35 |
| dependency-origin | target.kind in ['MCPServer', 'Tool', 'CIPipeline']; target.features.dependency_provenance ne DECLARED | R36 |
| network-egress | target.features.egress eq True |  |

`all` must match; empty `any` imposes no additional condition; nonempty `any`
needs at least one match; any matching `exclude` suppresses the rule. Required
evidence is a modeled flow with provenance. Preconditions, falsifier, target
behavior, impact assumption, mitigation and positive/negative designs are all
in the rule record and fact trace. An expected DENY is a design expectation;
a cross-tenant hypothesis is not an observed authorization bypass.

Tests exercise positive/negative fixtures, absent features, suppression reasons,
rule-injection rejection and semantic integrity. GPU/hardware systems are absent
and never invented. New features require deliberate fixtures, rules and tests.
