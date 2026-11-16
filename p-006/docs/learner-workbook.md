# Independent competency challenges — questions only

All G1–G5: NOT_DEMONSTRATED. Record your own evidence and defend conclusions before marking a gate.
Use separate provenance labels: Codex implemented; Codex tested; Human independently reproduced;
External human reviewer verified. Generated artifacts never complete a human challenge.

## G1 — Architecture understanding
Draw and explain the complete Open WebUI → Keycloak → PEP → OPA → Vault/LiteLLM → model flow.
Where are the trust boundaries, secrets, identities, assumptions and failure modes?

## G2 — Identity and authorization
Independently test token validation, tenant/role boundaries, identity propagation, logout/deactivation,
direct gateway bypass and policy outage. Which component enforces each decision? What evidence
would distinguish configured policy from a request actually denied by that policy?

## G3 — Secrets and gateway
Inspect Vault ACLs, leases, revocation, rotation, routing, provider/model restrictions and network
egress. How can you demonstrate that secrets never reach browser responses or retained logs?
Which rotation and rate-limit claims remain unverified or limited by the single-process design?

## G4 — Comparison
Reproduce an isolated weak-profile scenario, retest the hardened control, capture evidence, explain
residual risk, and defend why the two observations support your conclusion. Can the weak profile
be accidentally selected or exposed? How would you establish that experimentally?

## G5 — Consultancy delivery
Prepare and defend scope, architecture, trust boundaries, methodology, findings, impact, evidence,
remediation, retest, limitations and recommendations. Which statements need human review? What
would be necessary to extend this local demonstration to a production architecture?
