# Limits and residual risks

Local synthetic reference, not production certification. No real model, RAG corpus, autonomous agent,
external provider, client data, paid service or AWS resource is used. No complete prompt-injection,
model-behavior, billing, browser exploit or production penetration assessment is claimed.

Loopback HTTP, Keycloak start-dev/in-memory lab state, single-node Vault with TLS disabled and one-share
bootstrap, local writable upstream UI/identity startup roots, temporary generated file credentials,
single-process quotas/nonce state and Docker bridge trust are deliberate lab limits. Compromised PEP
or Vault read identity can impersonate requests at the gateway; host/operator is trusted. Proxy, TLS,
HA, durable audit, mTLS, distributed budgets/replay and independent review require separate work.

UI-specific refresh/logout/cookie behavior needs actual tests and browser retesting; a PEP introspection
check does not invalidate all upstream UI screens. Provider-key rotation and natural token expiry are
separate from tested gateway-key rotation and token revocation. No complete image/CVE audit has run.

The full supplied 37-risk taxonomy and source tool crosswalk were not attached; P005 includes only a
labelled subset and missing entries. Proposed relevance preserves that uncertainty and never invents
missing risk descriptions or a formal source mapping. P007 still hard-codes P006 unavailable and its v1
descriptor cannot express verified-ready; live P007 target integration remains BLOCKED without modifying
its source. Human G1–G5 and external review remain NOT_DEMONSTRATED.
