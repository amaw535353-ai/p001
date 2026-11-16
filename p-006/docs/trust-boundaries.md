# Trust boundaries

Every row assumes a trusted host/operator and synthetic data. Failure denies safely; missing runtime
evidence remains NOT_TESTED/BLOCKED. Diagrams and declarations are not independent verification.

| Boundary | Assets/data | Identity | Decision/enforcement | Tests |
|---|---|---|---|---|
| Browser→WebUI | session and synthetic chat | Human UI session | Native UI auth; PEP downstream | A01,U01,U03,U07 |
| WebUI→Keycloak | code, verifier, access/refresh tokens | Dedicated confidential client | Exact redirect + PKCE + realm | A02,A11,A12,U01 |
| WebUI→PEP | human token and bounded message | Signed subject/tenant registry binding | PEP signature, activity and size checks | A03–A10,U02 |
| PEP→OPA | trusted authorization context | Segmented PEP workload | OPA default deny; PEP enforce | P01–P08 |
| PEP/application→Vault | AppRole identity and narrow secret | Dedicated short-lived workload token | Vault ACL; fail closed | V01–V06 |
| PEP→LiteLLM | message plus bound workload proof | Narrow Vault credential | Callback HMAC/time/nonce/body | P09,P10,L08 |
| LiteLLM→backend | message plus dummy provider key | Dedicated local backend identity | Internal model bridge + backend auth | L01,L07 |
| Internal→external | no approved external data flow | None | Docker internal networks, no default route | N01,N05 |
| Tenant A→Tenant B | resource tenant request | Registry human tenant | OPA equality on actual PEP path | P04,A10 |
| Human→workload | verified subject to service credential | Separate human JWT and AppRole | PEP reconstruction; no shared-key user auth | P10,V01 |
| Admin→data plane | synthetic administrative action | Explicit role + tenant | Native UI auth and PEP/OPA | P05,P06,U03 |
| Audit/evidence→operator | sanitized events and hashes | Trusted local operator | Allowlisted fields; private ignored output | V07,V08 |

Evidence: separate evidence/*/results.json and reports/*/summary.json. Residual limits include local HTTP,
trusted same-bridge workloads, process-local state, tmpfs retention and unassessed graphical browser behavior.
