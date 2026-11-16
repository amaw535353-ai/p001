# Data flow inventory

| Flow | Data | Identity and destination | Retention |
|---|---|---|---|
| Browser→UI | Synthetic chat + UI session | Human; fixed local UI | UI tmpfs only |
| UI↔Keycloak | Authorization code/verifier, tokens, fictional profile | Dedicated confidential OIDC client | Encrypted UI tmpfs session; realm tmpfs |
| UI→PEP | Signed human access token + bounded message | Verified Keycloak subject | No prompt/token logs |
| PEP→OPA | Subject, tenant, roles, model, action, quota | Trusted internal PEP; no prompt/token | Versioned policy; safe PEP decision event |
| PEP/gateway→Vault | AppRole identity, short lease, designated secret read | Dedicated least-privilege policies | In-memory Vault only; self-revocation |
| PEP→gateway | Reconstructed message + synthetic IDs + request proof | Narrow workload key + bound proof | No raw gateway logs |
| Gateway→model | Bounded synthetic message and provider key | Fixed local workload route | No model logs; digest response |
| PEP→UI | Projected synthetic digest completion | Authorized request correlation | UI tmpfs |
| PEP→operator | Sanitized decision metadata and status/hash summaries | Operator, ignored evidence/reports | Explicit review before publication |

contracts/architecture/service-inventory.json is DECLARED bounded metadata. P004/P005 native import is
NOT_TESTED; see sibling matrix rather than treating arbitrary JSON as a proven sibling contract.
