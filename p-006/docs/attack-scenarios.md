# Synthetic scenario catalog

The acceptance catalog contains exact objectives and executable entrypoints. Scenario groups cover
missing/malformed/wrong-issuer/audience/algorithm/expiry JWTs; identity header/tenant/role tampering;
default deny, model and administrator boundaries; OPA outage/invalid response/version; gateway bypass
and request proof replay/substitution; narrow Vault reads, token revocation, outage and rotation;
provider outage, size/rate/quota bounds; UI OAuth/ordinary-user restrictions and actual network paths.
All requests target owned fixtures/services; no instructions or URLs in sample data are executed.

Additional browser session-fixation/CSRF, natural token expiry, UI logout vs PEP session behavior,
provider-key rotation, real provider failures and complete image/log/frontend secret scanning remain
explicit gates when not actually executed. Do not infer these from neighboring passing assertions.
