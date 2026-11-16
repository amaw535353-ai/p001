# Gateway routing and bounds

Pinned LiteLLM OSS with P006 custom authentication callback; no DB, virtual-key platform or paid
budget feature required. Both advertised model IDs resolve only to `openai/p006-deterministic` at
`http://model:8000/v1`. External destinations, retries, user API base overrides, tools and plugins
are unsupported. The startup provider key is retrieved server-side from Vault. The generated master
key is process-local; ordinary application credentials cannot access gateway administration.

Custom auth accepts only POST chat completion routes, strict reconstructed body/model/token bounds,
a 10 s timestamp, 32 hex nonce, HMAC SHA256 over canonical entire body and the current Vault key.
Single-worker nonce memory rejects replay for 20 s. Trust covers the PEP workload; a compromised PEP
or Vault reader can mint proofs. Multiple workers/restarts require distributed replay state and are
unsupported. No backend provider key reaches browser clients.

PEP caps input 16 KiB, dependency responses 64 KiB, message content/count, max output tokens 128,
4 in-flight gateway calls, 20 requests/user/minute and 1024 conservatively charged character+token
units/tenant/minute. This is a synthetic resource budget, not exact model-token billing. No refunds
for denied/failed requests; windows are process-local and reset on restart. Dependency timeout 4 s,
PEP bounded operation 12 s, outer request 16 s, no retry fallback. PEP-owned quotas are explicitly
distinguished from native LiteLLM rate/budget features.

Gateway/model/UI raw logs are disabled to avoid vendor exception/prompt leakage. The PEP emits only
its sanitized allowlisted audit events. Optional external inference/provider profiles are unsupported
and strict config rejects them; no prompts are sent to a third party by this project.
