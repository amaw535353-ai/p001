# Operations

`make status` shows container health; `make doctor` reports tools and fixed local mode. Do not print
runtime credential files or dump entire container environments/logs. Gateway/UI/Vault raw logging is
disabled. PEP safe audit events contain no prompts or tokens. Readiness checks identity key service,
default-deny policy response, required Vault read and gateway liveness; liveness alone is not readiness.

A failed bootstrap needs `make down` and a fresh `make up`: in-memory Vault root is intentionally not
retained for repair. Failed AppRole/session expiry denies, never falls back. A new bootstrap regenerates
all synthetic secrets and invalidates old realm/UI state. Stop/start without removing containers keeps
some tmpfs state but Vault process restart loses its in-memory storage; use the complete fresh sequence.

If vfs exhausts disk, retain the failure and do not run global cleanup. The official slim UI pin avoids
preloaded model assets. On this host the full UI's copied layers filled 63 GB. Ownership review rejected
a proposed broad cache filter; only the exact newly pulled, unused full UI tag was removed. Other project
images/caches were preserved. Host directory permissions and subordinate Docker UIDs differ: keep
.runtime 0700 and mount individual role directories directly; the bootstrap uses private captured IPC.

Native test exit 1 = observed failure, 2 = blocked execution, 0 = executed checks passed (P007's known
contract blocker is still recorded). Never interpret an absent/skipped/blocked result as PASS.

Both uppercase and lowercase HTTP/HTTPS/ALL proxy variables are cleared inside the isolated services,
and both NO_PROXY spellings cover all internal destinations. Inherited lowercase settings otherwise
sent internal SDK/OIDC traffic toward an unreachable proxy; validation rejects that escape route.
