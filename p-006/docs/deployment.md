# Deployment and reproducibility

Use `./scripts/setup`, `make doctor validate up`, then `make test-live`. Linux x86_64, Docker Compose v2,
Python 3.12 and a package download step are required. Runtime inference and tests require no public
network, AWS, GPU, paid account or model. `requirements.lock` pins every core wheel with SHA256;
setup downloads wheels into ignored .tools for an offline image installation. Reinstall on another
platform requires reviewed wheel/image support; no cross-platform claim.

All five product images and Python base have version+registry digest pins in config/images.lock.json.
The local P006 image is built from that base and locked wheels and labelled with owner and lock digest.
Source/config/scripts are mounted read-only; changes require validation and process restart. The operator
rebuilds only if the requirements-label hash changes. Record local image ID in each verification.
Containers use UID1000 (OPA65532), drop ALL capabilities, no-new-privileges, CPU/memory/PID limits,
read-only roots where practical and bounded logs. Keycloak/WebUI root filesystem writes are documented
exceptions for upstream startup; their application databases are tmpfs. No persistent secret volume.

`up` refuses an existing stack or unowned name collision. `down` removes only the explicit p006 container
and network name inventory after verifying owner labels. It removes memory databases; evidence remains.
`cleanup CONFIRM=p006-owned-resources` also deletes only p-006/.runtime and retains evidence/reports.
No global prune, unrelated volume/image cleanup, reset, force-push, branch rewrite or cloud deployment.
Docker image/build caches are retained; remove a particular unused project artifact only after ownership
review. Source setup/bootstrap/restart must be reverified after changing image versions.
