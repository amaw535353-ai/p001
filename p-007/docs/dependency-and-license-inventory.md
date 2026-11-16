# Dependencies and license inventory

Python 3.12-first. Core Pydantic 2.12.5 (MIT), jsonschema 4.26.0 (MIT), PyYAML 6.0.3
(MIT), with pinned pytest/ruff/mypy tooling aligned to inspected sibling conventions.
Hash-locked requirements include transitive dependencies. Existing sibling packages
install locally without dependency changes; pip check passes in both environments.

Promptfoo 0.125.1 community provider/CLI: MIT; full npm dependency graph/integrities
are committed in tools/package-lock.json. Inspect AI 0.3.290: MIT, separate lock/venv
because current Pydantic requirements differ. Playwright 1.65.2: Apache-2.0.
OWASP ZAP 2.17.0: Apache-2.0, hash-verified official archive. Debian Chromium and
OpenJDK are existing host dependencies with their own bundled notices; they are not
redistributed by this repository. No paid APIs are installed or invoked by default.

`dependency-inventory.json` records actual installed Python/Node names, versions and
license metadata; UNKNOWN entries require review before redistribution. It is not
a blanket legal clearance or vulnerability audit. Do not commit wheels, node_modules,
browser binaries or the ZAP archive. Keep upstream notices with any approved later
distribution. Installer cache/download activity is setup, not an offline runtime claim.

Pins were selected from inspected official documentation/package metadata on
2026-11-16 and tested on the recorded host. Updating pins requires API compatibility,
license and acceptance checks; do not silently upgrade add-ons or browser versions.
