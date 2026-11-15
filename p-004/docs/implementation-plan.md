# P-004 implementation plan

Base: clean `4b7f14aea75c65f111f16f84ae7908dabca6570c` on `work`;
feature branch `feat/p-004-architecture-attack-surface`. Lowercase `p-004/`
matches p-002/p-003. This tool cannot open a separate Codex chat; the work stays
in the existing isolated checkout. No remote push/publication is authorized.

The four named crosswalk/career files are absent from /workspace. The uploaded
P-004 prompt supplies mappings #1 Onyx, #2 OpenHands, #62 ZAP, #145 Playwright;
no detailed taxonomy or compliance mapping will be invented.

## Minimum stack and contracts

Python 3.12, Pydantic 2.12.5, PyYAML 6.0.3 and jsonschema 4.26.0; use
the already reviewed P-003 hash-locked toolchain for testing. No LLM/GPU/cloud
account needed. Implement bounded local parsers, tenant-aware typed graph,
stable IDs, provenance, semantic snapshots, deterministic diff, sanitized
Markdown/Mermaid/CSV and hashed evidence. Read actual P-001 manifests and source;
use actual P-002 generator/model validation without treating its grants as ROE.

Read-only P-003 adapter replays the actual hash-linked store and validates its
review evidence, then invokes p003.policy.evaluate for every HTTP operation.
No approval creation in the discovery CLI. Require immutable version/digest,
actor/context/budgets and an independently supplied owned-target manifest.
Local transport uses literal 127.0.0.1 only, exact reviewed GET/HEAD paths, no
DNS/proxies/redirect following/cookies/credentials/crawling, bounded bodies,
requests/rate/deadline and serialized connections. Recheck immediately before
connect and each request. There remains an unavoidable decision-to-send race;
do not claim atomic revocation with an external ledger.

Browser execution is BLOCKED unless an independent network-level sandbox is
available; context routing alone cannot prove all browser egress containment.
Ship a deterministic local fixture, sanitized traffic fixtures and refusal
tests; do not claim a live Playwright graph. ZAP is optional and unavailable:
validate a restrictive passive-import configuration and accept only sanitized
passive-alert contracts, never launch scans. Onyx/OpenHands are optional local
manifest adapters, not fabricated vendor APIs. Live Kubernetes inventory is
BLOCKED without a reviewed namespace identity and compatible host.

## Verification and delivery

At least 35 substantive cases: parser/model/schema, provenance/conflicts,
stable IDs/diff, hostile inputs and output injection, path/symlink limits,
P-002 tenant separation, real P-003 lifecycle denials, strict URL/method
checks, real loopback guarded transport, redirect spy, budget/deadline/stop,
browser/ZAP refusal, ownership cleanup, CLI subprocess and deterministic replay.
Offline subprocess tests deny all socket connects. Use pytest/Hypothesis,
ruff format/check, mypy, JSON Schema and root make unit/static. Save current
JUnit/command evidence with versions/hashes and honest optional statuses.

Outputs: assets, endpoints, identities, flows, boundaries, observations,
snapshot/diff/coverage, Mermaid, memo, evidence manifest, assessment record.
All runtime artifacts are ignored. Preserve independent learner exercises,
G1–G4 NOT DEMONSTRATED, and explicit future-consumer export contracts.
