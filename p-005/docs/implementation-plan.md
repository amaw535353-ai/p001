# P-005 implementation plan and inspection

Repository: amaw535353-ai/p001, clean initial HEAD 6e153d2 on `work`.
Dedicated branch: `feat/p-005-threat-modeling`; directory: `p-005/`.
The current Codex task cannot create another chat; branch/directory isolation is used.
No predecessor code or root configuration will be edited. No push or publication.

1. Build a typed Python 3.12 offline core with strict schemas, bounded data parsing,
   explicit principals/zones/flows, evidence-preserving boundary and path analysis.
2. Add an inspectable boolean rule DSL, prompt-sourced risk references, qualitative
   triage, proposed controls, unexecuted verification plans, review and diff workflows.
3. Validate actual P-004 snapshots and P-002/P-003 contracts; import P-001's
   allowlisted declarations only. Exercise predecessor contracts using actual generators.
4. Inspect and pin official ATLAS distribution and license. Keep native tools
   blocked unless a real compatible version/schema is available; no fake exports.
5. Generate escaped/redacted reports and diagrams, integrity manifests and contracts.
6. Execute negative/property/CLI/zero-network tests, end-to-end demonstrations,
   predecessor regressions and root unit/static checks. Record actual results.

The four named taxonomy/crosswalk/career files were searched under /workspace and
are absent. The supplied P-005 prompt is the only available risk-number source.
Only its explicitly described risks will be accepted, labelled PROMPT_SUBSET;
remaining taxonomy mappings are BLOCKED until the authoritative file is supplied.
No ASVS/AISVS IDs will be invented. No live target imports or external LLM feature.

Linux x86_64, Python 3.12.14, 5 reported CPUs, 33 GiB RAM. Rootless Docker lacks
cgroup delegation, so full kind checks remain blocked as established during setup.
Core P-005 requires no Docker, renderer, service or internet at runtime.
Dependencies reuse the exact inspected P-004 Python 3.12 hash-locked toolchain;
normal runtime will never fetch URLs or execute imported/native Python.
