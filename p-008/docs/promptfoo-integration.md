# Promptfoo — inventory #3

Verified 0.125.1 with Node >=22.22.0 (host Node 24.22.1). Reviewed the official custom
CommonJS provider API (`id`, `callApi`), current eval CLI and per-test output format.
Only P-008's fixed provider and fixed Javascript assertion text are executable.
Dataset metadata cannot select providers, scripts or endpoints.

`./scripts/p008 eval --tool promptfoo --family authorization` writes an owned config
with sample IDs/repetitions/scorer/rubric versions and runs eval with no cache,
one worker, bounded heap/time/output and telemetry/update checks disabled. The
Node preload guard refuses network/DNS. Raw per-test output, grading assertions,
provider/config/tool identity and host oracle results are retained. Native exit
100 for assertion failures does not erase observed failures; other tool errors
remain blocked. Text matching alone is not authorization evidence.
