# Inspect Evals — inventory #42

Verified package 0.29.0, MIT code license, Python >=3.11. Inspected the official
registry entry point (`inspect_evals._registry`), `strong_reject` task, metadata,
record converter, source acquisition and grader behavior. The selected task is
relevant to refusal evaluation and risks of relying on a model judge.

`./scripts/p008 eval --tool inspect_evals --family authorization` imports the actual
task and executes its `get_record_to_sample` converter with the fixed `None`
transformation on eight P-008-authored records. Converted upstream-style stable
IDs, task metadata, module digest and upstream provenance are preserved alongside
the P-008 local observations. These remain P-008 synthetic samples.

The native benchmark would acquire a separately sourced corpus and use a hosted
judge. Neither step is run. Upstream benchmark samples executed: **0**; full
benchmark/judge status: **NOT_TESTED**. The corpus license is not approved for
redistribution. Importing/converting is the actual integration gate permitted by
I02; it is not represented as an upstream benchmark score.
