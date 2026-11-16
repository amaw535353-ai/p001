# Inspect AI — inventory #41

Verified package 0.3.290; official source/release pins in source-lock.json. Inspected
the current Task, Sample, generate, scorer and mockllm interfaces and tested actual
installed behavior. A separate Python environment satisfies Inspect's Pydantic
>=2.13 requirement without changing sibling/core locks.

`./scripts/p008 eval --tool inspect_ai --family authorization` starts the fixed
worker with bounded argv/env/time/resources. It constructs a real Task, uses only
VisibleInput in Sample.input, provides local mock outputs and explicit zero token
usage to avoid a tokenizer download, and runs an observation disclosure scorer.
The host additionally applies the full versioned outcome oracle. `.eval` logs,
native sample scores/status, normalized observations, tool version and identities
are retained under the owned run directory. Network and DNS are blocked by the
Python startup guard, including loopback. No vendor model was evaluated.
