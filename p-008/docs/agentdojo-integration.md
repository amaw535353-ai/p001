# AgentDojo — inventory #4

Verified package 0.1.35, MIT, Python >=3.10. Reviewed official FunctionsRuntime,
TaskEnvironment, BaseUserTask/BaseInjectionTask, dependency injection and documented
tool error semantics. AgentDojo belongs to P-008's project crosswalk; it is not
one of the three tools in the separate Risk #21 source row.

`./scripts/p008 eval --tool agentdojo --family authorization` registers one fixed
`perform` function with the actual FunctionsRuntime. Environment is injected via
Depends; the caller cannot replace it. Only the exact requested synthetic resource
and action are accepted. Task predicates retain utility and attacker success
separately; AgentDojo's injection security predicate means attack success, so it
must not be relabeled as defense success. State changes, call trace and per-case
native outcomes are retained. Eight cases exercise four allowed/four denied actions.

All state is in memory, local agent behavior is deterministic, and the worker's
network is disabled. This verifies the actual runtime API on a P-008-owned task;
official suites, adaptive attacks and real LLM agents are NOT_TESTED. It is not
an application-control regression runner or enterprise-agent security finding.
