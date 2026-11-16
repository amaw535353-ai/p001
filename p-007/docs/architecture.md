# Architecture and trust boundaries

`catalog.py` loads a bounded, strict catalog. A plan snapshots selected test and
control definitions, target identity, policy, fixture data and source/lock hashes.
`evidence.run` verifies the plan immediately before execution, selects a fixed
adapter, evaluates behavior before redaction, then writes exclusive artifacts and
an atomic manifest. `regression.compare` checks comparability before classifying
transitions. `evidence.reproduce` verifies the recorded inputs before another run.

```
catalog + controls + target + fixture -> digest-bound plan
  -> offline policy OR fixed local model tool
  -> for HTTP: owned fixture lease + fresh P003 ledger + guard + numeric peer
  -> original runner output -> deterministic oracle -> normalized result
  -> redaction -> immutable evidence + hashes -> exports/comparison/reproduction
```

Public inputs are data, never command fragments. Fixed provider/task implementations
are source controlled. No arbitrary provider, executable, plugin, URL or shell
configuration is accepted by the operator CLI. Tool executables run as the task
user with a small environment and bounded process groups. Evidence files use
no-follow reads, symlink checks, exclusive creation and atomic publication.

P007 owns a small synthetic fixture, not an LLM reference application. P006, P008,
P009 and P010 remain separate projects. Human review and independent reproduction
are not automated assessment certifications.
