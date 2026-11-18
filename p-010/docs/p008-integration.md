# P-008 sanitized evaluation

```mermaid
flowchart LR
    X["p008-handoff-1.0"] --> A["Aggregate run metrics"]
    X --> B["Exported non-sealed result rows"]
    X --> O["Sealed omission policy"]
    A --> P["Supporting report context"]
    B --> P
    O --> P
```

The actual offline P-008 exporter produced a 48-observation handoff
with 38 public rows and 10 omitted sealed rows. Aggregate metrics may
include sealed observations. P-010 validates evaluator and metrics shape,
result row types and count arithmetic. Evaluator prompts and judge prompts
are dropped. P-008's P-010 findings array stays empty. The checked-in
test fixture replaces the evaluator prompt text and is distinct from the
actual local handoff retained for the demonstration.
