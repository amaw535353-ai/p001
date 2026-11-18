# Langfuse #117

```mermaid
flowchart LR
    E["Exact P-009 trace/span reference"] --> P["One configured local project"]
    P --> H["Health API version check"]
    H --> O["GET v2 observations · time fields only"]
    O --> R["IDs, timestamp and local deep link"]
    P --> U["REFERENCE_ONLY when unavailable"]
```

The connector targets Langfuse 4.80.0, the version pinned by P-009.
Official endpoint and field definitions were inspected. Tests check exact
trace/project/time, pagination bounds and metadata projection using a
deterministic API double. The P-009 exercise generated reference IDs, but
the P-010 adapter was not run against a native Langfuse deployment on this
host. It recorded REFERENCE_ONLY and NOT_TESTED. The opt-in read accepts a
numeric loopback port and explicit project binding. Provide credentials
through a private environment. Keep credentials out of browser code, reports and Git.
