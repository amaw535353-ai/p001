# Exact identifier correlation

```mermaid
flowchart LR
  Events[tenant-scoped original events] --> Buckets[exact trace, request, tool, decision and run IDs]
  Buckets --> Ambiguity[reject ambiguous request-to-multiple-trace join]
  Ambiguity --> Graph[versioned derived links]
  Graph --> View[time-sorted view with original timestamps]
  Events --> Gaps[missing sequence and event types]
```

`p009-exact-v1` links only exact shared identifiers within an already authorized tenant scope.
Time, similar content, usernames and actor/session resemblance create no link. Multiple traces
claiming one request produce ambiguity. Explicit source-event references link alerts only when
the referenced event is unique. Link identity uses a digest of source ID plus event ID.

Arrival order, original timestamps, clock skew, partial authorization records and missing controlled
sequence members remain visible. A timeline is a derived layer; original records are not rewritten.
A sequence gap is limited to the observed bounded range. Absence does not prove nonoccurrence.
