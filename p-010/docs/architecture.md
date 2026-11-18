# P-010 architecture

The local Unix account and private workspace are the trust boundary. Source
files cross a bounded, read-only validation boundary. The CLI governs local
synthetic role permissions and commits canonical changes and audit events in a
single SQLite transaction. The report exporter reads frozen links to exact
record versions. Redmine and Langfuse are optional and separately configured.

## Components and trust boundaries

```mermaid
flowchart LR
    S["P-003–P-009 owned JSON"] --> I["Bounded readers and source schemas"]
    subgraph W["Private P-010 workspace"]
        I --> D[("SQLite records and audit")]
        O["Operator CLI and roles"] --> D
        D --> M["Markdown, JSON and manifest"]
    end
    D --> R["Owned Redmine container · loopback"]
    O --> L["Explicit Langfuse loopback · read only"]
    A["Pinned ATLAS and OSCAL"] --> O
```

## Assessment source to finding

```mermaid
flowchart LR
    A["Source result"] --> B["Read-only projected record"]
    B --> C["Author links evidence"]
    C --> D["Candidate observation"]
    D --> E["Independent review"]
    E --> F["Versioned disposition"]
    E --> G["Confirmed finding with direct evidence"]
```

## Relationships

```mermaid
erDiagram
    ENGAGEMENT ||--o{ OBSERVATION : records
    OBSERVATION ||--o| FINDING : reviewed_into
    FINDING }o--o{ RISK : supports
    FINDING ||--o{ REMEDIATION : addresses
    REMEDIATION ||--o{ RETEST : evaluated_by
    RISK ||--o{ ACCEPTANCE : decided_by
    FINDING }o--o{ EVIDENCE : substantiated_by
```

The remaining flows are documented with the [state machine](finding-lifecycle.md),
[rubric](severity-and-risk-rubric.md), [evidence](evidence-quality.md), source adapters
[P-003](p003-integration.md), [P-005](p005-integration.md), [P-007](p007-integration.md),
[P-008](p008-integration.md), [P-009](p009-integration.md), [Redmine](redmine-integration.md),
[OSCAL](oscal-integration.md), [ATLAS](atlas-integration.md), [Langfuse](langfuse-integration.md),
[report approval](human-review-and-approval.md), [retention](retention-and-deletion.md)
and the [handoff](p010-handoff.md).
