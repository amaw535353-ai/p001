# Architecture and execution boundaries

The CLI reads bounded local JSON/YAML, validates the vendor-independent domain
model, derives candidate trust crossings, and evaluates safe rule predicates.
It emits hypotheses, proposed controls, non-executable verification designs,
escaped diagrams and a synthetic consultancy handover. No runtime module imports
HTTP clients, sockets or subprocess execution. Imported Python is never imported.

```mermaid
flowchart LR
  files[Untrusted local architecture data] --> parse[Size/depth/alias/tag checks]
  parse --> schema[Strict schema and referential integrity]
  schema --> graph[Directed graph and candidate boundaries]
  graph --> rules[Versioned boolean rules and fact trace]
  rules --> plans[Hypotheses and proposed controls]
  plans --> export[Redacted artifacts and integrity manifest]
  export --> human[Independent human review and later assessment]
```

The reference design contains separate tenant-a/tenant-b humans and workloads,
client/application/content/action zones, IdP, PEP/PDP, backend, retriever,
connector, document/index storage, provider gateway/model, secret store, CI,
audit sink, agent, MCP service, approval gate and mock ticket API. Every item
is DECLARED. Provider and user interfaces are graph data, never contacted URLs.

P-001–P-004 are local adapters, not service dependencies of the core. ATLAS is
pinned data. Native tools are unavailable and cannot execute through this CLI.
LLM-assisted generation and live imports are deliberately not implemented.
