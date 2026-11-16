# Sibling compatibility matrix

| Project | Actual consumed interface | Scope/status |
|---|---|---|
| P001 | resources.json reviewed metadata, kind/name/label projection | validated offline; Kubernetes enforcement NOT_TESTED |
| P002 | generate + strict Dataset 1.0 export | validated synthetic identity/tenant/scenario IDs; oracle is not native enforcement |
| P003 | sealed Engagement 1.0, actual Store replay/evidence + evaluate | metadata validated; fresh synthetic ALLOW/DENY/refusal tested per local request |
| P004 | inventory + Snapshot 1.0 + architecture digest | validated target/endpoint metadata; discovery is not authority |
| P005 | read_model p005-model-1.0 + actual analyze output | candidate threat/risk/control IDs remain MODELLED_THREAT |
| P006 | p006-target-adapter-v1 schema and empty example only | BLOCKED; no committed application or verified runtime |

`scripts/demo-contracts.py` executes these actual parsers/generators without network
access, retains source hashes and their stated limitations. Contract tests fail on
absent/incompatible schemas and invalid snapshot identities. No compatibility is
inferred from a directory name. P003 imports recheck review evidence/current state,
not a stale exported ALLOW. The old P003 sample time window is expired and is not
silently widened; a new ephemeral fictional policy is created only for local-demo.

The separate P006 prompt was not supplied. Its existence elsewhere would not prove
an implementation. A future integration needs actual versioned code, endpoints,
ownership, response schemas, scope and runtime evidence before the contract can be
enabled. P007 does not rebuild it. P008/P009/P010 consume ReportExport 1.0 plus
p007-handoff-v1 metadata/evidence references; their platforms are not implemented here.
