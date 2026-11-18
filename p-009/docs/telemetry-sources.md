# Source inventory and trust

`config/defaults.json` binds each source to a synthetic tenant, pseudonymous actor, service and
version. `Pipeline.submit` receives that source binding from trusted ingress code. Payload
tenant, actor, source and severity labels are omitted. A producer cannot ingest another tenant's
source. The Collector's shared lab producer credential represents only tenant A.

| Source | Supported interface | Limit |
|---|---|---|
| P009 synthetic | Executed SDK spans and strict source events | Deterministic model, no provider claim |
| Collector | OTLP JSON sink after processors | Internal network and producer credential are trusted |
| P006 | Actual PEP authorization JSON shape | Missing request ID; failures also lack tenant |
| P007 | Actual ReportExport 1.0 and explicitly selected run | Metadata reference does not authenticate source |
| P008 | Actual p008-handoff-1.0 shape | Metadata only; all sample results omitted |
| Wazuh | Controlled JSON and native rule/alert references | No host-agent or enterprise-SIEM coverage |

Unknown sources, incompatible schemas and ambiguous source bindings fail closed. No arbitrary
external URL, service discovery, user log directory, browser state or real identity is collected.
