# Local access control

The CLI runs under the workspace OS owner with private files. The
synthetic engagement roster assigns distinct author, reviewer, system
owner, risk owner and custodian references. Role checks gate review,
severity, treatment, implementation, acceptance, report approval and
purge. Source and record lookups are scoped to the engaged workspace.
The operating-system account can attest to any registered synthetic
role, so this design does not implement multi-user authentication or
real identity verification. Redmine uses separate fixture accounts.
