# Local deployment and runtime profiles

The offline, OSCAL and ATLAS profiles use Python 3.12 and local pinned
contracts. The offline profile needs uv for setup and the approved
repository checkout for sibling schemas. The Redmine profile uses
amd64 rootless Docker, a network-disabled container, one named volume
and a private synthetic project. Its preflight checks one CPU, 2 GiB
available memory and 1 GiB disk. The Langfuse read-only profile expects
a separately operated compatible local service and private project key.
P-010 installs no extra tracing stack. Enable each optional service
explicitly when the host can meet its own requirements.
