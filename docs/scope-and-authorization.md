# Scope and authorization
Only this repository, cluster `p001`, namespaces tenant-a/tenant-b/emulator, labelled
smoke resources `p001-smoke-*`, synthetic fixtures, and their loopback endpoints are
in scope. No third-party scanning, production accounts, real data, real credentials,
paid APIs, push or publication is authorized. CNI installation uses system privileges
inside the dedicated kind node; tenant workloads may not use host mounts or privilege.
No host elevation, host service changes, global prune or account-wide cleanup.
AWS is excluded until separate explicit authorization. Weak profiles are not included.
Preserve pre-existing resources and fail on ambiguous ownership.
