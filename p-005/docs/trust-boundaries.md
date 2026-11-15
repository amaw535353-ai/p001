# Trust boundary interpretation

Each directed edge is evaluated for zone, owner, tenant, principal, content,
agent/tool, approval, provider and deployment transitions. UNKNOWN zone trust
always creates an UNKNOWN_TRUST candidate. Candidate boundary records contain
precise edge IDs, ordered zone pairs, principal IDs and reasons. Their status is
INFERRED, even when their supporting source metadata is observed.

No unknown encryption, endpoint reachability or policy status is upgraded.
An explicit identity reference must resolve to a human, workload or actor and
belong to the source tenant or shared platform. Cross-tenant *flows* are valid
modeling inputs and create review candidates; unauthorized principal substitution
inside a node or flow is rejected as an inconsistent model.

Path candidates use one to four real directed edges, at most five distinct nodes,
without repeating nodes. Onward edges require the same explicit principal and
source tenant. Connectivity is insufficient to establish runtime privileges;
every path retains uncertainty and conditional execution prerequisites. No BFS
claim of exploitable reachability or automatic privilege acquisition is made.
