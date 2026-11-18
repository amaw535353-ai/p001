# P-009 engineering contract

Follow the root contract. Scope is p-009/ and its owned CI workflow; preserve
P-001 through P-008. Synthetic local telemetry only. No privileged containers,
public Docker networks, arbitrary targets, real provider or cloud operations.
Bind published ports to loopback and label every owned Docker resource io.p009.owner=p009.
Keep credentials, telemetry, runtime state, tools and evidence ignored. Never print
raw payloads or errors. Preserve source statuses, uncertainty and missing joins.
Run make verify, the socket-disabled suite, and root make unit static. Live product
claims require actual product execution; fixtures cannot satisfy live gates.
The user's direct request authorizes commit, push and merge. Learner G1–G5 and
external human verification remain NOT DEMONSTRATED. Workbook has questions only.
