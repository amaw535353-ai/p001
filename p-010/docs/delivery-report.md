# P-010 delivery report

P-010 was built on `p001-initial` at
`f6f975f3c570631098e82d8b8690b636a84ee9ee` in
`amaw535353-ai/p001`. The feature branch is
`feat/p-010-findings-risk-register-reporting`. GitHub showed PRs #3–#8
merged. Project changes are confined to `p-010/` and its offline workflow.

The CLI covers source validation, authoring, independent review, risk,
remediation, retest, acceptance, report packages, integrity, retention and
the four selected connectors. The offline canonical workspace uses
transactional SQLite. The reviewed severity rubric is
`p010-risk-rubric-1.0`. Authenticated identity and privileged host
rollback resistance remain outside the local model.

The managed host had an effective 2 CPU and 8 GiB cgroup limit with
approximately 55 GiB disk free after the native Redmine setup. Rootless
Docker 29.9.2 ran Redmine without a network or host ports. Scoped cleanup
removed its container, private keys and named volume. Sibling files and
unowned Docker resources were preserved.

The default training report is generated under
`.runtime/workspaces/<workspace>/reports/REPORT-DEMO-001-v3/`.
The actual handoff exercise used `p010-verified-demo`. Each generated
package contains its own manifest, and `report verify` checks it against
the canonical workspace. The actual-handoff package manifest SHA-256 was
`b321c600ba8524750a0d0736859266bdb9beae5e84262f8e73c114d4bdf7913b`.
The report JSON SHA-256 was
`5ddcd0ff191a3d6121371d2ce2d430e7797b6e159c4a311d2d2a039216136692`.
The demonstration kept P-007's FAIL in the
source record, retained the P-005 hypotheses, disclosed P-008 omission
and P-009 trace limits, and rejected approval of an incomplete draft.

The [validation status](validation-status.md), [test results](test-results.md),
[requirement-level matrix](acceptance-matrix.md) and
[dependency inventory](dependency-and-license-inventory.md) record
the measured scope. G1–G8 require the learner's own work and evidence.
