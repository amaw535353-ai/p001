# P-001 agent contract
Operate only in this checkout and P-001-owned disposable local resources. Each cloud
task is isolated: use the existing checkout; do not create worktrees unless requested.
Never access real AWS, push, publish, elevate privileges or remove unrelated resources
without separate explicit authorization. Bind host listeners to 127.0.0.1.
Never print or commit real credentials, state, raw logs, personal data or .env files.
Only clearly synthetic fixtures belong in tests. Preserve user changes.
Record actual commands and results. BLOCKED and NOT TESTED are never PASS.
Do not infer IAM enforcement from policy creation, or NetworkPolicy enforcement from
manifest existence. Keep learner assessment hypotheses and workbook free of solutions.
Run make unit and make static after code edits; runtime checks require make lab-test.
No offensive external scanning. No global Docker cleanup. No automatic AWS deployment.
