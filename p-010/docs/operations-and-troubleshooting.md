# Operator commands

Run from `p-010/` after `./scripts/setup`. The CLI accepts global
`--workspace`, `--engagement`, and `--actor` before the command.

```bash
./scripts/p010 doctor
./scripts/p010 rubric
./scripts/p010 demo
./scripts/p010 --workspace audit-demo demo --p008 /path/to/p008/handoff.json \
  --p009 /path/to/p009/handoff.json --events /path/to/p009/events.json
./scripts/p010 --workspace audit-demo --engagement ENG-DEMO-A --actor demo-author \
  report verify --id REPORT-DEMO-001
./scripts/p010 --workspace audit-demo audit verify
make redmine-up
make cleanup CONFIRM=p010-owned-resources
```

For new engagements, use `init --file` with the engagement schema, then
`source import`, `evidence link`, `observation draft`, `observation submit`
and `observation review`. Use `record list` and `record show` to obtain
exact links, and the `schemas/` inputs to prepare each JSON document.
Use `finding severity`, `risk set`, `remediation plan`, `retest plan`,
`retest record`, and `risk accept` for the lifecycle. Use `report build`,
`report review`, `report approve` and `report export` with the registered
actors. CLI subcommand help lists required flags.

The role registry, immutable source records and generated reports are
local. Make a new named workspace to rerun a training exercise. A
source verification failure is a reason to inspect the original input
version and file paths. A Redmine conflict requires inspecting the
stored binding and live issue fields before writing again. The
retention dry run `retention audit` reports the eligible time and plan
digest for the custodian.
