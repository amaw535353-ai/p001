# redmine local adapter

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Run from the P-002 component: `./scripts/lab up redmine`, then
`./scripts/p002 adapters seed --name redmine --target lab` and
`./scripts/p002 adapters verify --name redmine --target lab`.
Repeat import and real checks: `./scripts/integration-test --name redmine`.
Teardown: `./scripts/lab down redmine --confirm p002-local`.

See [API and edition limits](../../docs/nextcloud-redmine-labelstudio-apis.md)
and [actual evidence](../../docs/validation-status.md). Availability is not PASS.
