# label-studio local adapter

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Run from the P-002 component: `./scripts/lab up label-studio`, then
`./scripts/p002 adapters seed --name label-studio --target lab` and
`./scripts/p002 adapters verify --name label-studio --target lab`.
Repeat import and real checks: `./scripts/integration-test --name label-studio`.
Teardown: `./scripts/lab down label-studio --confirm p002-local`.

See [API and edition limits](../../docs/nextcloud-redmine-labelstudio-apis.md)
and [actual evidence](../../docs/validation-status.md). Availability is not PASS.
