# Redmine #142: opt-in local tracking

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

Official wiki reference: https://www.redmine.org/projects/redmine/wiki/Rest_api.
The wiki returned proxy HTTP 403. To verify API contracts without guessing, the
implementation inspected official redmine/redmine tag 6.1.0 commit
872d7816955d5d3d6c7d7e3a4a70d4b50c275993: config/routes.rb and
app/controllers/issues_controller.rb. Routes and accept_api_auth confirm issue REST
read/create/update contracts; file hashes and provenance are recorded in sources.json.
No running Redmine was present at 127.0.0.1:8782 (connection refused). Live server
version, edition, token permission and native behavior are NOT TESTED.

The adapter sends requests only to fixed http://127.0.0.1:8782 with proxies disabled
and redirects refused. Token is read privately from P003_REDMINE_TOKEN only on
explicit write. Dry-run needs no token and performs zero network requests. Before
writes it checks /users/current.json, /issue_statuses.json, /trackers.json and
/custom_fields.json. Missing access, missing open status/tracker, or any required
custom field blocks rather than invents values. A narrowly scoped local token may
lack custom-field discovery permission; use an independently reviewed suitable
training binding or leave this optional integration disabled. No privilege elevation
or user/role provisioning is implemented.

Ownership-init creates a private manifest and fresh marker. Explicit --write
--confirm p003-local allows creation only of p003-synthetic-engagements, private,
with the exact notice/marker. Existing unmarked projects are refused. Issue markers,
project IDs and journaled IDs must reconcile; drift and truncated listings block.
Readback verifies subject, description and owning project. Timeouts persist pending
intent: a later complete listing can reconcile a created issue, but absent uncertain
writes are not retried blindly. No DELETE, mass update, user creation, mail,
permission change or target authorization import exists. Local notifications must
already be disabled in the separately operated synthetic instance.

Tests use a labeled stub for dry-run, create/readback, repeated sync, lost-response
reconciliation, ownership collision, drift, required-field and truncation guards.
Those contract passes are not live integration or target-side enforcement evidence.
