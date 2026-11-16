# Authorization and scope

Ordinary operation is offline. Network tests require the exact `local-fixture`
registration, an active in-process FixtureLease, and a real P003Reader. An arbitrary
ownership JSON file cannot create a lease. The CLI has no arbitrary-URL option.
`--local-demo` creates a disposable simulated ledger for the owned engineering
fixture; reviewer names are fictional and no independent human review is asserted.

Before each request, the guard checks lease, time, route/method/category, request
budget, literal origin and effective IP mapping, then replays the actual P003 store
read-only. It verifies exact policy/version, current state, approval, review evidence,
window, actor/tenant, allowed activity/method, exclusions, contact and budgets. The
same check occurs before connect and before sending. Numeric AF_INET connection
and peer verification remove hostname rebinding from the connect path. Every
redirect is rejected, including same-origin redirects. The resolution-change test
proves the broker refuses before socket connect.

Only `http://127.0.0.1:<port>/<reviewed-path>` is accepted. Public/private/metadata
hosts, DNS aliases, userinfo, encoding, query strings, fragments and path tricks are
refused. Concurrency is one and the P007 ceiling narrows the synthetic P003 grant.
Ledger replay is point-in-time, not a signed capability or proof of legal authority.
Local filesystem ownership is inherited from P003, not a multiuser trust boundary.

Active scans require human opt-in and compatible bounded scope. Current P003 has no
bounded active-scan class and P007 cannot enforce scanner-per-rule traffic limits;
therefore active execution always BLOCKS, including after opt-in. No cloud, public
crawling, credential attacks, denial of service or real credentials are supported.
