# Authorization and containment

The discovery CLI cannot approve engagements. P-003 must be independently managed
and ACTIVE, with a matching immutable version/digest, valid synthetic review,
assessor/tenant/context, exact local URL asset and permitted method/activity.
Reviewers, actor labels and budgets in P-003 are local assertions, not authenticated
enterprise identities. Its synthetic approvals are not legal permission.

The P-004 adapter opens SQLite read-only, replays P-003's actual event chain,
validates actual review evidence and invokes its actual evaluator for every
operation. Exported policy JSON and test doubles cannot enable live operation.
P-003 decisions are not cached capability tokens. Amendment, stop-work, expired
window, invalid evidence, policy/tenant mismatch or exhausted budget denies the
next request. Local policy decision IDs/digests are retained without credentials.

The transport additionally enforces literal 127.0.0.1 HTTP, exact reviewed paths,
GET/HEAD only, no encoded/ambiguous URLs/userinfo/query/fragment, no hostname/DNS/
CIDR substitution, metadata/link-local/IPv6/external hosts, depth zero, one active
request, 30 total, 30/minute, 120 seconds and bounded responses. Known side-effect
paths are refused. Ambient proxy settings are rejected. No automatic redirect,
cookie, login, credential header, JavaScript, form, click, socket upgrade or crawl
exists. The real socket path is tested, including denied-endpoint spies.

There is a finite policy-decision-to-send race. Requests already in flight cannot
be recalled. Socket timeouts and body/deadline checks bound waiting, but this is
not an atomic revocation protocol, an OS security sandbox, an authenticated
ownership authority, or defense against a malicious user modifying local code.
P-003's own counters are caller assertions. P-004 counts its own reserved attempts
per process; separate processes can exceed aggregate budgets. Do not use this
runner for shared engagements requiring a central request quota service.

Playwright is BLOCKED because context routing alone cannot prove browser-wide
egress confinement. WebSocket/subresource/page-instruction attempts are tested
against refusal, not a live browser. ZAP traffic generation is never performed;
even passive-scanner baseline crawling would require authorization. The supplied
passive contract is not a ZAP Automation Framework configuration. Live cluster
inventory refuses without an independently reviewed namespace-scoped identity;
the tool does not use kube-admin or the Docker socket for discovery.

Sanitization uses allowlist projection, bounded text, credential patterns, query
removal, omitted response bodies/headers and safe renderers. Unknown secrets or
proprietary names cannot be identified perfectly: only synthetic inputs are
appropriate by default, and a human must inspect exports before publication.
