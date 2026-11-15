# Preflight order and overrides

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

1. Validate complete input, known activities, bounded fields, strict types and clocks.
2. Bind named current engagement/version, active status, approval digest, exact
   target/activity/window binding, and current review-evidence hash.
3. Check actor role/tenant, time and activation boundary, contact, workload identity,
   human checkpoint and supplied request/rate/cost/interruption budgets.
4. Canonicalize target without DNS or requests; select exact included owned assets.
5. Apply overriding exclusions, activity restrictions, method, tenant/environment,
   external ownership, redirects, evidence policy, data breach and stop conditions.
6. ALLOW only if all gates pass; otherwise DENY with stable reason codes, matched
   clauses, policy and approval digests, engine version and fresh audit UUID.

Multiple reason codes may be returned; overrides are evaluated even after a failed
gate. No REVIEW_REQUIRED decision can grant permission. Unknown/invalid input is
DENY; malformed store/chain fails the CLI closed with nonzero operation error.
An explicitly forbidden class overrides the same class appearing in an allowlist.

Only numeric loopback and reserved .test identifiers are accepted. .test is an
opaque offline identifier, not proof of resolution/ownership. No localhost aliases,
relative URLs, public hosts/IPs, IDNA, wildcards, credentials, query strings,
fragments, percent escapes, control characters, dot segments or redirects. Ports,
schemes, path case and methods remain distinct. Host case and literal IP formatting
normalize. Paths match exactly, not by prefix. Host, IP and URL selectors do not
implicitly authorize each other. Loopback CIDRs can include IP/CIDR subjects, never
an arbitrary URL's protocol/port; exclusions may conservatively match an IP inside
a URL against a CIDR. IPv6 only permits ::1/128. Ambiguous bracketed authorities fail.

Budgets are integer projections against all ceilings, not reservations or trustworthy
usage meters. Contact availability and human checkpoint are caller assertions.
Only a separately enforced runner can ensure honest counters and stop execution.
