# Trust boundaries and intended permissions

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

| Boundary | Intended policy | Backend evidence needed |
|---|---|---|
| Tenant A / Tenant B | DENY unless an explicit cross-tenant grant exists | Ordinary accounts in the target platform |
| HR / Finance / Engineering | Effective group/direct grant required | Native share or private-project membership |
| Group lifecycle | Half-open validity intervals, effective revocation | Native revocation and subsequent ordinary-account request |
| Human / service | Service grant + live caller entitlement + exact delegation | Real delegation mechanism, not an ID string |
| Request / approval / action | Distinct effective approver; exact parameters | Actual approval/execution integration |
| Source / derived index | Source remains canonical; derived metadata is untrusted | Later retrieval connector and sync tests |
| Core / network adapter | Fixed loopback endpoint and explicit target=lab | HTTP response, redirects refused |
| Operator / local secrets | Trusted operator; mode-0600 configuration | No raw secrets in records, exports or evidence |

Evaluation order: resolve actor/resource; check identity and resource lifecycle;
collect active direct/inherited grants and active group memberships; require an
explicit cross-tenant allowance; apply explicit deny before any allow; otherwise
default deny. Workloads additionally need an eligible caller, active matching
resource/action delegation, and the caller's own entitlement. Execution requires a
bound request and a different, currently authorized approver. Interval end timestamps
are exclusive. Owners receive no magical bypass; their membership/grants must exist.

Classification labels are **metadata**. The reference evaluator enforces explicit
entitlements, not a classification clearance lattice. Nextcloud Community does not
inherit this custom deny/approval/delegation model; file sharing implements the tested
subset. Redmine uses private projects and a dedicated local role. Label Studio labels
are annotation choices, not security authorization. Its Community project round-trip
is not tenant isolation verification.

Observed results are append-only run files, separate from the generated oracle.
An HTTP 401/403/404 counts as a denial only for the specific requested object/path;
404 does not prove the object exists or a particular native deny rule fired. Credentials
are never reused from an administrator session for an ordinary-user access check.
