# WP-6.1.1 — Onyx enterprise AI application security requirements and assets

**Assessment type:** Source-only security requirements and architecture review (not a penetration test)  
**Assessed on:** 2026-11-20  
**Canonical competency:** 6.1.1 — Enterprise application requirements, assets, roles and security objectives  
**Reference project:** P-006 in `amaw535353-ai/p001` (supporting P-004)  
**P-006 SHA:** `b6e2854762e17ffea541b02a9ecb9c329a28c5f7`  
**Independent target:** `onyx-dot-app/onyx`  
**Onyx SHA:** `0135795fdf8f28f2c8bd8b52361a5b7f2172586f`  
**Environment:** Google Cloud Shell, local shallow clones; file inspection only  
**Target edition and running configuration:** UNKNOWN; no Onyx runtime inspected  
**Assessment authorization:** No live external testing performed; source review of public Onyx repository only  
**Execution/competency status:** SOURCE-INSPECTED / RUNTIME-NOT-TESTED / INDEPENDENT-DEFENSE-PENDING

## Executive summary

A source review identified Onyx's authorization primitive (`require_permission`) and its separation between endpoint reachability (Gate 1) and resource-level scope (Gate 2). The `/manage/users` endpoint accepts `READ_USERS` from globally permitted users or scoped managers, combines the principal's authority with applicable token scopes, and masks group membership/admin status for scoped readers. The reviewed helper includes every retrieved user row but filters each row's *group memberships*; the endpoint omits invited users and disables API-key user inclusion for scoped readers. This initially suggested a potential row-scope issue. Source tests, however, expressly require group managers to see users outside their managed groups as candidates for addition. Accordingly, **broad candidate-directory visibility is an intended source-level behavior in this commit**, not a verified vulnerability. Security outcomes remain untested in a running Onyx environment.

This report does not certify the product, infer controls in Onyx from P-006, or claim that tests were run.

## 1. Objectives and assumptions

**Business setting (fictional for future testing):** An enterprise knowledge assistant with HR, Engineering and Finance groups. Synthetic actors: `admin_a`, `manager_a` (manages only Group A), `member_a`, and `outsider_b` (belongs only to Group B). These identities do not exist in a verified deployment.

**Security objectives:** Keep user and token authority aligned; restrict changes to groups and privileged configuration; preserve document/file isolation; limit external connector and agent actions to authorized principals; protect credentials; give appropriate observability without exposing secrets.

**Out of scope for this source-only review:** Running Onyx, enterprise licensing verification, real connector ACL sync, live model/agent testing, cloud IAM hardening, and exploitation or vulnerability confirmation.

## 2. Asset and data inventory (source-supported; deployment presence unknown)

| ID | Asset / subsystem | Source-supported purpose | Sensitivity / objective | Evidence |
|---|---|---|---|---|
| A01 | Next.js web UI | Browser-based chat/administration | User actions must not substitute for server authorization | [Architecture](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/.agents/feature-map/ARCHITECTURE.md) |
| A02 | API server / route handlers | Authenticated HTTP and chat operations | Server-side authentication and authorization | [Onyx main](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/main.py), [permissions](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/auth/permissions.py) |
| A03 | User/group/permission metadata | Permissions, membership, identity records | Prevent unauthorized administration and privilege escalation | [Group-scoping code](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/auth/scoped_permissions.py) |
| A04 | PostgreSQL | Authoritative metadata and tenant schemas according to architecture docs | Tenant data isolation, permission integrity | [Architecture](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/.agents/feature-map/ARCHITECTURE.md) |
| A05 | OpenSearch index | Document chunks, vector data and replicated ACL metadata | Authorized search/retrieval and ACL synchronization | [Architecture](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/.agents/feature-map/ARCHITECTURE.md) |
| A06 | Redis/cache | Session state, Celery messaging, coordination | Session isolation and process reliability | [Architecture](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/.agents/feature-map/ARCHITECTURE.md) |
| A07 | File store | Uploads, ingestion stages, checkpoints and snapshots | File ownership, credential and document confidentiality | [Architecture](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/.agents/feature-map/ARCHITECTURE.md) |
| A08 | Connector workers | External-source retrieval, background sync and ACL updates | Preserve source permissions; contain connector credentials | [Architecture](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/.agents/feature-map/ARCHITECTURE.md) |
| A09 | LLM and agent/tool integrations | Chat model calls, tools, optional MCP and Craft functionality | Prevent unauthorized actions and data disclosure | [Architecture](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/.agents/feature-map/ARCHITECTURE.md) |
| A10 | Audit events | Selected user role changes and permission-denial events in reviewed code | Trace decisions without leaking sensitive credentials | [Manage users](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/server/manage/users.py#L173-L210), [Scoped permissions](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/auth/scoped_permissions.py#L32-L46) |

The architecture map is evidence that components exist in the *repository's documented design*, not that they are running or configured in an assessed deployment.

## 3. Identity and principal matrix

| Principal | Proposed actions | Source-supported authorization boundary | Confirmation |
|---|---|---|---|
| Global administrator | Change admin access; manage users/groups | `require_permission(FULL_ADMIN_PANEL_ACCESS)` on admin-access route | Route source inspected; not runtime tested |
| Scoped group manager (edition-dependent) | Read member candidates; manage assigned groups only | Gate 1 `READ_USERS, allow_scope=True`; Gate 2 managed-group checks for protected changes | Source and test expectations inspected; enterprise-only integration test |
| Ordinary authenticated member | Use permitted user/chat surfaces; not privileged group management | Effective permissions and route dependencies | Mechanism source inspected; deployment role map unknown |
| Anonymous subject (configuration-dependent) | Only explicitly permitted anonymous surfaces | `allow_anonymous` path in `require_permission` | Mechanism source inspected; no configured instance tested |
| Scoped API token / PAT | Actions permitted by both user authority and token scope | `token_allows` + `require_permission`; exact token issuance rules to verify | Mechanism source inspected; no token tested |
| Ingestion/connector workload | Read configured sources, index data, sync permissions | Service credentials and application-side ingestion boundaries | Architecture-only; credential rules unverified |
| MCP / agent client or tool runtime | Execute enabled actions on acting user's behalf | Caller identity, available tools and delegated scopes | Architecture-only; enablement and enforcement unverified |

## 4. Source-confirmed authorization model

**Gate 1:** [`backend/onyx/auth/permissions.py`, lines 262–384](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/auth/permissions.py#L262-L384) expands grants, classifies `GLOBAL` / `SCOPED` / `NONE`, applies token restrictions, and returns or rejects before the handler. With `allow_scope=True`, Gate 1 permits the scoped principal to *reach* a handler; it does not automatically filter the handler's resources.

**Gate 2:** [`backend/onyx/auth/scoped_permissions.py`, lines 103–175](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/auth/scoped_permissions.py#L103-L175) defines checks for write-side managed-group scope; [`db/scoped_permissions.py`, lines 50–88](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/db/scoped_permissions.py#L50-L88) provides a scoped SQL predicate for resource reads. Individual route usage still requires case-by-case verification.

**Administrator change:** [`/manage/admin/users/admin-access` at users.py:173–210](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/server/manage/users.py#L173-L210) declares full-admin permission and emits a success audit event after role change. This is not proof that all admin routes follow the same pattern.

**Directory:** [`/manage/users` and `_snapshots_with_groups`, users.py:420–543](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/server/manage/users.py#L420-L543) load candidate users and filter displayed memberships to `visible_group_ids` for scoped callers; `is_admin` is set false, invitation list omitted, and API-key user inclusion disabled for such callers. It does *not* restrict the complete candidate-user roster to the managed group. [`get_all_users`, db/users.py:341–384](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/onyx/db/users.py#L341-L384) applies specified system/external/API-user/email filters, not a managed-group predicate.

**Intended directory policy:** The pinned repository's [integration test at lines 576–595](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/tests/integration/tests/permissions_membership/test_group_manager_membership.py#L576-L595) expressly requires a manager to see an outsider as a member candidate; a plain member is expected to be denied. The [unit test at lines 68–119](https://github.com/onyx-dot-app/onyx/blob/0135795fdf8f28f2c8bd8b52361a5b7f2172586f/backend/tests/unit/onyx/server/manage/test_user_management_scope.py#L68-L119) asserts redaction for scoped readers in paginated and unpaginated responses. These are *test definitions*, not test execution results from this engagement.

## 5. Roles, resources, actions — expected matrix

| Subject | Resource/action | Expected | Basis | Runtime |
|---|---|---|---|---|
| Global admin | Change another user's admin status | ALLOW when otherwise valid | Admin-access route / dependency | NOT_TESTED |
| Basic member without `READ_USERS` | `GET /manage/users` | DENY | Scoped-manager integration test expectation for plain member (Enterprise) | NOT_TESTED |
| Scoped manager A | Read user B as group-add candidate | ALLOW, even if B belongs only to unmanaged group | Explicit integration-test expectation | NOT_TESTED |
| Scoped manager A | Read B's unmanaged group membership | REDACT in directory response | Snapshot implementation + unit-test expectation | NOT_TESTED |
| Scoped manager A | Read complete invited-user list or API-key user entries through `/manage/users` | OMIT / EXCLUDE in this endpoint | Route code + unit-test expectation | NOT_TESTED |
| Scoped manager A | Modify membership of unmanaged Group B | DENY | Scope helpers + integration-test expectation | NOT_TESTED |
| Non-admin / scoped manager | Change global administrator status | DENY absent full global permission | Admin-access route + dependency | NOT_TESTED |
| Restricted token | Call a protected action not allowed by token scopes | DENY | `token_allows()` + `require_permission()` | NOT_TESTED |

This matrix applies to the *specified* routes and synthetic principals, not blanket authorization claims about Onyx.

## 6. Trust boundaries

| ID | Data/control flow | Security invariant | Current evidence |
|---|---|---|---|
| TB01 | Browser → API | Server computes principal's permission; UI affordances are not enforcement | `require_permission()` source |
| TB02 | User/token → route handler | User's authority AND token scope constrain operation | `token_allows()` + `require_permission()` source |
| TB03 | Scoped manager → group resource | Passing Gate 1 never grants unrelated group edits | `assert_within_scope()` / `within_managed_scope_clause()` definitions; selected route expectations |
| TB04 | Onyx → PostgreSQL / OpenSearch | Tenancy and document ACLs respected at data and retrieval boundaries | Architecture documented; runtime not inspected |
| TB05 | External connector → indexing and ACL sync | Only authorized content exposed; revocation uses a declared freshness contract | Architecture documented; exact edition/behavior unknown |
| TB06 | Onyx or sandbox → model/tool/provider | Egress, credentials and actions remain within delegated authority | Architecture documented; implementation/runtime not yet traced |

## 7. Requirements traceability and test oracles

See companion `WP-6.1.1-Onyx-Source-Traceability.csv` for source-linked per-requirement status. Existing canonical IDs `REQ-611-01` through `REQ-611-10` remain unchanged from the earlier work-package. New directory-specific test oracles use supplementary IDs `DIR-611-01`–`DIR-611-03`, **not replacements for canonical IDs**.

**DIR-611-01, positive oracle:** With a valid scoped-manager account in an authorized Enterprise lab, `GET /manage/users` returns intended member candidates, including a user only in an unmanaged group. Independently confirm expected synthetic roster and response shape.

**DIR-611-02, confidentiality oracle:** In that same response, inspect all returned fields for unmanaged memberships/admin status/invited-user list/API-key user entries. Expected: groups limited to manager-visible groups; source code sets `is_admin=False`; invitations omitted and API-key user inclusion suppressed for scoped callers. Verify both paginated and unpaginated cases.

**DIR-611-03, mutation-denial oracle:** Under the same scoped principal, attempt to change membership or manager assignment of an unmanaged group *in an owned lab only*. Expected: denied action with unchanged persisted group membership; confirm a permission-gate denial rather than a generic 4xx or incidental error. Use a global admin control to prove the operation is otherwise functional.

**Test classification:** All cases are `DESIGNED / NOT_EXECUTED`; only the positive/negative test *expectations* are supported by pinned Onyx tests.

## 8. Observations and disposition

| ID | Observation | Disposition | Confidence |
|---|---|---|---|
| OBS-611-01 | Scoped managers see candidate user rows outside their groups but only restricted membership/admin data | **Intentional source-level design** for membership picker; not a confirmed vulnerability | HIGH for pinned source/test intent; unverified at runtime |
| OBS-611-02 | `allow_scope=True` needs a separate resource scope check for protected operations | **Review invariant / regression risk**; no bypass demonstrated | HIGH for source pattern, route-by-route coverage unverified |
| OBS-611-03 | Community vs Enterprise permissions and feature gating can change applicable test matrix | **Environment variable to resolve before live tests** | SOURCE INDICATION; actual instance unknown |

**Confirmed vulnerabilities:** None.  
**Production assurance:** None.  
**Test execution:** No test runs were supplied or independently witnessed.  
**Residual unknowns:** Edition/configuration, live identity mechanism, per-route Gate 2 coverage, document ACLs, tenancy enforcement, workload credentials, user data classification and actual audit content.

## 9. P-006 transfer

P-006 source architecture (reviewed in user's Cloud Shell output) uses **Open WebUI → custom Python PEP → LiteLLM → deterministic mock**, with Keycloak, OPA and Vault. Onyx uses its *own* web/API/auth, storage, connectors, and optional agent processes. Transfer the *assessment discipline* (assets → roles → decisions → tests → evidence), **not** P-006's component names or unverified security claims. P-006's deterministic mock cannot establish Onyx or real-LLM security.

## 10. Exit criteria for competency 6.1.1

- [x] Clone and record pinned P-006 and Onyx source revisions.
- [x] Identify core Onyx assets and candidate human/workload principals from architecture and permission source.
- [x] Trace a representative endpoint through permission resolution and scoped authorization.
- [x] Resolve the candidate-directory policy ambiguity using corresponding tests.
- [x] Define measurable acceptance criteria and expected authorization outcomes.
- [ ] Identify the *actual deployed* edition/configuration and authorization settings (not required for source-only report).
- [ ] Independently execute positive/negative cases against an owned/authorized lab (not performed).
- [ ] Independently explain and defend the design, including why visible candidate users are not automatically a flaw.
- [ ] Check other sensitive entry points before claiming broad Onyx security coverage.

**Decision:** SOURCE-ONLY PLANNING ARTIFACT PREPARED. Do not record `RUNTIME_PASS`, full system assessment completion, or competency mastery. 6.1.1 may be signed off as *source-based requirements preparation* once the learner independently defends the architecture and oracles; deeper implementation/runtime testing should be tracked in appropriately mapped competencies.

## 11. Evidence and reproducibility

Cloud Shell evidence paths observed/created by the learner under `~/ai-security-wp611/evidence/6.1.1/`:

- `revisions.txt`, `source-inventory.txt`, `authorization-markers.txt`
- `permission-enforcement.txt`, `admin-access-route.txt`, `scoped-user-directory.txt`
- `user-directory-gate2.txt`, `scope-helper-locations.txt`, `user-directory-scope-markers.txt`
- `snapshot-scope.txt`, `user-response-fields.txt`, `managed-group-resolution.txt`, `user-directory-test-references.txt`
- `directory-policy-test.txt`, `directory-redaction-test.txt`, `directory-query.txt`

These are evidence *filenames in the user's Cloud Shell*, not files received and cryptographically verified in this report. Record exact SHA-256 hashes locally before preserving the collection. Do not commit private session tokens, credentials or real user data.
