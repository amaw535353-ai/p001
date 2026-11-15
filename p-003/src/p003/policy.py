"""Pure evaluation: no I/O, network, DNS, subprocess, storage, or scanner invocation."""

from uuid import uuid4

from p003.models import Authorization, CheckRequest, Decision, Engagement, sealed
from p003.targets import matches
from p003.util import digest


def evaluate(
    spec: Engagement | None,
    state: str,
    approval: Authorization | None,
    raw: dict,
    *,
    evidence_valid: bool,
    stopped: bool = False,
    active_since: str | None = None,
) -> Decision:
    """The caller must supply a freshly verified store view and evidence status.

    Counters and actor labels are caller assertions, not authenticated telemetry.
    A decision is point-in-time and must never be cached as a capability token.
    """
    reasons = []
    clauses = []
    request = None
    try:
        request = CheckRequest.model_validate(raw)
    except (ValueError, TypeError):
        reasons.append("INVALID-INPUT")
    if request is not None:
        if spec is None or request.engagement_id != spec.engagement_id:
            reasons.append("UNKNOWN-ENGAGEMENT")
        else:
            artifacts = [spec, spec.client, spec.scope, spec.roe, spec.evidence_policy, *spec.assets]
            if approval:
                artifacts.append(approval)
            if any(
                a.content_digest
                != digest({k: v for k, v in a.model_dump(mode="json").items() if k != "content_digest"})
                for a in artifacts
            ):
                reasons.append("POLICY-INTEGRITY")
            if state != "ACTIVE" or stopped:
                reasons.append("ENGAGEMENT-NOT-ACTIVE")
            if active_since and request.at < active_since:
                reasons.append("BEFORE-ACTIVATION")
            if request.engagement_version != spec.version:
                reasons.append("VERSION-MISMATCH")
            if approval is None:
                reasons.append("MISSING-APPROVAL")
            elif (
                approval.version != spec.version
                or approval.policy_digest != spec.content_digest
                or approval.engagement_id != spec.engagement_id
                or approval.author != next(a.ref for a in spec.actors if a.role == "reviewer")
                or approval.reviewer != approval.author
                or [x.model_dump() for x in approval.targets]
                != [
                    x.selector.model_dump()
                    for x in spec.assets
                    if x.asset_id in spec.scope.included_asset_ids
                ]
                or approval.activities != spec.scope.activities
                or approval.window != spec.window
            ):
                reasons.append("APPROVAL-BINDING-MISMATCH")
            if not evidence_valid:
                reasons.append("REVIEW-EVIDENCE-INVALID")
            r = spec.roe
            c = request.context
            b = request.budget
            if (
                not spec.window.start <= request.at < spec.window.end
                or not r.window.start <= request.at < r.window.end
                or (approval and not approval.window.start <= request.at < approval.window.end)
                or (approval and request.at < approval.created_at)
            ):
                reasons.append("OUTSIDE-WINDOW")
            actor = next((a for a in spec.actors if a.ref == request.actor), None)
            if actor is None or actor.role != "assessor" or actor.tenant != c.tenant:
                reasons.append("ASSESSOR-ROLE-OR-TENANT")
            if not r.emergency_contact or not r.contact_confirmed or not c.contact_available:
                reasons.append("CONTACT-MISSING")
            if not c.checkpoint_completed or c.source_identity not in r.source_identities:
                reasons.append("PREREQUISITE-MISSING")
            if (
                b.used_total + b.requested > r.max_total_requests
                or b.used_last_minute + b.requested > r.max_requests_per_minute
                or b.used_cost_units + b.requested_cost_units > r.max_cost_units
                or b.interruption_ms > r.max_interruption_ms
            ):
                reasons.append("BUDGET-OR-IMPACT-EXCEEDED")
            selected = [
                a
                for a in spec.assets
                if a.asset_id in spec.scope.included_asset_ids
                and a.included
                and (a.selector.kind != "cidr" or request.target.kind in ("cidr", "ip"))
                and matches(a.selector.kind, a.selector.value, request.target.kind, request.target.value)
            ]
            if not selected:
                reasons.append("TARGET-NOT-ALLOWLISTED")
            else:
                for asset in selected:
                    if asset.ownership != "synthetic-owned" or asset.third_party_restrictions:
                        reasons.append("OWNERSHIP-OR-EXTERNAL-RESTRICTION")
                    if asset.tenant != c.tenant or asset.environment != c.environment:
                        reasons.append("ASSET-CONTEXT-MISMATCH")
                    if c.method not in asset.methods:
                        reasons.append("METHOD-NOT-ALLOWED")
                    clauses.append(asset.asset_id)
            # Overrides are applied even when a previous gate already failed.
            if any(
                matches(x.selector.kind, x.selector.value, request.target.kind, request.target.value)
                for x in spec.scope.exclusions
            ):
                reasons.append("EXPLICIT-EXCLUSION")
            if (
                request.test_class not in spec.scope.activities
                or request.test_class not in r.allowed
                or request.test_class in r.forbidden
            ):
                reasons.append("ACTIVITY-NOT-ALLOWED")
            if c.redirects_expected:
                reasons.append("INDIRECTION-NOT-MODELED")
            if (
                c.data_class != spec.evidence_policy.data_class
                or not c.redaction_confirmed
                or c.storage_id not in spec.evidence_policy.storage_ids
                or (actor and actor.role not in spec.evidence_policy.access_roles)
            ):
                reasons.append("EVIDENCE-POLICY")
            if c.data_breach:
                reasons.append("STOP-DATA-BREACH")
            clauses.extend(["ROE", "EVIDENCE-POLICY", "SCOPE-OVERRIDES"])
    # Invalid bytes/objects cannot be re-serialized or echoed into the decision.
    try:
        request_hash = digest(raw)
    except (ValueError, TypeError, UnicodeError):
        request_hash = digest({"invalid": True})
    return sealed(
        Decision,
        id=str(uuid4()),
        source="p003 pure offline policy engine",
        author="p003-engine",
        created_at=request.at if request else "1970-01-01T00:00:00Z",
        decision="DENY" if reasons else "ALLOW",
        rationale=list(dict.fromkeys(reasons)) or ["ALL-GATES-MET"],
        matched_clauses=clauses,
        engagement_id=spec.engagement_id if spec else None,
        engagement_version=spec.version if spec else None,
        policy_digest=spec.content_digest if spec else None,
        approval_digest=approval.content_digest if approval else None,
        request_digest=request_hash,
        remaining_constraints=[
            "Point-in-time synthetic decision; recheck before each action.",
            "Caller budgets and actor labels are assertions, not authentication.",
            "Legal authority and target enforcement NOT VERIFIED.",
        ],
    )
