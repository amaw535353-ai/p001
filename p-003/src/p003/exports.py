"""Sanitized planning artifacts; no generated assessment findings or legal claims."""

import html

from p003 import NOTICE
from p003.models import Artifact, EvidenceManifest, PolicyManifest, sealed
from p003.util import digest, uid


def envelope(view, kind, payload):
    record = sealed(
        Artifact,
        id=uid(view.spec.content_digest + ":" + kind),
        source="p003 generated " + kind,
        author="p003-exporter",
        reviewer=None,
        created_at=view.spec.created_at,
    ).model_dump(mode="json")
    record.update(kind=kind, **payload)
    model = PolicyManifest if kind == "engagement-policy" else EvidenceManifest
    return sealed(model, **record).model_dump(mode="json")


def policy_manifest(view):
    s = view.spec
    auth = view.approvals.get(view.current)
    return envelope(
        view,
        "engagement-policy",
        {
            "engagement_id": s.engagement_id,
            "engagement_version": s.version,
            "status": view.state,
            "policy_digest": s.content_digest,
            "scope": s.scope.model_dump(mode="json"),
            "target_inventory": [a.model_dump(mode="json") for a in s.assets],
            "window": s.window.model_dump(),
            "expires_at": s.window.end,
            "resource_limits_and_stops": s.roe.model_dump(mode="json"),
            "evidence_policy": s.evidence_policy.model_dump(mode="json"),
            "authority_provenance": auth.model_dump(mode="json") if auth else None,
            "ledger_head": view.events[-1].content_digest,
            "consumption": "Not a bearer capability. Re-read the current ledger and review evidence before every action.",
            "enforcement": "NOT VERIFIED: a future runner may ignore this export; no signature or online revocation feed.",
            "real_legal_authority": "NOT VERIFIED",
        },
    )


def evidence_manifest(view):
    return envelope(
        view,
        "evidence-manifest",
        {
            "engagement_id": view.spec.engagement_id,
            "engagement_version": view.current,
            "policy_digest": view.spec.content_digest,
            "chain_head": view.events[-1].content_digest,
            "artifacts": [
                {
                    "reference": event.id,
                    "sha256": event.content_digest,
                    "event_type": event.event_type,
                    "sequence": event.sequence,
                }
                for event in view.events
            ],
            "review_references": [
                {"reference": a.evidence_ref, "sha256": a.evidence_sha256} for a in view.approvals.values()
            ],
            "custody": "Local hash-linked records; not independently witnessed or tamper-proof",
            "sanitization": "Synthetic structured references only; review contents and tokens omitted",
            "learner_gates": {
                "G1": "NOT DEMONSTRATED",
                "G2": "NOT DEMONSTRATED",
                "G3": "NOT DEMONSTRATED",
                "G4": "NOT DEMONSTRATED",
            },
        },
    )


def markdown(view):
    s = view.spec
    parts = [
        "# AI Security Engagement Scoping, Authorization, and Rules-of-Engagement Toolkit",
        NOTICE,
        f"Schema: 1.0 | Source: p003 generated plan | Author: {s.author} | Reviewer: [UNFILLED]",
        f"Classification: synthetic-internal | Policy digest: {s.content_digest}",
        f"Engagement: {s.engagement_id} v{s.version} | Local workflow status: {view.state}",
        "This is automatically generated planning content. Recorded training approval is not legal authority, "
        "a legal signature, client identity verification, target enforcement or legal advice.",
        "Real legal authority, real signatory identity, and target-side enforcement: NOT VERIFIED.",
        "## Executive brief",
        "Goals: " + "; ".join(s.goals),
        "Client-supplied claims: [UNVERIFIED HUMAN INPUT REQUIRED]",
        "Assessor-observed results: [NOT TESTED — independent assessment required]",
        "Findings / residual risk / acceptance: [UNFILLED]",
        "## Intake and context",
        s.business_context,
        "## Roles",
        *[f"- {a.role}: {a.ref} (fictional actor label)" for a in s.actors],
        "## Scope and third parties",
        *[
            f"- {a.asset_id}: `{a.selector.value}`; {a.tenant}; {a.environment}; "
            f"methods {','.join(a.methods)}; {a.ownership}; included={a.included}"
            for a in s.assets
        ],
        *[f"- Exclusion: `{e.selector.value}` — {e.reason}" for e in s.scope.exclusions],
        "## AI trust boundaries and assumptions",
        *[f"- {b}" for a in s.assets for b in a.trust_boundaries],
        *[f"- Assumption: {x}" for x in s.risk_assumptions],
        "## Authorization placeholder",
        "Real-client representative, authority verification, legal review, signature: [UNFILLED]",
        "## Rules of engagement",
        f"UTC interval: [{s.window.start}, {s.window.end})",
        "Permitted classes: " + ", ".join(s.scope.activities),
        "Forbidden: " + ", ".join(s.roe.forbidden),
        f"Ceilings: {s.roe.max_total_requests} total / {s.roe.max_requests_per_minute} per minute; "
        f"cost units {s.roe.max_cost_units}; interruption {s.roe.max_interruption_ms} ms.",
        "Contact: " + str(s.roe.emergency_contact),
        "Stop: " + ", ".join(s.roe.stop_conditions),
        s.roe.recovery,
        "## Requirements and planned verification",
        *[
            f"- {r.requirement_id} (L{r.level}): {r.exact_text}\n  State: {r.state}; "
            f"applicability: {r.applicability}; method: {r.planned_method}"
            for r in s.requirements
        ],
        "AISVS content: OWASP AISVS v1.01, CC-BY-SA-4.0; source attribution in docs/aisvs-version-and-attribution.md.",
        "## Evidence and retention",
        f"Synthetic only; approved storage IDs: {', '.join(s.evidence_policy.storage_ids)}; "
        f"retention: {s.evidence_policy.retention_days} days; redact before export.",
        s.evidence_policy.incident_notification,
        s.evidence_policy.deletion,
        "## Change control and exceptions",
        "All changes require a new version and fresh review. No exception bypass exists.",
        "## Handoff and completion",
        "Evidence inventory / unresolved risks / client handoff / independent reviewer: [UNFILLED]",
        "G1–G4: NOT DEMONSTRATED. No human assessment or real authorization claimed.",
    ]
    text = html.escape("\n\n".join(parts), quote=False) + "\n"
    return text + "\nDocument SHA-256 (all bytes before this line): " + digest(text.encode()) + "\n"
