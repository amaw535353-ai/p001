"""Reproducible, conspicuously simulated fixtures; initialization never approves."""

import json

from p003 import NOTICE
from p003.frameworks import catalog
from p003.models import (
    Asset,
    Client,
    Engagement,
    EvidencePolicy,
    ROE,
    ReviewEvidence,
    Scope,
    sealed,
)
from p003.util import uid

START = "2026-11-15T09:00:00Z"
END = "2026-11-15T17:00:00Z"
CREATED = "2026-11-15T08:00:00Z"
AT = "2026-11-15T10:00:00Z"


def header(name, author, at=CREATED):
    return {
        "id": uid(name),
        "source": "p003 deterministic simulated fixture",
        "author": author,
        "created_at": at,
    }


def engagement(letter="A", seed=42):
    suffix = letter.lower()
    prefix = "demo-" + suffix
    author = prefix + "-requestor"
    client_id = "CLIENT-DEMO-" + letter
    tenant = "tenant-" + suffix
    actors = [
        {"ref": prefix + "-" + role, "role": role, "client_id": client_id, "tenant": tenant}
        for role in ("requestor", "assessor", "reviewer", "owner")
    ]
    window = {
        "start": START if letter == "A" else "2026-10-01T09:00:00Z",
        "end": END if letter == "A" else "2026-10-01T17:00:00Z",
    }
    client = sealed(
        Client,
        **header(prefix + ":client", author),
        client_id=client_id,
        name="Fictional " + ("Aster" if letter == "A" else "Birch") + " Research",
        caveats="Fictional roles and synthetic assets only; no legal or identity verification.",
    )
    asset = sealed(
        Asset,
        **header(prefix + ":asset", author),
        asset_id=prefix + "-health",
        tenant=tenant,
        owner=prefix + "-owner",
        service="fictional marker API",
        environment="local-lab",
        selector={"kind": "url", "value": f"http://127.0.0.1:{8000 if letter == 'A' else 8001}/health"},
        methods=["GET"],
        ownership="synthetic-owned",
        included=True,
        third_party_restrictions=[],
        trust_boundaries=["Local reviewer -> policy -> future runner"],
    )
    scope = sealed(
        Scope,
        **header(prefix + ":scope", author),
        included_asset_ids=[asset.asset_id],
        exclusions=[
            {
                "selector": {"kind": "url", "value": "http://127.0.0.1:8000/admin"},
                "reason": "Administrative mutation excluded from this exercise",
            }
        ],
        activities=["passive-inspection", "bounded-local-api"],
        procedures=["Review synthetic health contract without invoking a target from this tool."],
        project_ids=["P-003"],
        candidate_risk_ids=[],
        constraints=["No scanner execution, no redirects, exact paths and methods only."],
    )
    roe = sealed(
        ROE,
        **header(prefix + ":roe", author),
        window=window,
        allowed=scope.activities,
        forbidden=[
            "denial-of-service",
            "phishing",
            "exfiltration",
            "privilege-escalation",
            "persistence",
            "destruction",
        ],
        max_total_requests=100,
        max_requests_per_minute=10,
        max_cost_units=0,
        max_interruption_ms=0,
        source_identities=[prefix + "-workload"],
        emergency_contact=prefix + "-reviewer",
        contact_confirmed=True,
        stop_conditions=[
            "budget-exhausted",
            "contact-missing",
            "data-breach",
            "service-interruption",
            "human-stop",
        ],
        recovery="Stop the future runner and request an independent human review; no automatic resume.",
        communications="Fictional local handover only; never send messages from this toolkit.",
    )
    policy = sealed(
        EvidencePolicy,
        **header(prefix + ":evidence", author),
        storage_ids=["p003-private"],
        access_roles=["assessor", "reviewer", "owner"],
        retention_days=30,
        deletion="Archive owned training data; human reviews retention/deletion.",
        incident_notification="Stop immediately and prepare an unsent escalation notice.",
        custody_references=[],
    )
    requirements = []
    for key in ("v1.01-C5.2.1", "v1.01-C5.2.5", "v1.01-C5.3.1"):
        requirements.append(
            {
                **catalog()[key],
                "applicability": "Candidate control for later independent AI assessment; not a P-003 compliance claim.",
                "asset_ids": [asset.asset_id],
                "planned_method": "Independent review of actual target controls under approved scope.",
                "required_evidence": ["Sanitized independently observed behavior and target configuration"],
                "state": "planned",
            }
        )
    return sealed(
        Engagement,
        **header(prefix + ":engagement:" + str(seed), author),
        engagement_id="ENG-DEMO-" + letter,
        version=1,
        client=client,
        tenant=tenant,
        goals=["Prepare and independently review a fictional consultancy engagement."],
        engagement_type="configuration-audit",
        business_context=f"Synthetic training dataset seed {seed}.",
        risk_assumptions=["Local ownership is declared, not independently proven."],
        sponsors=[prefix + "-owner"],
        actors=actors,
        window=window,
        scope=scope,
        roe=roe,
        assets=[asset],
        evidence_policy=policy,
        requirements=requirements,
        parent_digest=None,
        change_reason="Initial fictional training draft.",
    )


def extension(spec):
    author = spec.author
    asset = sealed(
        Asset,
        **{
            **spec.assets[0].model_dump(mode="json"),
            "id": uid("demo-a:expanded-asset"),
            "asset_id": "demo-a-metadata",
            "selector": {"kind": "url", "value": "http://127.0.0.1:8000/metadata"},
        },
    )
    scope = sealed(
        Scope,
        **{
            **spec.scope.model_dump(mode="json"),
            "id": uid("demo-a:expanded-scope"),
            "included_asset_ids": [*spec.scope.included_asset_ids, asset.asset_id],
        },
    )
    return sealed(
        Engagement,
        **{
            **spec.model_dump(mode="json"),
            "id": uid("demo-a:version-2"),
            "author": author,
            "version": spec.version + 1,
            "assets": [*spec.assets, asset],
            "scope": scope,
            "parent_digest": spec.content_digest,
            "change_reason": "Request metadata endpoint; no inherited permission.",
        },
    )


def request(**overrides):
    return {
        "schema_version": "1.0",
        "notice": NOTICE,
        "engagement_id": "ENG-DEMO-A",
        "engagement_version": 1,
        "actor": "demo-a-assessor",
        "test_class": "passive-inspection",
        "target": {"kind": "url", "value": "http://127.0.0.1:8000/health"},
        "at": AT,
        "budget": {
            "used_total": 0,
            "used_last_minute": 0,
            "requested": 1,
            "used_cost_units": 0,
            "requested_cost_units": 0,
            "interruption_ms": 0,
        },
        "context": {
            "tenant": "tenant-a",
            "environment": "local-lab",
            "method": "GET",
            "source_identity": "demo-a-workload",
            "checkpoint_completed": True,
            "contact_available": True,
            "redirects_expected": False,
            "data_class": "synthetic-only",
            "storage_id": "p003-private",
            "redaction_confirmed": True,
            "data_breach": False,
        },
        **overrides,
    }


def review(spec):
    actor = next(a.ref for a in spec.actors if a.role == "reviewer")
    return sealed(
        ReviewEvidence,
        **header(f"{spec.engagement_id}:{spec.version}:simulated-review", actor),
        reviewer=actor,
        evidence_ref=f"training-review-{spec.engagement_id[-1].lower()}-v{spec.version}",
        engagement_id=spec.engagement_id,
        version=spec.version,
        policy_digest=spec.content_digest,
        checklist="SIMULATED-REVIEW-NOT-IDENTITY-VERIFICATION",
        reviewed=True,
    )


def install_review(store, spec):
    record = review(spec)
    folder = store.path / "reviews"
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / (record.evidence_ref + ".json")
    if path.exists():
        raise ValueError("review fixture exists; do not overwrite review evidence")
    path.write_text(json.dumps(record.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n")
    path.chmod(0o600)
    return record.evidence_ref


def init(store, seed=42):
    for letter in ("A", "B"):
        spec = engagement(letter, seed)
        store.create(spec)
        install_review(store, spec)
    return {
        "status": "CREATED-DRAFTS-ONLY",
        "approval": "requires explicit separate simulated review action",
        "clock": AT,
        "engagements": ["ENG-DEMO-A", "ENG-DEMO-B"],
    }
