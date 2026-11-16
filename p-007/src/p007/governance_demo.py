"""Disposable simulated P-003 review for owned engineering fixtures only.

This never claims a human reviewed anything. It is called only by the explicit
local-demo command and tests, not by ordinary offline plan/run.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from p007.models import AuthorizationReference, Target


def simulated_ledger(
    target: Target, path: Path, *, state="ACTIVE", methods=None, activities=None, expired=False
) -> tuple:
    from p003 import demo
    from p003.models import Asset, Engagement, ROE, ReviewEvidence, Scope, sealed
    from p003.store import Store
    from p003.util import uid

    now = datetime.now(timezone.utc)

    def at(seconds):
        return (now + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    window = {"start": at(-600), "end": at(-1 if expired else 1800)}
    base = demo.engagement()
    paths = sorted({o.path for o in target.operations})
    assets = [
        sealed(
            Asset,
            **{
                **base.assets[0].model_dump(mode="json"),
                "id": uid("p007:" + target.instance_id + route),
                "asset_id": "p007-path-" + str(i),
                "selector": {"kind": "url", "value": target.origin + route},
                "methods": methods or ["GET"],
                "service": "p007 owned synthetic fixture",
            },
        )
        for i, route in enumerate(paths)
    ]
    scope = sealed(
        Scope,
        **{
            **base.scope.model_dump(mode="json"),
            "included_asset_ids": [a.asset_id for a in assets],
            "exclusions": [],
            "activities": activities or ["passive-inspection", "bounded-local-api"],
            "project_ids": ["P-007"],
            "constraints": ["P007 in-process loopback lease only", "No active scans, no redirects"],
        },
    )
    roe = sealed(
        ROE,
        **{
            **base.roe.model_dump(mode="json"),
            "window": window,
            "allowed": scope.activities,
            "max_total_requests": 512,
            "max_requests_per_minute": 60,
        },
    )
    spec = sealed(
        Engagement,
        **{
            **base.model_dump(mode="json"),
            "id": uid("p007:" + target.instance_id),
            "created_at": at(-590),
            "assets": assets,
            "scope": scope.model_dump(mode="json"),
            "roe": roe.model_dump(mode="json"),
            "window": window,
            "requirements": [],
            "business_context": "Codex synthetic engineering exercise; no human approval claim",
        },
    )
    store = Store(path, create=True)
    store.create(spec)
    record = sealed(
        ReviewEvidence,
        **{
            **demo.review(spec).model_dump(mode="json"),
            "created_at": at(-585),
            "source": "Codex simulated engineering review; human NOT DEMONSTRATED",
        },
    )
    reviews = store.path / "reviews"
    reviews.mkdir(mode=0o700)
    file = reviews / (record.evidence_ref + ".json")
    from p007.safety import canonical, write_new

    write_new(file, canonical(record.model_dump(mode="json")))
    store.transition(spec.engagement_id, "demo-a-requestor", "submit", version=1, at=at(-580))
    if state != "MISSING":
        store.transition(
            spec.engagement_id,
            "demo-a-reviewer",
            "approve",
            version=1,
            at=at(-570),
            simulate_review=True,
            expected_digest=spec.content_digest,
            evidence_ref=record.evidence_ref,
        )
        store.transition(spec.engagement_id, "demo-a-owner", "activate", version=1, at=at(-560))
        if state == "REVOKED":
            store.transition(
                spec.engagement_id, "demo-a-owner", "stop", version=1, at=at(-10), stop_status="REVOKED"
            )
    reference = AuthorizationReference(
        engagement_id=spec.engagement_id,
        engagement_version=1,
        policy_digest=spec.content_digest,
        store_path=str(store.path),
        actor="demo-a-assessor",
        tenant="tenant-a",
        source_identity="demo-a-workload",
        storage_id="p003-private",
        checkpoint_completed=True,
        contact_available=True,
        redaction_confirmed=True,
    )
    return store, reference
