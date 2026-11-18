"""Owned local retention planning and audited engagement tombstones."""

from datetime import timedelta

from p010.models import Link, RecordKind
from p010.safety import Invalid, digest, timestamp
from p010.workflow import Workflow

POLICY_VERSION = "p010-local-retention-1.0"
DAYS: dict[RecordKind, int] = {
    "engagement": 365,
    "source": 90,
    "evidence": 90,
    "observation": 180,
    "finding": 365,
    "risk": 365,
    "remediation": 180,
    "retest": 180,
    "retest-plan": 180,
    "acceptance": 365,
    "atlas": 365,
    "report": 365,
    "redmine-sync": 90,
}


def plan(flow: Workflow) -> dict:
    flow.require("CUSTODIAN")
    flow.store.verify()
    rows = flow.store.versions(flow.id)
    expires = [timestamp(row.envelope.created_at) + timedelta(days=DAYS[row.link.kind]) for row in rows]
    not_before = max([timestamp(flow.engagement.assessment_window.end), *expires])
    links = [row.link.model_dump(mode="json") for row in rows]
    value = {
        "engagement": flow.id,
        "policy": POLICY_VERSION,
        "records": links,
        "not_before": not_before.isoformat(),
        "days_by_record_type": DAYS,
        "audit": "Minimal tombstones retained for local integrity verification.",
        "scope": "Canonical SQLite records in this P-010 workspace. Source projects, integrations and exported copies are outside this purge.",
    }
    return {
        **value,
        "plan_sha256": digest(value),
        "eligible": bool(rows) and timestamp(flow.at) >= not_before,
    }


def purge(flow: Workflow, expected_sha256: str, confirm: str) -> dict:
    candidate = plan(flow)
    if (
        confirm != "p010-owned-engagement"
        or expected_sha256 != candidate["plan_sha256"]
        or not candidate["eligible"]
    ):
        raise Invalid("Retention purge requires the current eligible plan and exact confirmation")
    refs = [Link.model_validate(value) for value in candidate["records"]]
    count = flow.store.connection.execute("DELETE FROM records WHERE engagement=?", (flow.id,)).rowcount
    if count != len(refs):
        raise Invalid("Engagement changed while applying retention")
    flow.audit("retention-purge", "Purged expired local records and preserved minimal tombstones", refs)
    flow.store.verify()
    return {"status": "PASS", "purged": count, "plan_sha256": expected_sha256}
