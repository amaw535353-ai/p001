from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3

import pytest

from p003 import demo
from p003.models import Engagement, Event, Scope, sealed
from p003.store import Store
from p003.util import canonical, load


def submit(draft):
    return draft.transition("ENG-DEMO-A", "demo-a-requestor", "submit", version=1, at="2026-11-15T08:10:00Z")


def approve(draft, actor="demo-a-reviewer", **overrides):
    spec = demo.engagement()
    options = dict(
        version=1,
        at="2026-11-15T08:20:00Z",
        simulate_review=True,
        expected_digest=spec.content_digest,
        evidence_ref="training-review-a-v1",
    )
    options.update(overrides)
    return draft.transition("ENG-DEMO-A", actor, "approve", **options)


def test_initialization_never_approves(tmp_path):
    store = Store(tmp_path / "store", create=True)
    demo.init(store)
    assert store.read("ENG-DEMO-A", "demo-a-owner").state == "DRAFT"
    assert store.check(demo.request()).decision == "DENY"


def test_explicit_training_approval_and_activation(draft):
    submit(draft)
    assert approve(draft).state == "APPROVED"
    assert (
        draft.transition("ENG-DEMO-A", "demo-a-owner", "activate", version=1, at=demo.START).state == "ACTIVE"
    )
    assert draft.check(demo.request()).decision == "ALLOW"


@pytest.mark.parametrize("actor", ["demo-a-requestor", "demo-a-assessor", "demo-a-owner", "demo-b-reviewer"])
def test_self_or_wrong_role_approval_refused(draft, actor):
    submit(draft)
    with pytest.raises(ValueError):
        approve(draft, actor)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"simulate_review": False},
        {"expected_digest": "0" * 64},
        {"evidence_ref": "missing-review"},
        {"evidence_ref": "../../bad"},
    ],
)
def test_review_prerequisites(draft, kwargs):
    submit(draft)
    with pytest.raises((ValueError, OSError)):
        approve(draft, **kwargs)


def test_template_alone_and_out_of_order_events_not_approval(draft):
    with pytest.raises(ValueError):
        approve(draft)
    with pytest.raises(ValueError):
        draft.transition("ENG-DEMO-A", "demo-a-owner", "activate", version=1, at=demo.START)


@pytest.mark.parametrize(
    "kind,status",
    [("SUSPENDED", "SUSPENDED"), ("REVOKED", "REVOKED"), ("CLOSED", "CLOSED"), ("EXPIRED", "EXPIRED")],
)
def test_stop_overrides_and_cannot_reactivate(active, kind, status):
    active.transition(
        "ENG-DEMO-A",
        "demo-a-owner",
        "stop",
        version=1,
        at=demo.AT,
        stop_status=kind,
        purpose="synthetic stop",
    )
    assert active.read("ENG-DEMO-A", "demo-a-owner").state == status
    assert active.check(demo.request(at="2026-11-15T09:59:00Z")).decision == "DENY"
    with pytest.raises(ValueError):
        active.transition("ENG-DEMO-A", "demo-a-owner", "activate", version=1, at="2026-11-15T10:01:00Z")


def test_missing_and_modified_evidence_deny(active):
    path = active.path / "reviews/training-review-a-v1.json"
    raw = path.read_bytes()
    path.write_bytes(raw + b" ")  # Model digest unchanged; file hash still must detect it.
    assert "REVIEW-EVIDENCE-INVALID" in active.check(demo.request()).rationale
    path.unlink()
    assert "REVIEW-EVIDENCE-INVALID" in active.check(demo.request()).rationale


def test_pending_amendment_and_old_version_replay_denied(active):
    first = active.read("ENG-DEMO-A", "demo-a-requestor").spec
    second = demo.extension(first)
    view = active.transition(
        "ENG-DEMO-A",
        "demo-a-requestor",
        "amend",
        version=1,
        at=demo.AT,
        spec=second,
        purpose="Request additional metadata target",
    )
    assert view.state == "DRAFT" and view.states[1] == "SUSPENDED"
    assert active.check(demo.request()).decision == "DENY"
    assert active.check(demo.request(engagement_version=2)).decision == "DENY"


def test_fresh_reapproval_supersedes_old_scope(active, monkeypatch):
    monkeypatch.setattr("p003.store.now", lambda: demo.AT)
    first = active.read("ENG-DEMO-A", "demo-a-requestor").spec
    second = demo.extension(first)
    active.transition(
        "ENG-DEMO-A",
        "demo-a-requestor",
        "amend",
        version=1,
        at=demo.AT,
        spec=second,
        purpose="Synthetic scope extension",
    )
    demo.install_review(active, second)
    active.transition("ENG-DEMO-A", "demo-a-requestor", "submit", version=2, at=demo.AT)
    with pytest.raises(ValueError):
        active.transition(
            "ENG-DEMO-A",
            "demo-a-reviewer",
            "approve",
            version=2,
            at=demo.AT,
            simulate_review=True,
            expected_digest=second.content_digest,
            evidence_ref="training-review-a-v1",
        )
    active.transition(
        "ENG-DEMO-A",
        "demo-a-reviewer",
        "approve",
        version=2,
        at=demo.AT,
        simulate_review=True,
        expected_digest=second.content_digest,
        evidence_ref="training-review-a-v2",
    )
    view = active.transition("ENG-DEMO-A", "demo-a-owner", "activate", version=2, at=demo.AT)
    assert view.states[1] == "SUPERSEDED"
    assert active.check(demo.request()).decision == "DENY"
    raw = demo.request(
        engagement_version=2, target={"kind": "url", "value": "http://127.0.0.1:8000/metadata"}
    )
    assert active.check(raw).decision == "ALLOW"


def test_scope_reduction_also_requires_new_version(active):
    spec = active.read("ENG-DEMO-A", "demo-a-requestor").spec
    scope = sealed(Scope, **{**spec.scope.model_dump(mode="json"), "activities": ["passive-inspection"]})
    reduced = sealed(
        Engagement,
        **{
            **spec.model_dump(mode="json"),
            "version": 2,
            "parent_digest": spec.content_digest,
            "scope": scope,
        },
    )
    view = active.transition("ENG-DEMO-A", "demo-a-requestor", "amend", version=1, at=demo.AT, spec=reduced)
    assert view.state == "DRAFT" and 2 not in view.approvals


def test_two_clients_label_based_access_filter(draft):
    draft.create(demo.engagement("B"))
    assert [v.spec.engagement_id for v in draft.list_for("demo-a-assessor")] == ["ENG-DEMO-A"]
    with pytest.raises(ValueError):
        draft.read("ENG-DEMO-B", "demo-a-assessor")
    with pytest.raises(ValueError):
        draft.transition("ENG-DEMO-B", "demo-a-requestor", "submit", version=1, at=demo.AT)
    # This is label filtering, not OS authentication or proof of different people.


def test_duplicate_approval_and_event_id_refused(draft):
    submit(draft)
    approve(draft)
    with pytest.raises(ValueError):
        approve(draft)
    with draft.connect() as db:
        row = db.execute("SELECT id,event_json FROM events LIMIT 1").fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO events VALUES (999,?,?)", row)
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("DELETE FROM events")


def test_forged_approval_rejected_during_replay(draft):
    submit(draft)
    approve(draft)
    with draft.connect() as db:
        raw = json.loads(db.execute("SELECT event_json FROM events WHERE sequence=3").fetchone()[0])
        raw["actor"] = raw["author"] = "demo-a-assessor"
        raw["payload"]["authorization"]["author"] = "demo-a-assessor"
        # Even recomputing the event envelope cannot bypass role/binding validation.
        raw["payload"]["authorization"].pop("content_digest")
        from p003.models import Authorization

        raw["payload"]["authorization"] = sealed(Authorization, **raw["payload"]["authorization"]).model_dump(
            mode="json"
        )
        forged = sealed(Event, **raw)
        db.execute("DROP TRIGGER no_event_update")  # Deliberate owned test corruption.
        db.execute(
            "UPDATE events SET event_json=? WHERE sequence=3",
            (canonical(forged.model_dump(mode="json")).decode(),),
        )
    with pytest.raises(ValueError):
        draft.read("ENG-DEMO-A", "demo-a-owner")


def test_concurrent_approve_suspend_serialized(draft):
    submit(draft)

    def operation(kind):
        try:
            if kind == "approve":
                approve(draft)
            else:
                draft.transition(
                    "ENG-DEMO-A",
                    "demo-a-reviewer",
                    "stop",
                    version=1,
                    at="2026-11-15T08:20:00Z",
                    stop_status="SUSPENDED",
                    purpose="emergency stop",
                )
            return "ok"
        except ValueError:
            return "refused"

    with ThreadPoolExecutor(max_workers=2) as executor:
        result = list(executor.map(operation, ["approve", "stop"]))
    assert result[1] == "ok"
    assert draft.read("ENG-DEMO-A", "demo-a-owner").state == "SUSPENDED"
    assert draft.check(demo.request()).decision == "DENY"


def test_reset_archives_only_owned_store_and_reconstructs(draft, tmp_path):
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("preserve unrelated work")
    with pytest.raises(ValueError):
        draft.reset("wrong")
    archived = draft.reset("p003-local")
    assert (tmp_path / archived / "reviews/training-review-a-v1.json").exists()
    assert unrelated.read_text() == "preserve unrelated work"
    assert not draft.path.exists()
    restored = Store(draft.path, create=True)
    demo.init(restored)
    assert restored.read("ENG-DEMO-A", "demo-a-owner").state == "DRAFT"


def test_non_owned_directory_and_symlink_refused(tmp_path):
    path = tmp_path / "other"
    path.mkdir()
    (path / "notes.txt").write_text("user notes")
    with pytest.raises(ValueError):
        Store(path, create=True)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        Store(link, create=True)


def test_backdated_and_stale_transition_refused(active):
    with pytest.raises(ValueError):
        active.transition(
            "ENG-DEMO-A",
            "demo-a-owner",
            "stop",
            version=1,
            at="2026-11-15T08:00:00Z",
            stop_status="SUSPENDED",
        )
    with pytest.raises(ValueError):
        active.transition(
            "ENG-DEMO-A", "demo-a-owner", "stop", version=2, at=demo.AT, stop_status="SUSPENDED"
        )


def test_unknown_extra_fields_and_bad_digest_refused():
    raw = demo.engagement().model_dump(mode="json")
    raw["scope"]["allow_public"] = True
    with pytest.raises(ValueError):
        Engagement.model_validate(raw)
    raw = demo.engagement().model_dump(mode="json")
    raw["scope"]["activities"].append("config-review")
    with pytest.raises(ValueError):
        Engagement.model_validate(raw)


def test_evidence_path_model_rejects_traversal(draft):
    assert load(draft.path / "owner.json")["owner"] == "p003-synthetic-store-v1"
    submit(draft)
    with pytest.raises(ValueError):
        approve(draft, evidence_ref="../training-review-a-v1")


def test_missing_engagement_decision_is_still_audited(draft):
    result = draft.check(demo.request(engagement_id="UNTRUSTED-ENGAGEMENT-LABEL"))
    assert result.decision == "DENY"
    with draft.connect() as db:
        rows = [json.loads(row[0]) for row in db.execute("SELECT event_json FROM events")]
    recorded = [e for e in rows if e["engagement_id"] == "P003-UNBOUND"]
    assert len(recorded) == 1 and recorded[0]["payload"]["decision"]["id"] == result.id
    assert "UNTRUSTED-ENGAGEMENT-LABEL" not in canonical(recorded).decode()
    assert draft.read("ENG-DEMO-A", "demo-a-owner").state == "DRAFT"
