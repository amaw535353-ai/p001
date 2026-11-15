"""Append-only, hash-linked SQLite events with transactional replay.

Local filesystem ownership is the trust anchor, not a human authentication service.
A database owner can replace the whole store or rewrite its hashes. This is not a
tamper-proof log, legal signature service, or multiuser security boundary.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from p003.models import (
    Amendment,
    Authorization,
    Decision,
    Engagement,
    Event,
    ReviewEvidence,
    StopEvent,
    sealed,
    verified,
)
from p003.policy import evaluate
from p003.util import canonical, clock, digest, load, now

OWNER = "p003-synthetic-store-v1"
UNBOUND = "P003-UNBOUND"


class View:
    def __init__(self, spec: Engagement):
        self.versions = {spec.version: spec}
        self.states = {spec.version: "DRAFT"}
        self.approvals: dict[int, Authorization] = {}
        self.current = spec.version
        self.stopped = False
        self.events: list[Event] = []

    @property
    def spec(self):
        return self.versions[self.current]

    @property
    def state(self):
        return self.states[self.current]

    def actor(self, ref, roles):
        actor = next((a for a in self.spec.actors if a.ref == ref and a.role in roles), None)
        if actor is None:
            raise ValueError("actor not permitted for this engagement")
        return actor


def keys(payload, expected):
    if set(payload) != set(expected):
        raise ValueError("event payload contract mismatch")


def unbound_decision(event):
    keys(event.payload, ["decision"])
    decision = Decision.model_validate(event.payload["decision"])
    verified(decision)
    if (
        event.actor != "p003-engine"
        or event.author != "p003-engine"
        or decision.decision != "DENY"
        or decision.engagement_id is not None
        or decision.policy_digest is not None
        or decision.approval_digest is not None
    ):
        raise ValueError("invalid unbound decision event")


def apply(view: View | None, event: Event) -> View:
    p = event.payload
    if event.actor != event.author:
        raise ValueError("event author/actor mismatch")
    if event.event_type == "create":
        keys(p, ["spec"])
        spec = Engagement.model_validate(p["spec"])
        verified(spec)
        if view is not None or spec.version != 1 or event.actor != spec.author:
            raise ValueError("invalid create event")
        view = View(spec)
    else:
        if view is None:
            raise ValueError("missing create event")
        if event.created_at < view.events[-1].created_at:
            raise ValueError("backdated event")
        if event.event_type == "decision":
            keys(p, ["decision"])
            decision = Decision.model_validate(p["decision"])
            verified(decision)
            if event.actor != "p003-engine" or decision.engagement_id != view.spec.engagement_id:
                raise ValueError("decision event mismatch")
        elif event.event_type == "amend":
            keys(p, ["spec", "amendment"])
            view.actor(event.actor, ["requestor"])
            if view.state not in ("DRAFT", "SUBMITTED", "APPROVED", "ACTIVE") or view.stopped:
                raise ValueError("cannot amend a stopped/terminal engagement; create a separate engagement")
            spec = Engagement.model_validate(p["spec"])
            verified(spec)
            amendment = Amendment.model_validate(p["amendment"])
            verified(amendment)
            if (
                spec.version != view.current + 1
                or spec.parent_digest != view.spec.content_digest
                or spec.engagement_id != view.spec.engagement_id
                or spec.client != view.spec.client
                or spec.tenant != view.spec.tenant
                or spec.author != event.actor
                or amendment.old_scope_digest != view.spec.content_digest
                or amendment.new_scope_digest != spec.content_digest
                or amendment.old_version != view.current
                or amendment.new_version != spec.version
            ):
                raise ValueError("amendment version/digest/client mismatch")
            # Pending amendments pause old scope too; conservative for all edits.
            view.states[view.current] = "SUSPENDED"
            view.current = spec.version
            view.versions[view.current] = spec
            view.states[view.current] = "DRAFT"
        elif event.event_type == "stop":
            keys(p, ["stop"])
            view.actor(event.actor, ["owner", "reviewer", "assessor"])
            stop = StopEvent.model_validate(p["stop"])
            verified(stop)
            if (
                stop.version != view.current
                or stop.engagement_id != view.spec.engagement_id
                or stop.author != event.actor
                or stop.effective_at != event.created_at
            ):
                raise ValueError("stop binding mismatch")
            if view.state in ("CLOSED", "REJECTED", "EXPIRED", "REVOKED"):
                raise ValueError("terminal engagement")
            view.states[view.current] = stop.status
            view.stopped = True
        else:
            if view.stopped:
                raise ValueError("stop overrides transition")
            if event.event_type == "approve":
                keys(p, ["authorization"])
                view.actor(event.actor, ["reviewer"])
                auth = Authorization.model_validate(p["authorization"])
                verified(auth)
                if (
                    view.state != "SUBMITTED"
                    or auth.author != event.actor
                    or auth.reviewer != event.actor
                    or auth.engagement_id != view.spec.engagement_id
                    or auth.version != view.current
                    or auth.policy_digest != view.spec.content_digest
                    or auth.window != view.spec.window
                    or auth.activities != view.spec.scope.activities
                    or auth.created_at != event.created_at
                    or auth.targets
                    != [
                        a.selector
                        for a in view.spec.assets
                        if a.asset_id in view.spec.scope.included_asset_ids
                    ]
                    or event.created_at >= auth.window.end
                ):
                    raise ValueError("approval does not bind the exact submitted version")
                view.approvals[view.current] = auth
                view.states[view.current] = "APPROVED"
                for version in view.versions:
                    if version < view.current:
                        view.states[version] = "SUPERSEDED"
            else:
                keys(p, ["version"])
                if type(p["version"]) is not int or p["version"] != view.current:
                    raise ValueError("stale transition version")
                if event.event_type == "submit":
                    view.actor(event.actor, ["requestor"])
                    if view.state != "DRAFT":
                        raise ValueError("only draft can be submitted")
                    view.states[view.current] = "SUBMITTED"
                elif event.event_type == "activate":
                    view.actor(event.actor, ["owner"])
                    if (
                        view.state != "APPROVED"
                        or view.current not in view.approvals
                        or not view.spec.window.start <= event.created_at < view.spec.window.end
                        or not view.spec.roe.window.start <= event.created_at < view.spec.roe.window.end
                        or not view.spec.roe.contact_confirmed
                        or not view.spec.roe.emergency_contact
                    ):
                        raise ValueError("activation prerequisites missing")
                    view.states[view.current] = "ACTIVE"
                elif event.event_type == "reject":
                    view.actor(event.actor, ["reviewer"])
                    if view.state != "SUBMITTED":
                        raise ValueError("only submitted can be rejected")
                    view.states[view.current] = "REJECTED"
                else:
                    raise ValueError("unknown event")
    if view.spec.engagement_id != event.engagement_id:
        raise ValueError("event engagement mismatch")
    view.events.append(event)
    return view


class Store:
    def __init__(self, path: Path, *, create=False):
        self.path = path.absolute()
        if any(p.is_symlink() for p in [self.path, *self.path.parents]):
            raise ValueError("store symlinks forbidden")
        marker = self.path / "owner.json"
        if create:
            if self.path.exists() and any(self.path.iterdir()) and not marker.exists():
                raise ValueError("refusing non-owned directory")
            self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not marker.exists():
                marker.write_text(json.dumps({"owner": OWNER}) + "\n")
                marker.chmod(0o600)
        if not marker.exists() or load(marker) != {"owner": OWNER}:
            raise ValueError("owned P-003 store absent; run demo init")
        if self.path.stat().st_mode & 0o077:
            raise ValueError("store must be private (mode 0700)")
        self.database = self.path / "events.sqlite3"
        if self.database.is_symlink():
            raise ValueError("database symlink forbidden")
        if create:
            with self.connect() as db:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,
                                                 event_json TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS no_event_update BEFORE UPDATE ON events
                  BEGIN SELECT RAISE(ABORT, 'append-only events'); END;
                CREATE TRIGGER IF NOT EXISTS no_event_delete BEFORE DELETE ON events
                  BEGIN SELECT RAISE(ABORT, 'append-only events'); END;
                """)
            self.database.chmod(0o600)
        elif not self.database.exists():
            raise ValueError("store database missing")

    def connect(self):
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def replay(self, db) -> dict[str, View]:
        views: dict[str, View] = {}
        previous = None
        record_ids: set[str] = set()
        for expected_seq, (seq, event_id, raw) in enumerate(
            db.execute("SELECT sequence,id,event_json FROM events ORDER BY sequence"), 1
        ):
            event = Event.model_validate(json.loads(raw))
            verified(event)
            if (
                seq != expected_seq
                or event.sequence != seq
                or event.id != event_id
                or event.previous_digest != previous
            ):
                raise ValueError("event chain/ID/sequence mismatch")
            ids = [event.id]
            for key in ("authorization", "amendment", "stop", "decision"):
                if key in event.payload:
                    ids.append(event.payload[key]["id"])
            if len(set(ids)) != len(ids) or record_ids.intersection(ids):
                raise ValueError("duplicated event/approval/decision record ID")
            record_ids.update(ids)
            if event.event_type == "create":
                incoming = Engagement.model_validate(event.payload["spec"])
                used = {a.ref for v in views.values() for a in v.spec.actors}
                if used & {a.ref for a in incoming.actors}:
                    raise ValueError("actor references cannot cross client engagements")
            if event.engagement_id == UNBOUND and event.event_type == "decision":
                unbound_decision(event)
            else:
                views[event.engagement_id] = apply(views.get(event.engagement_id), event)
            previous = event.content_digest
        return views

    def append(self, db, views, engagement_id, actor, kind, payload, at, purpose):
        clock(at)
        row = db.execute("SELECT sequence,event_json FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        seq, prev = (row[0] + 1, json.loads(row[1])["content_digest"]) if row else (1, None)
        event = sealed(
            Event,
            id=str(uuid4()),
            source="p003 local append-only workflow",
            author=actor,
            created_at=at,
            sequence=seq,
            engagement_id=engagement_id,
            event_type=kind,
            actor=actor,
            purpose=purpose,
            previous_digest=prev,
            payload=payload,
        )
        if engagement_id == UNBOUND and kind == "decision":
            unbound_decision(event)
            result = None
        else:
            result = apply(views.get(engagement_id), event)
        db.execute(
            "INSERT INTO events VALUES (?,?,?)",
            (seq, event.id, canonical(event.model_dump(mode="json")).decode()),
        )
        return result

    def create(self, spec: Engagement):
        with self.transaction() as db:
            views = self.replay(db)
            if spec.engagement_id in views or spec.engagement_id == UNBOUND:
                raise ValueError("engagement already exists")
            used = {a.ref for v in views.values() for a in v.spec.actors}
            if used & {a.ref for a in spec.actors}:
                raise ValueError("actors must be distinct across engagements")
            return self.append(
                db,
                views,
                spec.engagement_id,
                spec.author,
                "create",
                {"spec": spec.model_dump(mode="json")},
                spec.created_at,
                "synthetic draft creation",
            )

    def read(self, engagement_id, actor):
        with self.transaction() as db:
            view = self.replay(db)[engagement_id]
            view.actor(actor, ["requestor", "assessor", "reviewer", "owner"])
            return view

    def list_for(self, actor):
        with self.transaction() as db:
            return [v for v in self.replay(db).values() if any(a.ref == actor for a in v.spec.actors)]

    def evidence(self, view: View, auth: Authorization):
        path = self.path / "reviews" / (auth.evidence_ref + ".json")
        review = ReviewEvidence.model_validate(load(path))
        verified(review)
        if (
            digest(path.read_bytes()) != auth.evidence_sha256
            or review.policy_digest != view.spec.content_digest
            or review.engagement_id != view.spec.engagement_id
            or review.version != view.current
            or review.author != auth.author
            or review.reviewer != auth.author
            or review.evidence_ref != auth.evidence_ref
            or review.created_at > auth.created_at
        ):
            raise ValueError("review evidence binding/hash mismatch")
        return review

    def transition(
        self,
        engagement_id,
        actor,
        kind,
        *,
        version,
        at,
        purpose="explicit workflow transition",
        evidence_ref=None,
        simulate_review=False,
        expected_digest=None,
        spec=None,
        stop_status=None,
    ):
        with self.transaction() as db:
            views = self.replay(db)
            view = views[engagement_id]
            if version != view.current:
                raise ValueError("stale workflow version")
            payload: dict = {"version": version}
            if kind == "approve":
                view.actor(actor, ["reviewer"])
                if not simulate_review or expected_digest != view.spec.content_digest:
                    raise ValueError("explicit simulated review and exact policy digest required")
                # Validate references through the typed authorization before using a path.
                auth = sealed(
                    Authorization,
                    id=str(uuid4()),
                    source="explicit simulated training approval",
                    author=actor,
                    reviewer=actor,
                    created_at=at,
                    engagement_id=engagement_id,
                    version=version,
                    policy_digest=view.spec.content_digest,
                    evidence_ref=evidence_ref,
                    evidence_sha256="0" * 64,
                    checklist="SIMULATED-REVIEW-NOT-IDENTITY-VERIFICATION",
                    targets=[
                        a.selector
                        for a in view.spec.assets
                        if a.asset_id in view.spec.scope.included_asset_ids
                    ],
                    activities=view.spec.scope.activities,
                    window=view.spec.window,
                    exceptions=[],
                    revocation_history=[],
                )
                path = self.path / "reviews" / (auth.evidence_ref + ".json")
                auth = sealed(
                    Authorization,
                    **{**auth.model_dump(mode="json"), "evidence_sha256": digest(path.read_bytes())},
                )
                self.evidence(view, auth)
                payload = {"authorization": auth.model_dump(mode="json")}
            elif kind == "activate":
                if version not in view.approvals:
                    raise ValueError("approval missing")
                self.evidence(view, view.approvals[version])
            elif kind == "amend":
                if not isinstance(spec, Engagement):
                    raise ValueError("validated full new engagement version required")
                amendment = sealed(
                    Amendment,
                    id=str(uuid4()),
                    source="explicit scope amendment",
                    author=actor,
                    created_at=at,
                    engagement_id=engagement_id,
                    old_version=version,
                    new_version=spec.version,
                    old_scope_digest=view.spec.content_digest,
                    new_scope_digest=spec.content_digest,
                    reason=purpose,
                )
                payload = {
                    "spec": spec.model_dump(mode="json"),
                    "amendment": amendment.model_dump(mode="json"),
                }
            elif kind == "stop":
                stop = sealed(
                    StopEvent,
                    id=str(uuid4()),
                    source="explicit stop overrides",
                    author=actor,
                    created_at=at,
                    engagement_id=engagement_id,
                    version=version,
                    reason=purpose,
                    effective_at=at,
                    status=stop_status,
                    approval_link=None,
                )
                payload = {"stop": stop.model_dump(mode="json")}
            return self.append(db, views, engagement_id, actor, kind, payload, at, purpose)

    def check(self, raw: dict):
        with self.transaction() as db:
            views = self.replay(db)
            engagement_id = raw.get("engagement_id")
            view = views.get(engagement_id) if isinstance(engagement_id, str) else None
            valid = False
            auth = view.approvals.get(view.current) if view else None
            if auth and view:
                try:
                    self.evidence(view, auth)
                    valid = True
                except (ValueError, OSError):
                    valid = False
            decision = evaluate(
                view.spec if view else None,
                view.state if view else "ABSENT",
                auth,
                raw,
                evidence_valid=valid,
                stopped=view.stopped if view else True,
                active_since=next(
                    (e.created_at for e in reversed(view.events) if e.event_type == "activate"), None
                )
                if view
                else None,
            )
            if view:
                at = max(now(), view.events[-1].created_at)
                self.append(
                    db,
                    views,
                    view.spec.engagement_id,
                    "p003-engine",
                    "decision",
                    {"decision": decision.model_dump(mode="json")},
                    at,
                    "sanitized preflight audit",
                )
            else:
                self.append(
                    db,
                    views,
                    UNBOUND,
                    "p003-engine",
                    "decision",
                    {"decision": decision.model_dump(mode="json")},
                    now(),
                    "sanitized denial with no matching engagement",
                )
            return decision

    def reset(self, confirmation):
        """Archive the complete owned store; no recursive deletion or external cleanup."""
        if confirmation != "p003-local":
            raise ValueError("reset requires --confirm p003-local")
        with self.transaction() as db:
            self.replay(db)
        archive = self.path.with_name(self.path.name + ".archive-" + str(uuid4()))
        os.rename(self.path, archive)
        return archive.name
