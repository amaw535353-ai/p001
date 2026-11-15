"""Real P-003 evaluation and a narrower, independent local observation ceiling."""

from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import os
import re
import sqlite3
import threading
import time
from urllib.parse import urlsplit

from pydantic import Field

from p004.graph import stable
from p004.models import SHA, Ref, Strict
from p004.safety import Invalid, address, load


class Denied(Invalid):
    pass


class OwnedTarget(Strict):
    schema_version: str = "p004-owned-target-v1"
    owner: str = "p004-local-fixture"
    instance_id: Ref
    origin: str
    tenant_id: Ref
    safe_paths: list[str] = Field(min_length=1, max_length=16)
    synthetic_only: bool


class LiveContext(Strict):
    engagement_id: Ref
    approved_engagement_version: int = Field(ge=1)
    policy_digest: SHA
    actor: Ref
    tenant: Ref
    source_identity: Ref
    storage_id: Ref
    checkpoint_completed: bool
    contact_available: bool
    redaction_confirmed: bool


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_url(value: str) -> str:
    # No hostname aliases, DNS, IPv6 expansion, userinfo, percent encoding or query strings.
    if any(x in value for x in ("?", "#", "@", "%", "\\")) or not value.isascii():
        raise Denied("URL-AMBIGUITY")
    try:
        p = urlsplit(value)
        normalized = address(value)
        if (
            p.scheme != "http"
            or p.hostname != "127.0.0.1"
            or not re.fullmatch(r"127\.0\.0\.1:[0-9]+", p.netloc)
        ):
            raise Denied("LITERAL-LOCAL-HTTP-ONLY")
        if re.search(
            r"(?:^|/)(?:logout|delete|admin|reset|create|submit|shutdown|execute)(?:/|$)", p.path, re.I
        ):
            raise Denied("SIDE-EFFECT-PATH")
        return normalized
    except (ValueError, TypeError) as exc:
        raise Denied("UNSAFE-LOCAL-URL") from exc


class P003Adapter:
    """Reads the real ledger without appending decisions or changing approval state.

    No exported policy file or mock is a live substitute. Local filesystem ownership
    is the trust anchor inherited from P-003, not a multiuser security boundary.
    """

    def __init__(self, store_path: Path, context: LiveContext):
        from p003.store import Store

        self.store = Store(store_path)
        self.context = context
        self.policy_digest = context.policy_digest

    def authorize(self, url, method, used_total, used_minute):
        from p003.policy import evaluate

        c = self.context
        raw = dict(
            engagement_id=c.engagement_id,
            engagement_version=c.approved_engagement_version,
            actor=c.actor,
            test_class="passive-inspection",
            target={"kind": "url", "value": url},
            at=utc_now(),
            budget=dict(
                used_total=used_total,
                used_last_minute=used_minute,
                requested=1,
                used_cost_units=0,
                requested_cost_units=0,
                interruption_ms=0,
            ),
            context=dict(
                tenant=c.tenant,
                environment="local-lab",
                method=method,
                source_identity=c.source_identity,
                checkpoint_completed=c.checkpoint_completed,
                contact_available=c.contact_available,
                redirects_expected=False,
                data_class="synthetic-only",
                storage_id=c.storage_id,
                redaction_confirmed=c.redaction_confirmed,
                data_breach=False,
            ),
        )
        try:
            with sqlite3.connect(self.store.database.as_uri() + "?mode=ro", uri=True, timeout=1) as db:
                db.execute("BEGIN")
                views = self.store.replay(db)
                view = views.get(c.engagement_id)
                if (
                    view is None
                    or view.current != c.approved_engagement_version
                    or view.spec.content_digest != c.policy_digest
                ):
                    raise Denied("P003-IMMUTABLE-BINDING-MISMATCH")
                approval = view.approvals.get(view.current)
                evidence_valid = bool(approval and self.store.evidence(view, approval))
                decision = evaluate(
                    view.spec,
                    view.state,
                    approval,
                    raw,
                    evidence_valid=evidence_valid,
                    stopped=view.stopped,
                    active_since=next(
                        (e.created_at for e in reversed(view.events) if e.event_type == "activate"), None
                    ),
                )
                result = decision.model_dump(mode="json")
                if result["decision"] != "ALLOW":
                    raise Denied("P003-DENIED-" + "-".join(result["rationale"]))
                # Independently require the exact URL asset, never a CIDR/host grant.
                if not any(
                    a.included
                    and a.asset_id in view.spec.scope.included_asset_ids
                    and a.selector.kind == "url"
                    and a.selector.value == url
                    and a.ownership == "synthetic-owned"
                    for a in view.spec.assets
                ):
                    raise Denied("P003-EXACT-URL-ASSET-REQUIRED")
                return dict(
                    decision_id=decision.id,
                    request_digest=decision.request_digest,
                    policy_digest=decision.policy_digest,
                    decision="ALLOW",
                    engagement_id=c.engagement_id,
                    approved_engagement_version=c.approved_engagement_version,
                    target=url,
                    method=method,
                    at=raw["at"],
                )
        except Denied:
            raise
        except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
            raise Denied("P003-UNAVAILABLE-OR-INVALID") from exc


class Guard:
    def __init__(
        self,
        adapter: P003Adapter | None,
        owned: OwnedTarget,
        *,
        max_requests=30,
        max_seconds=120,
        max_per_minute=30,
        clock=time.monotonic,
    ):
        if not isinstance(adapter, P003Adapter):
            raise Denied("REAL-P003-ADAPTER-REQUIRED")
        if any(
            os.environ.get(name)
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
        ):
            raise Denied("AMBIENT-PROXY-SETTINGS-REFUSED")
        if not 1 <= max_requests <= 30 or not 1 <= max_seconds <= 120 or not 1 <= max_per_minute <= 30:
            raise Denied("HARD-BUDGET-CEILING")
        if (
            owned.schema_version != "p004-owned-target-v1"
            or owned.owner != "p004-local-fixture"
            or owned.synthetic_only is not True
        ):
            raise Denied("OWNED-SYNTHETIC-FIXTURE-REQUIRED")
        origin = local_url(owned.origin + "/" if not owned.origin.endswith("/") else owned.origin)
        if urlsplit(origin).path != "/" or owned.tenant_id != adapter.context.tenant:
            raise Denied("OWNERSHIP-TENANT-OR-ORIGIN")
        self.origin = origin.removesuffix("/")
        self.allowed = {local_url(self.origin + p) for p in owned.safe_paths}
        self.adapter = adapter
        self.owned = owned
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self.max_per_minute = max_per_minute
        self.clock = clock
        self.started = clock()
        self.used = 0
        self.recent: deque[float] = deque()
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.decisions: list[dict] = []

    def check(self, url, method="GET", depth=0, *, consume=False):
        if self.stopped.is_set():
            raise Denied("STOP-WORK")
        if self.clock() - self.started >= self.max_seconds:
            raise Denied("DURATION-LIMIT")
        if method not in ("GET", "HEAD") or depth != 0:
            raise Denied("SAFE-FIXED-NAVIGATION-ONLY")
        normalized = local_url(url)
        if normalized not in self.allowed:
            raise Denied("TARGET-NOT-EXACTLY-REVIEWED")
        while self.recent and self.clock() - self.recent[0] >= 60:
            self.recent.popleft()
        if self.used >= self.max_requests or len(self.recent) >= self.max_per_minute:
            raise Denied("REQUEST-OR-RATE-BUDGET")
        decision = self.adapter.authorize(normalized, method, self.used, len(self.recent))
        if consume:
            self.used += 1
            self.recent.append(self.clock())
            self.decisions.append({**decision, "event_id": stable("decision", decision["decision_id"])})
        return normalized


def read_owned(path: Path) -> OwnedTarget:
    return OwnedTarget.model_validate(load(path.parent, path.name))
