"""Fresh P-003 ledger replay and exact loopback enforcement before every request."""

from collections import deque
from datetime import datetime, timezone
import http.client
import re
import socket
import sqlite3
import threading
import time
from urllib.parse import urlsplit

from p007.models import AuthorizationReference, Target, TestCase
from p007.safety import Blocked


def local_url(value: str) -> str:
    if not isinstance(value, str) or not value.isascii() or re.search(r"[\s%@?#\\]", value):
        raise Blocked("URL-AMBIGUITY")
    try:
        p = urlsplit(value)
        if p.scheme != "http" or p.hostname != "127.0.0.1" or p.username or p.password or not p.port:
            raise Blocked("LITERAL-LOOPBACK-ONLY")
        if p.netloc != f"127.0.0.1:{p.port}" or not re.fullmatch(r"/(?:[A-Za-z0-9_/-]*)", p.path):
            raise Blocked("NONCANONICAL-LOCAL-URL")
    except ValueError as exc:
        raise Blocked("INVALID-LOCAL-URL") from exc
    return value


def resolve_mapping(target: Target) -> None:
    host = urlsplit(local_url(target.origin + "/")).hostname
    rows = socket.getaddrinfo(host, urlsplit(target.origin).port, socket.AF_INET, socket.SOCK_STREAM)
    if not rows or {str(x[4][0]) for x in rows} != set(target.allowed_ips):
        raise Blocked("DESTINATION-MAPPING-CHANGED")


class P003Reader:
    """Read-only actual ledger, current approval and review-evidence validation."""

    def __init__(self, reference: AuthorizationReference):
        from pathlib import Path
        from p003.store import Store

        self.ref = reference
        self.store = Store(Path(reference.store_path))

    def authorize(self, url, method, category, test_class, used, requested=1) -> dict:
        from p003.policy import evaluate

        c = self.ref
        at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = dict(
            engagement_id=c.engagement_id,
            engagement_version=c.engagement_version,
            actor=c.actor,
            test_class=test_class,
            target={"kind": "url", "value": url},
            at=at,
            budget=dict(
                used_total=used,
                used_last_minute=used,
                requested=requested,
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
                view = self.store.replay(db).get(c.engagement_id)
                if (
                    view is None
                    or view.current != c.engagement_version
                    or view.spec.content_digest != c.policy_digest
                ):
                    raise Blocked("P003-BINDING-MISMATCH")
                approval = view.approvals.get(view.current)
                valid = False
                if approval:
                    self.store.evidence(view, approval)
                    valid = True
                decision = evaluate(
                    view.spec,
                    view.state,
                    approval,
                    raw,
                    evidence_valid=valid,
                    stopped=view.stopped,
                    active_since=next(
                        (e.created_at for e in reversed(view.events) if e.event_type == "activate"), None
                    ),
                )
                if decision.decision != "ALLOW":
                    raise Blocked("P003-DENIED:" + ",".join(decision.rationale))
                if not any(
                    a.included
                    and a.asset_id in view.spec.scope.included_asset_ids
                    and a.selector.kind == "url"
                    and a.selector.value == url
                    and method in a.methods
                    and a.ownership == "synthetic-owned"
                    for a in view.spec.assets
                ):
                    raise Blocked("P003-EXACT-ASSET-REQUIRED")
                return {
                    "reference": c.engagement_id,
                    "version": c.engagement_version,
                    "policy_digest": c.policy_digest,
                    "decision_digest": decision.content_digest,
                    "request_digest": decision.request_digest,
                    "decision": "ALLOW",
                    "at": at,
                    "category": category,
                    "method": method,
                    "origin_path": url,
                    "legal_authority": "NOT VERIFIED",
                    "review": "SIMULATED-CODEX-EXERCISE",
                }
        except Blocked:
            raise
        except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
            raise Blocked("P003-UNAVAILABLE-OR-INVALID") from exc


class Guard:
    def __init__(self, target: Target, reader: P003Reader | None, lease, test: TestCase):
        from p007.fixture import FixtureLease

        if not isinstance(lease, FixtureLease) or not lease.active or lease.target != target:
            raise Blocked("OWNED-IN-PROCESS-LEASE-REQUIRED")
        if not isinstance(reader, P003Reader):
            raise Blocked("REAL-P003-READER-REQUIRED")
        local_url(target.origin + "/")
        self.target, self.reader, self.lease, self.test = target, reader, lease, test
        self.started = time.monotonic()
        self.used = 0
        self.recent: deque[float] = deque()
        self.decisions: list[dict] = []
        self.lock = threading.Lock()
        self.stopped = False

    def check(self, url: str, method="GET", *, consume=False):
        if self.stopped or not self.lease.active:
            raise Blocked("STOPPED-OR-EXPIRED-LEASE")
        if time.monotonic() - self.started >= self.test.limits.timeout_seconds:
            raise Blocked("TIME-BUDGET")
        local_url(url)
        if not url.startswith(self.target.origin + "/"):
            raise Blocked("ORIGIN-NOT-ALLOWLISTED")
        path = urlsplit(url).path
        if not any(
            o.path == path and o.method == method and o.category == self.test.category
            for o in self.target.operations
        ):
            raise Blocked("METHOD-ROUTE-CATEGORY-NOT-ALLOWED")
        if self.test.category == "active_scan" or self.test.authorization_class == "active-scan":
            raise Blocked("ACTIVE-ZAP-UNSUPPORTED-FAIL-CLOSED")
        if self.test.offline_only:
            raise Blocked("OFFLINE-TEST-CANNOT-SEND-TRAFFIC")
        if self.used >= self.test.limits.requests:
            raise Blocked("REQUEST-BUDGET")
        resolve_mapping(self.target)
        decision = self.reader.authorize(
            url, method, self.test.category, self.test.authorization_class, self.used
        )
        if consume:
            self.used += 1
            self.decisions.append(decision)
        return url


class GuardedHTTP:
    """No ambient proxies, DNS hostname connect, redirects or caller headers."""

    def __init__(self, guard: Guard):
        self.guard = guard

    def request(self, url: str, method="GET", *, session=None) -> dict:
        guard = self.guard
        if not guard.lock.acquire(blocking=False):
            raise Blocked("CONCURRENCY-BUDGET")
        connection = None
        try:
            guard.check(url, method)
            p = urlsplit(url)
            wire = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                wire.settimeout(min(3, guard.test.limits.timeout_seconds))
                guard.check(url, method)
                wire.connect(("127.0.0.1", p.port))
                if wire.getpeername()[0] != "127.0.0.1":
                    raise Blocked("PEER-MISMATCH")
                guard.check(url, method, consume=True)
                headers = {"User-Agent": "p007-synthetic/1.0"}
                if session is not None:
                    if session not in ("a", "b", "expired", "loggedout"):
                        raise Blocked("SYNTHETIC-SESSION-ONLY")
                    headers["Cookie"] = "p007_session=" + session
                connection = http.client.HTTPConnection("127.0.0.1", p.port, timeout=3)
                connection.sock = wire
                connection.request(method, p.path, headers=headers)
                response = connection.getresponse()
                body = response.read(min(65536, guard.test.limits.output_bytes) + 1)
                if len(body) > min(65536, guard.test.limits.output_bytes):
                    raise Blocked("RESPONSE-BUDGET")
                if response.getheader("X-P007-Instance") != guard.target.instance_id:
                    raise Blocked("OWNERSHIP-INSTANCE-MISMATCH")
                if 300 <= response.status < 400:
                    # Every redirect is refused, including same-origin redirects.
                    raise Blocked("REDIRECT-BLOCKED")
                return {
                    "status": response.status,
                    "body": body,
                    "headers": {
                        k: v
                        for k, v in response.getheaders()
                        if k.lower() not in ("set-cookie", "cookie", "authorization")
                    },
                    "set_session": p.path.rsplit("/", 1)[-1] if p.path.startswith("/session/") else None,
                }
            finally:
                wire.close()
        finally:
            if connection:
                connection.close()
            guard.lock.release()


def active_zap_gate(*, opt_in=False, guard=None):
    if not opt_in:
        raise Blocked("ACTIVE-ZAP-REQUIRES-SEPARATE-HUMAN-OPT-IN")
    if guard is None:
        raise Blocked("ACTIVE-ZAP-REQUIRES-LOCAL-SCOPE-AND-P003")
    # Current P-003 has no bounded-active-scan activity and the runner cannot
    # enforce a hard per-rule request ceiling. Never fabricate compatibility.
    raise Blocked("ACTIVE-ZAP-UNSUPPORTED-BY-P003-AND-REQUEST-CEILING")
