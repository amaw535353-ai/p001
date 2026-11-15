"""All tests deny non-loopback egress; only marked transport tests may connect locally."""

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import threading
from uuid import uuid4

import pytest

from p003 import demo
from p003.models import Asset, Engagement, EvidencePolicy, ROE, ReviewEvidence, Scope, sealed
from p003.store import Store
from p003.util import uid
from p004.graph import Graph
from p004.models import Context, Source
from p004.policy import Guard, LiveContext, OwnedTarget, P003Adapter
from p004.safety import digest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


@pytest.fixture(autouse=True)
def deny_egress(request, monkeypatch):
    original = socket.socket.connect
    local = bool(request.node.get_closest_marker("local_network"))

    def connect(wire, destination):
        if local and isinstance(destination, tuple) and destination[0] == "127.0.0.1":
            return original(wire, destination)
        raise AssertionError("TEST-NETWORK-DENIED")

    def deny(*_args, **_kw):
        raise AssertionError("TEST-DNS-OR-EGRESS-DENIED")

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def ref():
    return Source(path="synthetic-fixture.json", sha256=digest(b"synthetic"), pointer="/")


@pytest.fixture
def graph():
    return Graph(
        Context(run_id="synthetic-run", timestamp_utc="2026-11-15T12:00:00Z", git_commit="test-synthetic")
    )


@pytest.fixture
def approved_factory(tmp_path):
    """Explicit simulated review/activation for disposable, owned test targets ONLY."""

    def make(port=8764, paths=("/health",), state="ACTIVE", methods=None, exclusions=None, roe_changes=None):
        now = datetime.now(timezone.utc)

        def at(seconds):
            return (now + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        window = dict(start=at(-600), end=at(3600))
        base = demo.engagement()
        assets = [
            sealed(
                Asset,
                **{
                    **base.assets[0].model_dump(mode="json"),
                    "id": uid("p004-test:" + path),
                    "asset_id": "fixture-path-" + str(i),
                    "selector": {"kind": "url", "value": f"http://127.0.0.1:{port}{path}"},
                    "methods": methods or ["GET"],
                },
            )
            for i, path in enumerate(paths)
        ]
        scope = sealed(
            Scope,
            **{
                **base.scope.model_dump(mode="json"),
                "included_asset_ids": [x.asset_id for x in assets],
                "exclusions": exclusions or [],
            },
        )
        roe = sealed(
            ROE,
            **{
                **base.roe.model_dump(mode="json"),
                "window": window,
                "max_requests_per_minute": 30,
                **(roe_changes or {}),
            },
        )
        evidence = sealed(EvidencePolicy, **base.evidence_policy.model_dump(mode="json"))
        spec = sealed(
            Engagement,
            **{
                **base.model_dump(mode="json"),
                "created_at": at(-900),
                "window": window,
                "assets": assets,
                "scope": scope,
                "roe": roe,
                "evidence_policy": evidence,
                "requirements": [],
            },
        )
        store = Store(tmp_path / ("owned-" + uuid4().hex), create=True)
        store.create(spec)
        review = sealed(
            ReviewEvidence, **{**demo.review(spec).model_dump(mode="json"), "created_at": at(-800)}
        )
        (store.path / "reviews").mkdir(mode=0o700)
        review_path = store.path / "reviews" / (review.evidence_ref + ".json")
        review_path.write_text(json.dumps(review.model_dump(mode="json")))
        review_path.chmod(0o600)
        if state != "DRAFT":
            store.transition(spec.engagement_id, "demo-a-requestor", "submit", version=1, at=at(-700))
        if state not in ("DRAFT", "SUBMITTED"):
            store.transition(
                spec.engagement_id,
                "demo-a-reviewer",
                "approve",
                version=1,
                at=at(-650),
                simulate_review=True,
                expected_digest=spec.content_digest,
                evidence_ref=review.evidence_ref,
            )
        if state not in ("DRAFT", "SUBMITTED", "APPROVED"):
            store.transition(spec.engagement_id, "demo-a-owner", "activate", version=1, at=at(-600))
        if state in ("REVOKED", "SUSPENDED", "CLOSED", "EXPIRED"):
            store.transition(
                spec.engagement_id,
                "demo-a-owner",
                "stop",
                version=1,
                at=at(-100),
                purpose="Synthetic stop-work test",
                stop_status=state,
            )
        context = LiveContext(
            engagement_id=spec.engagement_id,
            approved_engagement_version=1,
            policy_digest=spec.content_digest,
            actor="demo-a-assessor",
            tenant="tenant-a",
            source_identity="demo-a-workload",
            storage_id="p003-private",
            checkpoint_completed=True,
            contact_available=True,
            redaction_confirmed=True,
        )
        return store, context

    return make


@pytest.fixture
def local_app():
    instance = "fixture-" + uuid4().hex
    received = []
    controls = {"callback": None, "location": "http://127.0.0.1:9/outside"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            received.append(self.path)
            if controls["callback"]:
                controls["callback"]()
            body = b'{"synthetic":true}'
            if self.path == "/secret":
                body = b'{"token":"p004-NOT-A-REAL-TOKEN"}'
            if self.path == "/large":
                body = b"x" * 65_000
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("X-P004-Instance", instance)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "fixture-secret=DO-NOT-ARCHIVE")
            if self.path == "/redirect":
                self.send_header("Location", controls["location"])
            self.end_headers()
            self.wfile.write(body)

    app = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    app.daemon_threads = True
    worker = threading.Thread(target=app.serve_forever, daemon=True)
    worker.start()
    owned = OwnedTarget(
        instance_id=instance,
        origin=f"http://127.0.0.1:{app.server_port}",
        tenant_id="tenant-a",
        safe_paths=["/health", "/api/catalog", "/redirect", "/secret", "/large"],
        synthetic_only=True,
    )
    yield app, owned, received, controls
    app.shutdown()
    app.server_close()
    worker.join(timeout=3)


@pytest.fixture
def live_guard(local_app, approved_factory):
    app, owned, received, controls = local_app
    store, ctx = approved_factory(app.server_port, owned.safe_paths)
    guard = Guard(P003Adapter(store.path, ctx), owned)
    return guard, store, received, controls
