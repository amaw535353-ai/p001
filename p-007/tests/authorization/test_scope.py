import socket
import pytest
from p007.authorization import Guard, GuardedHTTP, P003Reader, active_zap_gate, local_url
from p007.catalog import plan
from p007.evidence import run, verify, utc_now
from p007.governance_demo import simulated_ledger
from p007.safety import Blocked


def test_A01_offline_has_no_sockets_or_dns(tmp_path):
    assert any(r.status == "PASS" for r in verify(run(plan(), root=tmp_path)).results)


def test_A02_unregistered_refused_before_connect(monkeypatch):
    attempts = []
    monkeypatch.setattr(socket.socket, "connect", lambda *_: attempts.append(1))
    with pytest.raises(Blocked, match="UNREGISTERED"):
        plan("unregistered")
    assert attempts == []


def test_A03_external_metadata_private_and_url_tricks():
    for url in (
        "https://example.com/",
        "http://10.0.0.1:8080/",
        "http://169.254.169.254:80/",
        "http://localhost:8000/",
        "http://127.0.0.1:8000@evil.test/",
        "http://127.0.0.1:8000/%2e%2e/",
        "http://127.0.0.1:8000/../health",
        "http://127.0.0.1:8000/health?to=evil",
        "http://127.1:8000/",
    ):
        with pytest.raises(Blocked):
            local_url(url)


@pytest.mark.live
def test_A04_redirect_no_followup(network_context, monkeypatch):
    lease, _, _, guard, _ = network_context

    class Response:
        status = 302

        def read(self, *_):
            return b""

        def getheader(self, name):
            return lease.target.instance_id if name == "X-P007-Instance" else "https://example.invalid/"

    monkeypatch.setattr("http.client.HTTPConnection.getresponse", lambda *_: Response())
    with pytest.raises(Blocked, match="REDIRECT"):
        GuardedHTTP(guard).request(lease.target.origin + "/ui")
    assert guard.used == 1


@pytest.mark.live
def test_A05_resolution_change_refused_before_connect(network_context, monkeypatch):
    lease, _, _, guard, _ = network_context
    attempts = []
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 80))]
    )
    monkeypatch.setattr(socket.socket, "connect", lambda *_: attempts.append(1))
    with pytest.raises(Blocked, match="MAPPING-CHANGED"):
        GuardedHTTP(guard).request(lease.target.origin + "/ui")
    assert attempts == [] and guard.used == 0


@pytest.mark.live
def test_A06_p003_method_and_category_scope(network_context, tmp_path):
    lease, _, _, _, selected = network_context
    for name, options, reason in (
        ("head", {"methods": ["HEAD"]}, "METHOD-NOT-ALLOWED"),
        ("passive", {"activities": ["passive-inspection"]}, "ACTIVITY-NOT-ALLOWED"),
    ):
        _, ref = simulated_ledger(lease.target, tmp_path / name, **options)
        guard = Guard(lease.target, P003Reader(ref), lease, selected.tests[0])
        with pytest.raises(Blocked, match=reason):
            guard.check(lease.target.origin + "/ui")


@pytest.mark.live
def test_A07_missing_expired_revoked_mismatched_authorization(network_context, tmp_path, monkeypatch):
    lease, _, _, _, selected = network_context
    attempts = []
    monkeypatch.setattr(socket.socket, "connect", lambda *_: attempts.append(1))
    for name, options in (
        ("missing", {"state": "MISSING"}),
        ("expired", {"expired": True}),
        ("revoked", {"state": "REVOKED"}),
        ("mismatch", {}),
    ):
        _, ref = simulated_ledger(lease.target, tmp_path / name, **options)
        if name == "mismatch":
            ref = ref.model_copy(update={"policy_digest": "0" * 64})
        guard = Guard(lease.target, P003Reader(ref), lease, selected.tests[0])
        with pytest.raises(Blocked):
            GuardedHTTP(guard).request(lease.target.origin + "/ui")
    assert attempts == []


def test_A08_active_zap_needs_optin_and_scope():
    with pytest.raises(Blocked, match="HUMAN-OPT-IN"):
        active_zap_gate()
    with pytest.raises(Blocked, match="LOCAL-SCOPE"):
        active_zap_gate(opt_in=True)


@pytest.mark.live
def test_revocation_rechecked_before_next_request(network_context):
    lease, store, _, guard, _ = network_context
    GuardedHTTP(guard).request(lease.target.origin + "/health")
    store.transition("ENG-DEMO-A", "demo-a-owner", "stop", version=1, at=utc_now(), stop_status="REVOKED")
    with pytest.raises(Blocked, match="ENGAGEMENT-NOT-ACTIVE"):
        GuardedHTTP(guard).request(lease.target.origin + "/health")
    assert guard.used == 1


@pytest.mark.live
def test_exact_route_budget_and_expired_lease(network_context):
    lease, _, _, guard, _ = network_context
    with pytest.raises(Blocked, match="METHOD-ROUTE-CATEGORY"):
        guard.check(lease.target.origin + "/unknown")
    guard.used = guard.test.limits.requests
    with pytest.raises(Blocked, match="REQUEST-BUDGET"):
        guard.check(lease.target.origin + "/ui")
    guard.used = 0
    guard.lease.active = False
    with pytest.raises(Blocked, match="EXPIRED-LEASE"):
        guard.check(lease.target.origin + "/ui")
