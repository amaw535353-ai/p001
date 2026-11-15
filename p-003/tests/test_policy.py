from copy import deepcopy
import socket
import subprocess
from pathlib import Path
from unittest.mock import patch

from hypothesis import given, strategies as st
import pytest

from p003 import demo
from p003.models import Asset, Engagement, ROE, Scope, sealed
from p003.policy import evaluate
from p003.targets import normalize, matches


def engine(active, raw=None, spec=None, state="ACTIVE", stopped=False):
    view = active.read("ENG-DEMO-A", "demo-a-assessor")
    return evaluate(
        spec or view.spec,
        state,
        view.approvals[1],
        raw or demo.request(),
        evidence_valid=True,
        stopped=stopped,
    )


def test_positive_exact_scope(active):
    result = active.check(demo.request())
    assert result.decision == "ALLOW"
    assert result.authority_status == result.target_enforcement == "NOT VERIFIED"
    assert result.policy_digest and result.approval_digest and result.id


@pytest.mark.parametrize(
    "path,value,reason",
    [
        ("engagement_id", "", "INVALID-INPUT"),
        ("engagement_id", "ENG-MISSING", "UNKNOWN-ENGAGEMENT"),
        ("engagement_version", 2, "VERSION-MISMATCH"),
        ("test_class", "scanner-exploit", "INVALID-INPUT"),
        ("test_class", "config-review", "ACTIVITY-NOT-ALLOWED"),
        ("actor", "demo-a-owner", "ASSESSOR-ROLE-OR-TENANT"),
        ("actor", "demo-b-assessor", "ASSESSOR-ROLE-OR-TENANT"),
        ("context.tenant", "tenant-b", "ASSESSOR-ROLE-OR-TENANT"),
        ("context.environment", "offline", "ASSET-CONTEXT-MISMATCH"),
        ("context.method", "POST", "METHOD-NOT-ALLOWED"),
        ("context.source_identity", "other-workload", "PREREQUISITE-MISSING"),
        ("context.checkpoint_completed", False, "PREREQUISITE-MISSING"),
        ("context.contact_available", False, "CONTACT-MISSING"),
        ("context.redirects_expected", True, "INDIRECTION-NOT-MODELED"),
        ("context.storage_id", "unapproved-store", "EVIDENCE-POLICY"),
        ("context.data_class", "real-customer-secret", "INVALID-INPUT"),
        ("context.redaction_confirmed", False, "EVIDENCE-POLICY"),
        ("context.data_breach", True, "STOP-DATA-BREACH"),
        ("budget.used_total", 100, "BUDGET-OR-IMPACT-EXCEEDED"),
        ("budget.used_last_minute", 10, "BUDGET-OR-IMPACT-EXCEEDED"),
        ("budget.requested_cost_units", 1, "BUDGET-OR-IMPACT-EXCEEDED"),
        ("budget.interruption_ms", 1, "BUDGET-OR-IMPACT-EXCEEDED"),
        ("budget.requested", -1, "INVALID-INPUT"),
        ("budget.requested", True, "INVALID-INPUT"),
        ("budget.requested", "1", "INVALID-INPUT"),
        ("at", "2026-11-15T08:59:59Z", "OUTSIDE-WINDOW"),
        ("at", "2026-11-15T17:00:00Z", "OUTSIDE-WINDOW"),
        ("at", "2026-11-15T10:00:00+01:00", "INVALID-INPUT"),
        ("at", "2026-02-30T10:00:00Z", "INVALID-INPUT"),
        ("target.value", "http://127.0.0.1:8001/health", "TARGET-NOT-ALLOWLISTED"),
        ("target.value", "https://127.0.0.1:8000/health", "TARGET-NOT-ALLOWLISTED"),
        ("target.value", "http://127.0.0.1:8000/health/child", "TARGET-NOT-ALLOWLISTED"),
        ("target.value", "http://127.0.0.1:8000/healthier", "TARGET-NOT-ALLOWLISTED"),
        ("target.value", "http://127.0.0.1:8000/Health", "TARGET-NOT-ALLOWLISTED"),
        ("target.value", "http://localhost:8000/health", "INVALID-INPUT"),
        ("target.value", "http://127.1:8000/health", "INVALID-INPUT"),
        ("target.value", "http://2130706433:8000/health", "INVALID-INPUT"),
        ("target.value", "http://public.example.com/health", "INVALID-INPUT"),
        ("target.value", "http://169.254.169.254/latest", "INVALID-INPUT"),
        ("target.value", "http://api.test:8000/health", "TARGET-NOT-ALLOWLISTED"),
        ("target.value", "http://[::1]:8000/health", "TARGET-NOT-ALLOWLISTED"),
        ("target.value", "http://127.0.0.1:8000/%68ealth", "INVALID-INPUT"),
        ("target.value", "http://127.0.0.1:8000/%FF", "INVALID-INPUT"),
        ("target.value", "http://127.0.0.1:8000/a/../health", "INVALID-INPUT"),
        ("target.value", "http://127.0.0.1:8000//health", "INVALID-INPUT"),
        ("target.value", "http://127.0.0.1:8000/health?redirect=https://example.com", "INVALID-INPUT"),
        ("target.value", "http://u@127.0.0.1:8000/health", "INVALID-INPUT"),
        ("target.value", "/health", "INVALID-INPUT"),
        ("target.value", "http://*.test:8000/health", "INVALID-INPUT"),
        ("target.value", "http://xn--demo.test:8000/health", "INVALID-INPUT"),
        ("target.value", "http://127.0.0.1:8000/hea\x00lth", "INVALID-INPUT"),
    ],
)
def test_negative_inputs(active, path, value, reason):
    raw = deepcopy(demo.request())
    keys = path.split(".")
    target = raw
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    result = engine(active, raw)
    assert result.decision == "DENY" and reason in result.rationale


@pytest.mark.parametrize("field", ["budget", "context", "engagement_id", "target", "actor", "at"])
def test_missing_prerequisites(active, field):
    raw = demo.request()
    del raw[field]
    view = active.read("ENG-DEMO-A", "demo-a-assessor")
    assert evaluate(view.spec, "ACTIVE", view.approvals[1], raw, evidence_valid=True).decision == "DENY"


@pytest.mark.parametrize(
    "state",
    ["DRAFT", "SUBMITTED", "APPROVED", "EXPIRED", "REVOKED", "SUSPENDED", "CLOSED", "REJECTED", "SUPERSEDED"],
)
def test_nonactive_denied(active, state):
    assert engine(active, state=state).decision == "DENY"


def test_approval_evidence_and_stop_required(active):
    view = active.read("ENG-DEMO-A", "demo-a-assessor")
    for auth, valid, stopped in [
        (None, True, False),
        (view.approvals[1], False, False),
        (view.approvals[1], True, True),
    ]:
        assert (
            evaluate(
                view.spec, "ACTIVE", auth, demo.request(), evidence_valid=valid, stopped=stopped
            ).decision
            == "DENY"
        )


def test_policy_edit_and_digest_tamper_denied(active):
    spec = active.read("ENG-DEMO-A", "demo-a-assessor").spec
    changed = sealed(Engagement, **{**spec.model_dump(mode="json"), "goals": ["Relaxed new objective"]})
    assert "APPROVAL-BINDING-MISMATCH" in engine(active, spec=changed).rationale
    forged = spec.model_copy(update={"goals": ["Silently changed"]})
    assert "POLICY-INTEGRITY" in engine(active, spec=forged).rationale


def test_no_network_process_or_file_io_in_evaluation(active):
    view = active.read("ENG-DEMO-A", "demo-a-assessor")

    def forbidden(*args, **kwargs):
        raise AssertionError("pure evaluation performed I/O")

    with (
        patch.object(socket, "socket", forbidden),
        patch.object(socket, "getaddrinfo", forbidden),
        patch.object(subprocess, "run", forbidden),
        patch.object(Path, "read_text", forbidden),
        patch.object(Path, "read_bytes", forbidden),
        patch("builtins.open", forbidden),
    ):
        assert (
            evaluate(view.spec, "ACTIVE", view.approvals[1], demo.request(), evidence_valid=True).decision
            == "ALLOW"
        )


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=40))
def test_property_exact_path_not_prefix(path):
    base = normalize("url", "http://127.0.0.1:8000/health")
    other = normalize("url", "http://127.0.0.1:8000/health/" + path)
    assert not matches("url", base, "url", other)


@given(st.integers(min_value=0, max_value=255))
def test_property_loopback_cidr_boundaries(last):
    target = normalize("ip", "127.0.1." + str(last))
    assert matches("cidr", "127.0.1.0/24", "ip", target)
    assert not matches("cidr", "127.0.0.0/24", "ip", target)


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "126.0.0.0/7", "::/0", "::/127", "10.0.0.0/8"])
def test_cidr_must_be_loopback_only(cidr):
    with pytest.raises(ValueError):
        normalize("cidr", cidr)


def test_ipv6_boundary_and_host_case():
    assert normalize("url", "HTTP://API.TEST/health") == "http://api.test:80/health"
    assert not matches("host", "api.test", "host", "sub.api.test")
    assert matches("cidr", "::1/128", "url", "http://[::1]:8000/health")
    with pytest.raises(ValueError):
        normalize("url", "http://[::2]:8000/health")


def test_explicit_exclusions_override_and_missing_contact(active):
    view = active.read("ENG-DEMO-A", "demo-a-assessor")
    spec = view.spec
    scope = sealed(
        Scope,
        **{
            **spec.scope.model_dump(mode="json"),
            "exclusions": [
                {"selector": spec.assets[0].selector.model_dump(), "reason": "Explicit overriding exclusion"}
            ],
        },
    )
    changed = sealed(Engagement, **{**spec.model_dump(mode="json"), "scope": scope})
    assert "EXPLICIT-EXCLUSION" in engine(active, spec=changed).rationale
    roe = sealed(ROE, **{**spec.roe.model_dump(mode="json"), "emergency_contact": None})
    changed = sealed(Engagement, **{**spec.model_dump(mode="json"), "roe": roe})
    assert "CONTACT-MISSING" in engine(active, spec=changed).rationale


def test_external_ownership_is_not_approval(active):
    spec = active.read("ENG-DEMO-A", "demo-a-assessor").spec
    asset = sealed(Asset, **{**spec.assets[0].model_dump(mode="json"), "ownership": "external-unverified"})
    changed = sealed(Engagement, **{**spec.model_dump(mode="json"), "assets": [asset]})
    assert "OWNERSHIP-OR-EXTERNAL-RESTRICTION" in engine(active, spec=changed).rationale
