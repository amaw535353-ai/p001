from hypothesis import given, strategies as st
import pytest

from p003 import demo
from p003.models import Authorization, Engagement, Scope, sealed
from p003.policy import evaluate
from p003.targets import normalize
from p003.util import uid


def authorization(spec):
    return sealed(
        Authorization,
        id=uid("property-authorization"),
        source="simulated unit fixture only",
        author="demo-a-reviewer",
        reviewer="demo-a-reviewer",
        created_at="2026-11-15T08:20:00Z",
        engagement_id=spec.engagement_id,
        version=spec.version,
        policy_digest=spec.content_digest,
        evidence_ref="simulated-property-review",
        evidence_sha256="a" * 64,
        checklist="SIMULATED-REVIEW-NOT-IDENTITY-VERIFICATION",
        targets=[a.selector for a in spec.assets],
        activities=spec.scope.activities,
        window=spec.window,
        exceptions=[],
        revocation_history=[],
    )


@given(st.sampled_from(["url", "cidr"]))
def test_property_exclusion_always_overrides_valid_approval(kind):
    spec = demo.engagement()
    selector = (
        spec.assets[0].selector.model_dump() if kind == "url" else {"kind": "cidr", "value": "127.0.0.0/8"}
    )
    scope = sealed(
        Scope,
        **{
            **spec.scope.model_dump(mode="json"),
            "exclusions": [{"selector": selector, "reason": "Overriding synthetic exclusion"}],
        },
    )
    spec = sealed(Engagement, **{**spec.model_dump(mode="json"), "scope": scope})
    result = evaluate(spec, "ACTIVE", authorization(spec), demo.request(), evidence_valid=True)
    assert result.decision == "DENY" and "EXPLICIT-EXCLUSION" in result.rationale


@given(st.sampled_from(["REVOKED", "SUSPENDED", "CLOSED", "SUPERSEDED", "SUBMITTED"]))
def test_property_terminal_or_pending_wins_over_approval(state):
    spec = demo.engagement()
    assert evaluate(spec, state, authorization(spec), demo.request(), evidence_valid=True).decision == "DENY"


@given(
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=24).filter(
        lambda x: (
            x
            not in ("passive-inspection", "config-review", "bounded-local-api", "synthetic-prompt-evaluation")
        )
    )
)
def test_property_unknown_action_never_permits(action):
    spec = demo.engagement()
    raw = demo.request(test_class=action)
    assert evaluate(spec, "ACTIVE", authorization(spec), raw, evidence_valid=True).decision == "DENY"


@given(st.integers(min_value=2, max_value=10000))
def test_property_version_replay_denies(version):
    spec = demo.engagement()
    raw = demo.request(engagement_version=version)
    assert evaluate(spec, "ACTIVE", authorization(spec), raw, evidence_valid=True).decision == "DENY"


def test_cidr_inclusion_does_not_authorize_any_port_or_scheme():
    from p003.models import Asset

    spec = demo.engagement()
    asset = sealed(
        Asset,
        **{**spec.assets[0].model_dump(mode="json"), "selector": {"kind": "cidr", "value": "127.0.0.0/8"}},
    )
    spec = sealed(Engagement, **{**spec.model_dump(mode="json"), "assets": [asset]})
    result = evaluate(spec, "ACTIVE", authorization(spec), demo.request(), evidence_valid=True)
    assert result.decision == "DENY" and "TARGET-NOT-ALLOWLISTED" in result.rationale


def test_activation_time_cannot_be_replayed_backwards():
    spec = demo.engagement()
    result = evaluate(
        spec,
        "ACTIVE",
        authorization(spec),
        demo.request(),
        evidence_valid=True,
        active_since="2026-11-15T11:00:00Z",
    )
    assert result.decision == "DENY" and "BEFORE-ACTIVATION" in result.rationale


@pytest.mark.parametrize(
    "target", ["http://[::1]garbage:8000/health", "http://[::1]:/health", "http://[::1%25lo]:8000/health"]
)
def test_ambiguous_ipv6_url_rejected(target):
    with pytest.raises(ValueError):
        normalize("url", target)


def test_explicit_forbidden_class_overrides_roe_allowlist():
    from p003.models import ROE

    spec = demo.engagement()
    roe = sealed(
        ROE, **{**spec.roe.model_dump(mode="json"), "forbidden": [*spec.roe.forbidden, "passive-inspection"]}
    )
    spec = sealed(Engagement, **{**spec.model_dump(mode="json"), "roe": roe})
    result = evaluate(spec, "ACTIVE", authorization(spec), demo.request(), evidence_valid=True)
    assert result.decision == "DENY" and "ACTIVITY-NOT-ALLOWED" in result.rationale


@pytest.mark.parametrize("change", ["contact", "owner", "sponsor"])
def test_unknown_party_references_rejected(change):
    from p003.models import Asset, ROE

    spec = demo.engagement()
    raw = spec.model_dump(mode="json")
    if change == "contact":
        raw["roe"] = sealed(ROE, **{**raw["roe"], "emergency_contact": "unknown-contact"})
    elif change == "owner":
        raw["assets"] = [sealed(Asset, **{**raw["assets"][0], "owner": "unknown-owner"})]
    else:
        raw["sponsors"] = ["unknown-sponsor"]
    with pytest.raises(ValueError):
        sealed(Engagement, **raw)
