import pytest

from p005.evidence.safety import REPO, Invalid, canonical
from p005.ingestion.predecessors import p001, p002, p003_context, p004
from p005.modeling.rule_engine import analyze


def actual_p004(tmp_path, status="DECLARED"):
    from p004.graph import Graph
    from p004.models import Context, Source

    g = Graph(
        Context(run_id="p005-contract", timestamp_utc="2026-11-15T00:00:00Z", git_commit="synthetic-test")
    )
    ref = Source(path="synthetic-architecture.json", sha256="0" * 64, pointer="/assets")
    user = g.asset("human", "human-identity", "tenant-a", ref, status=status)
    api = g.asset("api", "api-service", "tenant-a", ref, status=status)
    g.flow(user, api, "invokes", ref, status=status, boundary="declared identity boundary")
    path = tmp_path / "snapshot.json"
    path.write_bytes(canonical(g.snapshot().model_dump(mode="json")))
    return path


def test_p004_declared_stays_declared(tmp_path):
    path = actual_p004(tmp_path)
    m = p004(path)
    assert all(n.epistemic_status == "DECLARED" for n in m.nodes)
    assert all(e.status == "DECLARED" for e in m.evidence)
    assert m.integrations[0].status == "VERIFIED"
    assert m.source_context[0]["project"] == "P-004"


def test_p004_inferred_remains_uncertain(tmp_path):
    path = actual_p004(tmp_path, "INFERRED")
    m = p004(path)
    assert all(n.epistemic_status == "INFERRED" for n in m.nodes)
    assert all(n.requires_human_review and n.evidence_refs for n in m.nodes)
    assert all(n.confidence == "INFERENCE" for n in m.nodes)


def test_p004_missing_and_digest_mismatch_rejected(tmp_path):
    with pytest.raises(Invalid):
        p004(tmp_path / "absent.json")
    path = actual_p004(tmp_path)
    import json

    data = json.loads(path.read_text())
    data["assets"][0]["label"] = "changed"
    path.write_bytes(canonical(data))
    with pytest.raises(Invalid, match="DIGEST"):
        p004(path)


def test_p004_observed_requires_specific_observed_claim(tmp_path):
    path = actual_p004(tmp_path, "OBSERVED")
    m = p004(path)
    assert all(n.epistemic_status == "OBSERVED" for n in m.nodes)
    assert all(e.authorization == "UNKNOWN" and e.enforcement_result == "NOT_TESTED" for e in m.flows)


def test_actual_p002_generator_oracle_is_not_enforcement(tmp_path):
    from p002.generators import generate

    data = generate(seed=2026, profile="tiny", mode="fixtures")
    path = tmp_path / "p002-dataset.json"
    path.write_bytes(canonical(data.model_dump(mode="json")))
    m = p002(path)
    assert m.integrations[0].status == "VERIFIED"
    assert {n.kind for n in m.nodes} >= {"HumanIdentity", "WorkloadIdentity"}
    assert {e.expected_decision for e in m.flows} == {"ALLOW", "DENY", "UNKNOWN"}
    assert {e.declared_grant_effect for e in m.flows} >= {"ALLOW", "DENY"}
    assert all(e.epistemic_status == "DECLARED" and e.enforcement_result == "NOT_TESTED" for e in m.flows)
    assert all(n.source_id for n in m.nodes)
    assert any(n.kind == "DocumentCollection" for n in m.nodes)
    assert m.source_context[0]["scenario_ids"] == [s.id for s in data.scenarios]


def test_actual_p003_context_is_not_authorization(model):
    m = p003_context(model, REPO / "p-003/examples/engagement-draft-a.json")
    assert m.engagement_id == "ENG-DEMO-A"
    assert m.model_scope.real_legal_authority == "NOT_VERIFIED"
    assert not m.model_scope.in_scope_node_ids  # No source ID mapping fabricated.
    assert all(p["scope_state"] == "REQUIRES_NEW_AUTHORIZATION" for p in analyze(m)["verification_plan"])


def test_p003_tampered_context_fails_closed(model, tmp_path):
    import json

    data = json.loads((REPO / "p-003/examples/engagement-draft-a.json").read_text())
    data["version"] = 2
    path = tmp_path / "tampered.json"
    path.write_bytes(canonical(data))
    with pytest.raises(ValueError):
        p003_context(model, path)


def test_p003_exact_address_exclusion_overrides_inclusion(model):
    data = model.model_dump()
    data["nodes"][0]["address"] = "http://127.0.0.1:8000/admin"
    data["nodes"][0]["source_id"] = "demo-a-health"
    m = type(model).model_validate(data)
    scoped = p003_context(m, REPO / "p-003/examples/engagement-draft-a.json")
    assert m.nodes[0].id in scoped.model_scope.out_of_scope_node_ids
    assert m.nodes[0].id not in scoped.model_scope.in_scope_node_ids
    assert scoped.source_context[-1]["ledger_and_revocation"].startswith("NOT_TESTED")


def test_p003_cross_tenant_address_never_grants_model_scope(model):
    data = model.model_dump()
    target = next(n for n in data["nodes"] if n["id"] == "tenant-b-api")
    target["address"] = "http://127.0.0.1:8000/health"
    target["source_id"] = "demo-a-health"
    m = type(model).model_validate(data)
    scoped = p003_context(m, REPO / "p-003/examples/engagement-draft-a.json")
    assert target["id"] not in scoped.model_scope.in_scope_node_ids


def test_p001_approved_inventory_never_opens_state(tmp_path):
    m = p001(REPO / "infra/kubernetes/resources.json")
    assert m.integrations[0].status == "VERIFIED"
    assert all(n.epistemic_status == "DECLARED" for n in m.nodes)
    assert not m.flows  # Metadata projection does not invent traffic.
    assert all(n.kind != "SecretStore" for n in m.nodes)
    state = tmp_path / "terraform.tfstate"
    state.write_text("secret=synthetic-private-state")
    with pytest.raises(Invalid, match="APPROVED-INVENTORY"):
        p001(state)


@pytest.mark.parametrize("source", ["p002", "p003"])
def test_predecessor_missing_version_never_coerced(model, tmp_path, source):
    path = tmp_path / "missing-version.json"
    path.write_text("{}")
    with pytest.raises(Invalid, match="INCOMPATIBLE-SCHEMA"):
        if source == "p002":
            p002(path)
        else:
            p003_context(model, path)
