from copy import deepcopy

import pytest
from pydantic import ValidationError

from p005.domain.schemas import HumanReview, ThreatScenario, VerificationCase
from p005.evidence.safety import DATA, PROJECT, Invalid, canonical, load
from p005.ingestion.fixtures import build
from p005.modeling.diff import compare
from p005.modeling.risk_catalog import validate_ids
from p005.modeling.rule_engine import analyze, rules, validate_analysis


def fired(result):
    return {t["rule_trace"]["rule_id"] for t in result["threats"]}


def test_matching_rule_has_facts_and_trace(model):
    result = analyze(model)
    threat = next(t for t in result["threats"] if t["rule_trace"]["rule_id"] == "mcp-boundary")
    assert threat["status"] == "MODELLED_THREAT" and threat["hypothesis_status"] == "HYPOTHESIS"
    assert threat["rule_trace"]["input_facts"] and threat["rule_trace"]["falsifier"]
    assert threat["evidence_refs"] and threat["edge_ids"] and threat["boundary_ids"]
    assert threat["applicability"] == "PROPOSED" and threat["review_status"] == "NEEDS_REVIEW"


def test_absent_features_do_not_fire(model):
    active = fired(analyze(model))
    assert not active & {
        "coding-workspace",
        "persistent-memory",
        "a2a-scope",
        "evaluation-data",
        "identity-audience",
        "cross-tenant",
    }


def test_tenant_hypotheses_not_deduplicated(model):
    threats = [t for t in analyze(model)["threats"] if t["rule_trace"]["rule_id"] == "mcp-boundary"]
    assert len(threats) == 2 and len({t["threat_id"] for t in threats}) == 2
    assert {t["tenant_id"] for t in threats} == {"tenant-a", "tenant-b"}


@pytest.mark.parametrize(
    "variant,expected",
    [
        ("tenant-boundary-change", "cross-tenant"),
        ("wrong-audience", "identity-audience"),
        ("stale-grants", "stale-grants"),
        ("disabled-policy", "tool-authority"),
        ("disabled-logging", "monitoring-gap"),
        ("added-egress", "network-egress"),
    ],
)
def test_controlled_variants_surface_specific_hypotheses(variant, expected):
    m = build(PROJECT / f"fixtures/variants/{variant}.yaml")
    assert expected in fired(analyze(m))


def test_indirect_prompt_delegation_approval(model):
    active = fired(analyze(model))
    assert {"indirect-prompt", "broad-delegation", "approval-integrity"} <= active


def test_priority_is_ordinal_with_rationale(model):
    for threat in analyze(model)["threats"]:
        assert "rationale" in threat["triage"] and threat["triage"]["control_strength_unknown"]
        assert "finding_severity" not in threat and "likelihood" not in threat
        assert "Ordinal review triage" in threat["triage"]["rationale"]


def test_all_plans_are_unexecuted_and_controls_owned(model):
    result = analyze(model)
    for plan in result["verification_plan"]:
        assert plan["run_status"] == "NOT_TESTED" and not plan["executable"]
        assert plan["positive_path"] and plan["negative_path"] and plan["required_evidence"]
        assert plan["roe_check_state"] == "REQUIRES_NEW_AUTHORIZATION"
    for control in result["controls"]:
        assert control["owner_role"] and control["acceptance_criteria"] and control["objective"]
        assert control["state"] == "CONTROL_PROPOSED" and control["external_requirement_id"] is None


def test_out_of_scope_is_flagged():
    m = build(PROJECT / "fixtures/variants/tenant-boundary-change.yaml")
    result = analyze(m)
    tid = next(t["threat_id"] for t in result["threats"] if t["rule_trace"]["rule_id"] == "cross-tenant")
    plan = next(p for p in result["verification_plan"] if p["threat_id"] == tid)
    assert plan["scope_state"] == plan["roe_check_state"] == "OUT_OF_SCOPE"


@pytest.mark.parametrize("ids", [["R999"], ["R0"], ["R16"], ["AML.T0000"], ["R025"]])
def test_unverified_risk_ids_fail_with_source(ids):
    with pytest.raises(Invalid, match="source-attribution"):
        validate_ids(ids)


def test_rule_dsl_rejects_code_fields(tmp_path):
    data = load(DATA / "rules.json")
    data["rules"][0]["all"][0]["field"] = "__import__('os').system"
    path = tmp_path / "code-rule.json"
    path.write_bytes(canonical(data))
    with pytest.raises(ValidationError):
        rules(path)


def test_suppression_requires_reason_and_is_traced(model):
    with pytest.raises(Invalid):
        analyze(model, suppressions={"mcp-boundary": ""})
    result = analyze(
        model, suppressions={"mcp-boundary": "Fixture scope excludes native MCP implementation review"}
    )
    assert "mcp-boundary" not in fired(result)
    assert len(result["suppressions"]) == 2
    assert all(s["reason"] for s in result["suppressions"])


def test_changed_architecture_invalidates_reviews(model):
    after = build(PROJECT / "fixtures/variants/tenant-boundary-change.yaml")
    diff = compare(model, after)
    assert diff["previous_decisions"] == "INVALIDATED" and diff["review_state"] == "NEEDS_REVIEW"
    assert diff["hypotheses"]["added"] and diff["graph"]["flows"]["added"]
    assert diff["newly_out_of_scope"] == ["tenant-b-documents"]
    assert diff["atlas_mappings"] == "REQUIRES_REASSESSMENT"


def test_version_sequence_cannot_silently_reuse(model):
    with pytest.raises(Invalid, match="INCREASING"):
        compare(model, model)


def test_finding_and_test_result_cannot_be_invented(model):
    result = analyze(model)
    threat = deepcopy(result["threats"][0])
    threat["status"] = "FINDING_CONFIRMED"
    with pytest.raises(ValidationError):
        ThreatScenario.model_validate(threat)
    plan = deepcopy(result["verification_plan"][0])
    plan["run_status"] = "PASS"
    with pytest.raises(ValidationError):
        VerificationCase.model_validate(plan)


def test_analysis_orphan_and_staleness_rejected(model):
    data = analyze(model)
    data["threats"][0]["test_ids"] = ["missing-test"]
    with pytest.raises(Invalid):
        validate_analysis(model, data)
    data["model_digest"] = "0" * 64
    with pytest.raises(Invalid, match="STALE"):
        validate_analysis(model, data)


def test_review_requires_explanation():
    with pytest.raises(ValidationError):
        HumanReview.model_validate(
            dict(
                threat_id="threat-aa",
                model_digest="0" * 64,
                sequence=1,
                reviewer_role="synthetic-reviewer",
                decision="ACCEPTED_FOR_TESTING",
                reason="",
                at_utc="2026-11-15T00:00:00Z",
            )
        )


@pytest.mark.parametrize(
    "kind,feature,rule_id",
    [
        ("Retriever", "coding_workspace", "coding-workspace"),
        ("Memory", "persistent_memory", "persistent-memory"),
        ("A2APeer", None, "a2a-scope"),
        ("Evaluator", None, "evaluation-data"),
    ],
)
def test_optional_modeled_features_trigger_only_when_added(model, kind, feature, rule_id):
    from test_model import regraph

    assert rule_id not in fired(analyze(model))
    data = model.model_dump()
    target = next(n for n in data["nodes"] if n["id"] == "tenant-a-retriever")
    target["kind"] = kind
    if feature:
        target["features"][feature] = True
    if kind == "Evaluator":
        next(n for n in data["nodes"] if n["id"] == "tenant-a-backend")["features"]["untrusted_content"] = (
            True
        )
    assert rule_id in fired(analyze(regraph(data)))


def test_candidate_budget_fails_closed(model):
    from test_model import regraph

    data = model.model_dump()
    prototype = next(e for e in data["flows"] if e["id"] == "tenant-a-agent-mcp")
    for index in range(130):
        edge = deepcopy(prototype)
        edge["id"] = f"bounded-duplicate-transition-{index}"
        data["flows"].append(edge)
    with pytest.raises(Invalid, match="CANDIDATE-BUDGET"):
        analyze(regraph(data))


def test_cross_threat_control_reference_is_rejected(model):
    result = analyze(model)
    result["threats"][0]["control_ids"] = result["threats"][1]["control_ids"]
    with pytest.raises(Invalid, match="CROSS-THREAT"):
        validate_analysis(model, result)
