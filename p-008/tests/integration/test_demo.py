from p008.demo import demo
from p008.registry import Registry
from p008.safety import PROJECT, load
from p008.models import CONTRACTS
import jsonschema


def test_entire_offline_workflow_preserves_baseline(tmp_path):
    result = demo(Registry(tmp_path / "owned"))
    assert result["status"] == "PASS" and result["baseline_evaluation_status"] == "FAIL"
    assert result["same_identity_comparison"]["classification"] == "UNCHANGED"
    assert not result["changed_comparison"]["comparable"]
    assert result["reproduction"]["output_match"]
    assert all(v == "NOT DEMONSTRATED" for v in result["learner_gates"].values())


def test_every_shipped_schema_is_valid():
    for name in CONTRACTS:
        schema = load(PROJECT / "schemas" / (name + ".schema.json"))
        jsonschema.Draft202012Validator.check_schema(schema)
    assert len(CONTRACTS) == 21


def test_missing_sibling_validators_do_not_break_offline_core(monkeypatch):
    from p008 import integrations

    def unavailable():
        raise ImportError("synthetic missing optional installation")

    monkeypatch.setattr(integrations, "available_siblings", unavailable)
    states = {r["project"]: r["status"] for r in integrations.siblings()}
    assert states["P-007"] == states["P-006"] == "BLOCKED"
