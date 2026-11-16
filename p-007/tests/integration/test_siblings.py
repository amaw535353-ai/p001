import pytest
from p007.integrations import import_contract
from p007.safety import REPO, Blocked, canonical, write_new


def test_p001_metadata_contract():
    result = import_contract("P-001", REPO / "infra/kubernetes/resources.json")
    assert result["status"] == "PASS" and result["count"] > 0


def test_p002_real_generator_validated_export(tmp_path):
    from p002.generators import generate

    path = tmp_path / "dataset.json"
    write_new(path, canonical(generate(seed=7, profile="tiny", mode="fixtures").model_dump(mode="json")))
    result = import_contract("P-002", path)
    assert result["identities"] and len(result["tenants"]) == 2 and result["scenario_refs"]


def test_p003_sealed_engagement_metadata():
    result = import_contract("P-003", REPO / "p-003/examples/engagement-draft-a.json")
    assert result["status"] == "PASS" and result["source_hash"]


def test_missing_incompatible_and_absent_sibling_contracts(tmp_path):
    with pytest.raises(Blocked, match="ABSENT"):
        import_contract("P-004", tmp_path / "absent.json")
    path = tmp_path / "old.json"
    write_new(path, canonical({"schema_version": "0.0"}))
    with pytest.raises(Blocked, match="INCOMPATIBLE"):
        import_contract("P-002", path)
    with pytest.raises(Blocked, match="P006"):
        import_contract("P-006", path)
