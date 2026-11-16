from copy import deepcopy
import jsonschema
import pytest
from pydantic import ValidationError
from p007.catalog import catalog, plan
from p007.models import Catalog, TestCase as Case, CONTRACTS
from p007.safety import PROJECT, Invalid, canonical, load


def test_F01_valid_case_jsonschema_and_model(case):
    data = case.model_dump(mode="json")
    jsonschema.validate(data, load(PROJECT / "schemas/test-case.schema.json"))
    assert Case.model_validate(data).test_id == case.test_id


def test_F02_missing_and_unknown_fields(case):
    for change in ("missing", "unknown"):
        data = case.model_dump(mode="json")
        if change == "missing":
            del data["objective"]
        else:
            data["unexpected"] = "value"
        with pytest.raises(ValidationError):
            Case.model_validate(data)


def test_F03_duplicate_version_conflict():
    data = catalog().model_dump(mode="json")
    duplicate = deepcopy(data["tests"][0])
    duplicate["version"] = "different-version"
    data["tests"].append(duplicate)
    with pytest.raises(ValidationError, match="DUPLICATE"):
        Catalog.model_validate(data)


def test_F04_invalid_references():
    for field in ("control_ids", "risk_ids", "threat_ids", "target_id"):
        data = catalog().model_dump(mode="json")
        data["tests"][0][field] = "unknown" if field == "target_id" else ["unknown"]
        with pytest.raises(ValidationError, match="REFERENCE"):
            Catalog.model_validate(data)


def test_F05_stable_normalized_plan():
    assert canonical(plan().model_dump(mode="json")) == canonical(plan().model_dump(mode="json"))


def test_F08_oversized_input_and_limits(tmp_path, case):
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * 1_048_577)
    with pytest.raises(Invalid, match="SIZE-LIMIT"):
        load(path)
    data = case.model_dump(mode="json")
    data["limits"]["concurrency"] = 2
    with pytest.raises(ValidationError):
        Case.model_validate(data)


def test_all_schemas_match_typed_contracts():
    for name, model in CONTRACTS.items():
        schema = load(PROJECT / "schemas" / (name + ".schema.json"))
        jsonschema.Draft202012Validator.check_schema(schema)
        schema.pop("$schema")
        assert schema == model.model_json_schema()
