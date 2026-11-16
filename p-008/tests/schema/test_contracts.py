import copy

import jsonschema
import pytest
from pydantic import ValidationError

from p008.models import Bundle, DatasetCard, EvaluationSample, ExpectedOutcome
from p008.safety import Invalid, bounded


def test_S01_valid_card_and_manifest(registry, bundle):
    _, manifest = registry.dataset()
    jsonschema.validate(bundle.card.model_dump(mode="json"), DatasetCard.model_json_schema())
    jsonschema.validate(manifest.model_dump(mode="json"), type(manifest).model_json_schema())
    assert manifest.sample_ids == [s.sample_id for s in bundle.samples]


def test_S02_missing_sample_fields_and_unknown_fields(bundle):
    data = bundle.samples[0].model_dump(mode="json")
    data.pop("input")
    with pytest.raises(ValidationError):
        EvaluationSample.model_validate(data)
    data = bundle.samples[0].model_dump(mode="json")
    data["execute_plugin"] = "malicious"
    with pytest.raises(ValidationError):
        EvaluationSample.model_validate(data)


def test_S03_duplicate_registry_ids_rejected(data):
    for table in ("samples", "tasks", "scorers"):
        mutated = copy.deepcopy(data)
        mutated[table].append(copy.deepcopy(mutated[table][0]))
        if table == "samples":
            mutated["card"]["sample_count"] += 1
        with pytest.raises(ValidationError, match="DUPLICATE"):
            Bundle.model_validate(mutated)


def test_S04_bad_cross_references_rejected(data):
    data["samples"][0]["scorer_version"] = "9.0.0"
    with pytest.raises(ValidationError, match="REFERENCE"):
        Bundle.model_validate(data)


def test_S05_unsupported_modality_and_capability(data):
    invalid = copy.deepcopy(data)
    invalid["samples"][0]["modality"] = "image"
    with pytest.raises(ValidationError):
        Bundle.model_validate(invalid)
    data["card"]["capabilities"] = ["structured_response"]
    with pytest.raises(ValidationError, match="UNSUPPORTED-CAPABILITY"):
        Bundle.model_validate(data)


def test_S06_outcome_and_label_provenance_required(bundle):
    data = bundle.outcomes[0].model_dump(mode="json")
    for missing in ("decision", "label_provenance"):
        changed = dict(data)
        changed.pop(missing)
        with pytest.raises(ValidationError):
            ExpectedOutcome.model_validate(changed)


def test_S07_content_dataset_and_structure_bounds(data):
    oversized = copy.deepcopy(data)
    oversized["samples"][0]["input"]["prompt"] = "a" * 8193
    with pytest.raises(ValidationError):
        Bundle.model_validate(oversized)
    data["samples"] *= 6
    with pytest.raises(ValidationError, match="256"):
        Bundle.model_validate(data)
    nested = {}
    for _ in range(30):
        nested = {"child": nested}
    with pytest.raises(Invalid, match="STRUCTURE-LIMIT"):
        bounded(nested)


def test_S08_frozen_version_cannot_be_overwritten(registry, bundle):
    before = (registry.path("datasets", "synthetic-core", "1.0.0") / "manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        registry.freeze(bundle)
    assert before == (registry.path("datasets", "synthetic-core", "1.0.0") / "manifest.json").read_bytes()
