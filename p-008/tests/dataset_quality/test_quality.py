import pytest
from pydantic import ValidationError

from p008.exports import publication_eligible
from p008.generation import generate
from p008.models import Provenance
from p008.quality import audit, model_visible
from p008.safety import Invalid, canonical, digest
from tests.conftest import move_split, refresh


def test_D01_same_seed_stable_content():
    assert digest(generate(20261116)) == digest(generate(20261116))


def test_D02_new_seed_and_version_retained():
    before, after = generate(1), generate(2, "1.1.0")
    assert before.card.provenance.seed == 1 and after.card.provenance.seed == 2
    assert after.card.version == "1.1.0" and digest(before) != digest(after)


def test_D03_exact_duplicates_detected(data):
    data["samples"][1]["input"] = dict(data["samples"][0]["input"])
    result = audit(refresh(data))
    assert result["exact_duplicates"] and "EXACT-DUPLICATES" in result["errors"]


def test_D04_near_duplicates_are_review_signal(data):
    data["samples"][1]["input"]["prompt"] = data["samples"][0]["input"]["prompt"] + " Please."
    result = audit(refresh(data))
    assert result["near_duplicate_candidates"]
    assert result["near_duplicate_candidates"][0]["review_only"] is True
    assert result["status"] == "PASS" and not result["leakage_groups"]


def test_D05_lineage_split_leakage(data):
    result = audit(refresh(move_split(data)))
    assert "SPLIT-LINEAGE-LEAKAGE" in result["errors"]
    assert any(x.startswith("scenario:") for x in result["leakage_groups"])


def test_D06_sealed_labels_absent_from_visible_inputs(bundle):
    sealed = [s for s in bundle.samples if s.split == "sealed_holdout"]
    assert len(sealed) == 10
    for sample in sealed:
        visible = canonical(model_visible(sample))
        assert b"P008_HOLDOUT_" not in visible and b"expected_outcome" not in visible
        assert b"label_key" not in visible


def test_D07_upstream_license_and_permission_required(bundle):
    p = bundle.card.provenance.model_dump(mode="json")
    p.pop("license_id")
    with pytest.raises(ValidationError):
        Provenance.model_validate(p)
    provenance = bundle.card.provenance.model_copy(
        update={"source_type": "upstream_benchmark", "redistribution": "restricted"}
    )
    changed = bundle.model_copy(update={"card": bundle.card.model_copy(update={"provenance": provenance})})
    with pytest.raises(Invalid, match="LICENSE"):
        publication_eligible(changed)


def test_D08_expected_outcome_consistency(data):
    target = next(e for e in data["outcomes"] if e["decision"] == "DENY")
    target.update(allowed_actions=["write"], forbidden_actions=[])
    result = audit(refresh(data))
    assert any("INCONSISTENT-EXPECTED" in e for e in result["errors"])


def test_D09_coverage_reconciles_to_samples(bundle):
    result = audit(bundle)
    assert result["sample_count"] == 48
    for key in ("family", "split", "modality", "difficulty", "outcome"):
        assert sum(result["coverage"][key].values()) == 48
    assert result["coverage"]["risk"] == {"21": 8}


def test_D10_ambiguous_labels_require_adjudication(data):
    data["outcomes"][0]["adjudication"] = "ambiguous"
    result = audit(refresh(data))
    assert any("LABEL-REVIEW-REQUIRED" in e for e in result["errors"])
