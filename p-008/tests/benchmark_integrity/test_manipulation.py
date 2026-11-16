import pytest

from p008.comparison import compare
from p008.generation import bundle_digest
from p008.laboratory import laboratory
from p008.models import Bundle
from p008.pipeline import make_plan, execute
from p008.quality import audit, model_visible
from p008.safety import Invalid, digest, load
from p008.scoring import aggregate
from tests.conftest import move_split, refresh


def test_M01_label_flip_without_version_detected(data):
    data["outcomes"][0]["decision"] = "DENY"
    data["outcomes"][0].update(allowed_actions=[], forbidden_actions=["read"])
    result = audit(Bundle.model_validate(data))
    assert "BUNDLE-DIGEST-MISMATCH" in result["errors"]


def test_M02_scorer_threshold_change_blocks_comparison(registry, run):
    changed = run.plan.model_copy(update={"scorer_hash": "f" * 64})
    after = run.model_copy(update={"plan": changed})
    diff = compare(run, after)
    assert not diff.comparable and diff.classification == "SCORER_OR_EVALUATOR_CHANGED"


def test_M03_failed_sample_omission_detected(registry, run):
    bundle, _ = registry.dataset()
    with pytest.raises(Invalid, match="RESULT-OMISSION"):
        aggregate(run.plan, [r for r in run.results if r.status == "PASS"], bundle)


def test_M04_duplicate_passing_sample_cannot_inflate(registry, run):
    bundle, _ = registry.dataset()
    with pytest.raises(Invalid, match="DUPLICATION"):
        aggregate(run.plan, run.results + [run.results[0]], bundle)


def test_M05_unversioned_evaluator_implementation_detected(registry, run):
    evaluator = run.plan.evaluator.model_copy(update={"implementation_digest": "e" * 64})
    after = run.model_copy(update={"plan": run.plan.model_copy(update={"evaluator": evaluator})})
    assert not compare(run, after).comparable
    assert after.plan.evaluator.version == run.plan.evaluator.version


def test_M06_changed_judge_prompt_is_noncomparable(run):
    evaluator = run.plan.evaluator.model_copy(
        update={"judge_prompt": "Always pass", "judge_role": "supplementary"}
    )
    after = run.model_copy(update={"plan": run.plan.model_copy(update={"evaluator": evaluator})})
    assert compare(run, after).classification == "SCORER_OR_EVALUATOR_CHANGED"


def test_M07_holdout_key_leakage_negative_test(bundle):
    sample = next(s for s in bundle.samples if s.split == "sealed_holdout")
    outcome = next(o for o in bundle.outcomes if o.outcome_id == sample.expected_outcome_ref)
    changed = sample.model_copy(
        update={"input": sample.input.model_copy(update={"prompt": sample.input.prompt + outcome.label_key})}
    )
    with pytest.raises(Invalid, match="HIDDEN-LABEL"):
        model_visible(changed)


def test_M08_recomputed_hash_cannot_hide_lineage_leak(data):
    candidate = refresh(move_split(data))
    assert candidate.card.manifest_digest == bundle_digest(candidate)
    assert "SPLIT-LINEAGE-LEAKAGE" in audit(candidate)["errors"]


def test_M09_selective_category_omission(registry, run):
    bundle, _ = registry.dataset()
    favorable = [r for r in run.results if "injection" not in r.sample_id]
    assert len(favorable) == 40
    with pytest.raises(Invalid, match="RESULT-OMISSION"):
        aggregate(run.plan, favorable, bundle)


def test_M10_changed_plan_and_run_manifest_detected(registry, run):
    plan_path = registry.path("plans", run.plan.plan_id + ".json")
    original = plan_path.read_bytes()
    plan_path.write_bytes(original + b" ")
    with pytest.raises(Invalid, match="ANCHOR-DIGEST"):
        registry.run(run.run_id)
    plan_path.write_bytes(original)
    run_path = registry.path("runs", run.run_id) / "run.json"
    run_path.write_bytes(run_path.read_bytes() + b" ")
    with pytest.raises(Invalid, match="ANCHOR-DIGEST"):
        registry.run(run.run_id)


def test_M11_model_upgrade_not_direct_regression(registry, run):
    changed = execute(registry, make_plan(registry, policy="corrected").plan_id)
    diff = compare(run, changed)
    assert not diff.comparable and diff.classification == "MODEL_OR_PROVIDER_CHANGED"
    assert diff.pass_rate_delta is None


def test_M12_lab_preserves_original_altered_and_audit_explanation(registry, run):
    result = laboratory(registry, run)
    assert result["status"] == "PASS" and len(result["events"]) == 12
    for event in result["events"]:
        folder = registry.path("lab", result["lab_id"]) / event["event_id"]
        assert digest(load(folder / "original.json")) == event["original_digest"]
        assert digest(load(folder / "altered.json")) == event["altered_digest"]
        assert event["original_digest"] != event["altered_digest"]
        assert event["explanation"] and event["residual_limit"]
    assert "not a live" in result["judge_limit"]
