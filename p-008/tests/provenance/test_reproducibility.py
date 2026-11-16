import copy

import pytest

from p008.exports import export
from p008.generation import generate
from p008.models import Provenance
from p008.pipeline import make_plan, reproduce
from p008.registry import Registry
from p008.safety import Invalid, digest, implementation


def test_P01_manifest_has_generator_commit_seed_hash(registry):
    bundle, manifest = registry.dataset()
    p = bundle.card.provenance
    assert p.commit and len(p.commit) == 40 and p.seed == 20261116
    assert manifest.generator_source_hash == p.source_sha256 == implementation("generation.py")
    assert manifest.bundle_digest == bundle.card.manifest_digest


def test_P02_scorer_and_rubric_identity_retained(bundle):
    scorer = bundle.scorers[0]
    assert scorer.implementation_digest == implementation("scoring.py")
    assert scorer.rubric.version == "1.0.0" and scorer.rubric.threshold == 1.0
    assert len(digest(scorer.rubric)) == 64


def test_P03_tool_model_provider_identity_in_plan(registry):
    plan = make_plan(registry)
    assert plan.evaluator.provider == "p008-local" and plan.evaluator.model == "deterministic-policy-v1"
    assert plan.evaluator.tool == "offline" and plan.evaluator.tool_version == "1.0.0"
    assert plan.dependency_lock_hash and plan.runtime and plan.source_hashes


def test_P04_unchanged_artifacts_verify(registry):
    bundle, manifest = registry.dataset()
    assert len(manifest.artifacts) == 4 and len(bundle.samples) == 48


def test_P05_modified_sample_label_scorer_detected(tmp_path, bundle):
    for index, name in enumerate(("dataset.json", "private/outcomes.json", "model-inputs.json")):
        registry = Registry(tmp_path / str(index))
        registry.freeze(copy.deepcopy(bundle))
        path = registry.path("datasets", "synthetic-core", "1.0.0") / name
        path.write_bytes(path.read_bytes() + b" ")
        with pytest.raises(Invalid, match="MODIFIED-ARTIFACT"):
            registry.dataset()


def test_P06_missing_artifact_detected(registry):
    (registry.path("datasets", "synthetic-core", "1.0.0") / "splits.json").unlink()
    with pytest.raises(Invalid, match="MISSING-ARTIFACT"):
        registry.dataset()


def test_P07_new_version_preserves_baseline(registry):
    _, original = registry.dataset()
    registry.freeze(generate(7, "1.1.0"))
    _, retained = registry.dataset()
    assert digest(retained) == digest(original)
    assert registry.dataset(version="1.1.0")[0].card.provenance.seed == 7


def test_P08_reproduction_reports_implementation_drift(registry, run, monkeypatch):
    from p008 import pipeline

    monkeypatch.setattr(pipeline, "source_hashes", lambda: {"changed.py": "f" * 64})
    with pytest.raises(Invalid, match="IMPLEMENTATION-DRIFT"):
        reproduce(registry, run.run_id)


def test_P09_upstream_commit_attribution_preserved(bundle):
    value = bundle.card.provenance.model_dump(mode="json")
    value.update(
        source_type="upstream_benchmark",
        repository="https://github.com/UKGovernmentBEIS/inspect_evals",
        commit="a4205c238a40de36204c487fa38d7720bc1085cf",
        license_id="MIT",
        redistribution="allowed",
        attribution="UK AI Security Institute; source reference only",
    )
    source = Provenance.model_validate(value)
    assert source.model_dump()["commit"] == value["commit"] and source.attribution == value["attribution"]


def test_P10_public_export_excludes_markers_and_sealed_rows(registry, run):
    folder = export(registry, run_id=run.run_id)
    raw = b"".join(p.read_bytes() for p in folder.iterdir())
    assert b"P008_DUMMY_SECRET" not in raw and b"P008_HOLDOUT_" not in raw and b'"label_key"' not in raw
    import json

    summary = json.loads((folder / "evaluation-report.json").read_text())
    bundle, _ = registry.dataset()
    sealed = {s.sample_id for s in bundle.samples if s.split == "sealed_holdout"}
    assert not sealed & {r["sample_id"] for r in summary["results"]}
    assert summary["omission_policy"]["sealed_results_excluded"] == 10
