import pytest
from p007.catalog import plan
from p007.evidence import baseline, run, verify
from p007.regression import compare, transition


def test_G01_immutable_baseline(offline_run):
    ref = baseline(offline_run, "synthetic-baseline")
    before = ref.read_bytes()
    with pytest.raises(FileExistsError):
        baseline(offline_run, "synthetic-baseline")
    assert ref.read_bytes() == before


def test_G02_regression(tmp_path):
    a = verify(run(plan(variant="remediated"), root=tmp_path))
    b = verify(run(plan(variant="regressed"), root=tmp_path))
    value = compare(a, b, "synthetic-regression-v1")
    assert (
        next(e for e in value.entries if e.test_id == "T-offline-regression-sentinel").classification
        == "REGRESSION"
    )


def test_G03_improvement_retains_original_failure(tmp_path):
    a = verify(run(plan(), root=tmp_path))
    b = verify(run(plan(variant="remediated"), root=tmp_path))
    value = compare(a, b, "synthetic-remediation-v1")
    assert (
        next(e for e in value.entries if e.test_id == "T-offline-output-validation").classification
        == "IMPROVED"
    )
    assert next(r for r in a.results if r.test_id == "T-offline-output-validation").status == "FAIL"


def test_G04_unchanged_pass_and_fail(offline_run):
    value = compare(verify(offline_run), verify(offline_run))
    assert {e.classification for e in value.entries} >= {"UNCHANGED_PASS", "UNCHANGED_FAIL"}


def test_G05_changes_noncomparable_even_with_wrong_rule(tmp_path):
    a = verify(run(plan(), root=tmp_path))
    b = verify(run(plan(variant="remediated"), root=tmp_path))
    assert all(e.classification == "BLOCKED_OR_NOT_COMPARABLE" for e in compare(a, b).entries)
    changed = b.results[0].model_copy(
        update={
            "compatibility_hash": "0" * 64,
            "compatibility": {**b.results[0].compatibility, "model": "different"},
        }
    )
    altered = b.model_copy(update={"results": [changed, *b.results[1:]]})
    assert (
        next(
            e for e in compare(a, altered, "synthetic-remediation-v1").entries if e.test_id == changed.test_id
        ).classification
        == "BLOCKED_OR_NOT_COMPARABLE"
    )


def test_G06_inconsistent_repetitions_flaky(offline_run):
    result = next(r for r in verify(offline_run).results if r.test_id == "T-offline-repeated-model")
    assert result.status == "FLAKY" and len(result.runner.samples) == 3
    assert {s["decision"] for s in result.runner.samples} == {"ALLOW", "DENY"}


def test_G07_blocked_and_untested_not_passes():
    assert transition("BLOCKED", "PASS") == "BLOCKED_OR_NOT_COMPARABLE"
    assert transition("NOT_TESTED", "PASS") == "BLOCKED_OR_NOT_COMPARABLE"


def test_G08_remediation_and_retest_links(tmp_path):
    a = verify(run(plan(), root=tmp_path))
    b = verify(
        run(plan(variant="remediated"), root=tmp_path, remediation_ref="SIMULATED-fix-01", retest_of=a.run_id)
    )
    value = compare(a, b, "synthetic-remediation-v1")
    assert value.remediation_ref == "SIMULATED-fix-01" and b.retest_of == a.run_id
    assert value.retest_evidence == b.run_id + "/manifest.json"
