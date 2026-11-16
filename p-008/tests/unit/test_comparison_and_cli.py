from p008.cli import main
from p008.comparison import compare
from p008.models import HumanAdjudication
from p008.pipeline import execute, make_plan, reproduce
from p008.safety import Invalid
import pytest
from pydantic import ValidationError


def test_identical_identity_comparison_unchanged(registry, run):
    again = execute(registry, run.plan.plan_id)
    result = compare(run, again)
    assert result.comparable and result.classification == "UNCHANGED"
    assert len(result.transitions) == 48 and result.pass_rate_delta == 0


def test_sample_level_mixed_transitions_retained(run):
    rows = list(run.results)
    rows[0] = rows[0].model_copy(update={"status": "FAIL"})
    bad = next(i for i, r in enumerate(rows) if r.sample_id == "p008-injection-04")
    rows[bad] = rows[bad].model_copy(update={"status": "PASS"})
    after = run.model_copy(update={"results": rows})
    result = compare(run, after)
    assert result.classification == "MIXED"
    assert result.transitions[rows[0].sample_id] == ["PASS", "FAIL"]
    assert result.transitions[rows[bad].sample_id] == ["FAIL", "PASS"]


def test_incomplete_comparison_blocked(registry):
    plan = make_plan(registry, policy="timeout")
    before, after = execute(registry, plan.plan_id), execute(registry, plan.plan_id)
    assert compare(before, after).classification == "BLOCKED"


def test_full_reproduction_retains_failures(registry, run):
    result = reproduce(registry, run.run_id)
    assert result["output_match"] and result["original_output_sha256"] == result["reproduced_output_sha256"]
    assert result["evaluation_status"] == "FAIL"


def test_cli_failure_exit_code_and_dry_run(registry, capsys):
    argv = ["--root", str(registry.root), "eval"]
    assert main(argv + ["--dry-run"]) == 0
    assert '"network":"disabled"' in capsys.readouterr().out
    assert main(argv) == 1
    assert '"status":"FAIL"' in capsys.readouterr().out


def test_human_adjudication_cannot_be_auto_verified():
    with pytest.raises(ValidationError, match="HUMAN-REVIEW"):
        HumanAdjudication(
            adjudication_id="a",
            sample_id="b",
            previous_outcome_digest="a" * 64,
            proposed_outcome_digest="b" * 64,
            state="accepted",
            reviewer=None,
            evidence=None,
            reason="needs review",
        )


def test_source_task_and_scorer_bytes_checked(registry, monkeypatch):
    from p008 import pipeline

    plan = make_plan(registry)
    monkeypatch.setattr(pipeline, "implementation", lambda name: "d" * 64)
    with pytest.raises(Invalid, match="TASK-IMPLEMENTATION-DRIFT"):
        pipeline.preflight(registry, plan)


def test_unknown_sample_reproduction_rejected(registry, run):
    with pytest.raises(Invalid, match="SAMPLE-NOT-IN"):
        reproduce(registry, run.run_id, "unknown-sample")
