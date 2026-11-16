from p007.assertions import normalize
from p007.catalog import plan
from p007.evidence import run, verify
from p007.models import RunnerResult


def test_F06_unsupported_p006_blocked(tmp_path):
    result = verify(run(plan("p006-unavailable", "p006"), root=tmp_path)).results[0]
    assert result.status == "BLOCKED" and not result.runner.executed


def test_F07_exit_zero_is_not_oracle(case):
    raw = RunnerResult(
        adapter="offline",
        executed=True,
        original_status="COMPLETE",
        exit_code=0,
        observed={"http_status": 403, "decision": "DENY"},
        tool_version="builtin-1.0",
    )
    result = normalize(case, raw, compatibility={})
    assert result.status == "FAIL" and result.runner.exit_code == 0


def test_nonzero_raw_exit_and_status_retained(case):
    raw = RunnerResult(
        adapter="promptfoo",
        executed=True,
        original_status="PROVIDER-DIED",
        exit_code=23,
        error_class="provider",
        tool_version="0.125.1",
    )
    result = normalize(case, raw, compatibility={})
    assert result.status == "INCONCLUSIVE"
    assert result.runner.exit_code == 23 and result.runner.original_status == "PROVIDER-DIED"


def test_skip_and_missing_observation_never_pass(case):
    for executed, label in ((False, "SKIP"), (True, "COMPLETE")):
        raw = RunnerResult(
            adapter="offline",
            executed=executed,
            original_status=label,
            exit_code=0,
            tool_version="builtin-1.0",
        )
        assert normalize(case, raw, compatibility={}).status in ("NOT_TESTED", "INCONCLUSIVE")


def test_retired_case_not_applicable_never_pass(case):
    raw = RunnerResult(
        adapter="offline",
        executed=False,
        original_status="NOT_APPLICABLE",
        exit_code=None,
        tool_version="builtin-1.0",
    )
    retired = case.model_copy(update={"lifecycle": "retired"})
    assert normalize(retired, raw, compatibility={}).status == "NOT_APPLICABLE"


def test_oracle_requires_value_types(case):
    raw = RunnerResult(
        adapter="offline",
        executed=True,
        original_status="COMPLETE",
        exit_code=0,
        observed={"http_status": "200", "decision": "ALLOW"},
        tool_version="builtin-1.0",
    )
    assert normalize(case, raw, compatibility={}).status == "FAIL"
