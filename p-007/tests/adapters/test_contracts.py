import pytest
from p007.adapters import execute_test
from p007.adapters.promptfoo import parse_results
from p007.adapters.zap import observations, automation
from p007.assertions import normalize
from p007.authorization import active_zap_gate
from p007.catalog import plan
from p007.models import RunnerResult
from p007.runners import Capability
from p007.safety import Blocked


def test_R03_provider_error_and_timeout_not_pass(case):
    with pytest.raises(ValueError, match="PROVIDER-ERROR"):
        parse_results({"results": {"results": [{"error": "synthetic provider failed"}]}})
    for kind in ("provider", "timeout"):
        raw = RunnerResult(
            adapter="promptfoo",
            executed=True,
            original_status="ERROR",
            exit_code=None,
            error_class=kind,
            tool_version="0.125.1",
        )
        assert normalize(case, raw, compatibility={}).status == "INCONCLUSIVE"


def test_R06_missing_inspect_provider_blocked(monkeypatch):
    monkeypatch.setattr(
        "p007.adapters.discover",
        lambda _: Capability("inspect_ai", False, "absent", None, "missing model/provider"),
    )
    selected = plan("local-model", "inspect_ai", test_id="T-inspect_ai-allowed")
    raw = execute_test(selected.tests[0], selected)
    assert not raw.executed and raw.error_class == "dependency"
    assert normalize(selected.tests[0], raw, compatibility={}).status == "BLOCKED"


def test_R08_active_still_refused_with_optin_if_contract_unsupported():
    with pytest.raises(Blocked, match="UNSUPPORTED-BY-P003"):
        active_zap_gate(opt_in=True, guard=object())


def test_R09_alert_observation_never_confirmed():
    rows = observations(
        {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "10020",
                            "name": "Synthetic header",
                            "instances": [{}],
                            "confidence": "2",
                        }
                    ]
                }
            ]
        }
    )
    assert rows[0]["status"] == "OBSERVATION" and rows[0]["confirmed_vulnerability"] is False
    assert rows[0]["false_positive_review"] == "NOT_REVIEWED"


def test_zap_no_spider_active_or_requestor_jobs(tmp_path):
    jobs = automation("http://127.0.0.1:8767", tmp_path / "in.har", tmp_path)["jobs"]
    assert {j["type"] for j in jobs} == {"passiveScan-config", "import", "passiveScan-wait", "report"}
    job = next(j for j in jobs if j["type"] == "import")
    assert job["parameters"]["type"] == "har"
    assert set(job["parameters"]) == {"type", "fileName"}
