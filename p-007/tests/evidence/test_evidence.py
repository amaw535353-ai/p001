import json
import pytest
from p007.assertions import normalize
from p007.evidence import reproduce, verify
from p007.exports import export
from p007.models import ReproductionRequest, RunnerResult
from p007.safety import Invalid


def test_E01_manifest_identities(offline_run):
    value = verify(offline_run)
    assert value.repository["commit_sha"]
    assert value.repository["head_state"] in ("attached", "detached")
    if value.repository["head_state"] == "attached":
        assert value.repository["branch"]
    else:
        assert value.repository["branch"] is None
    assert value.target.target_id == "offline-demo" and value.target.environment == "offline"
    assert all(r.definition_hash for r in value.results)


def test_E02_unchanged_hashes_verify(offline_run):
    assert len(verify(offline_run).artifacts) == 14


def test_E03_modified_artifact(offline_run):
    (offline_run / "T-offline-allowed.json").write_text("{}")
    with pytest.raises(Invalid, match="MODIFIED"):
        verify(offline_run)


def test_E04_missing_artifact(offline_run):
    (offline_run / "T-offline-allowed.json").unlink()
    with pytest.raises(Invalid, match="MISSING"):
        verify(offline_run)


def test_E05_redaction_after_leak_oracle(case):
    raw = RunnerResult(
        adapter="offline",
        executed=True,
        original_status="COMPLETE",
        exit_code=0,
        tool_version="builtin-1.0",
        observed={"http_status": 200, "decision": "ALLOW", "output": "P007_SECRET_DUMMY_CONTEXT"},
        metadata={
            "Authorization": "Bearer P007_TOKEN_SYNTHETIC",
            "cookie": "P007_COOKIE_SYNTHETIC",
            "cookie_httponly": True,
        },
    )
    result = normalize(case, raw, compatibility={})
    text = result.model_dump_json()
    assert result.status == "FAIL" and result.assertion == "FORBIDDEN-MARKER-PRESENT"
    assert "P007_SECRET" not in text and "P007_TOKEN" not in text and "P007_COOKIE" not in text
    assert "REDACTED" in text
    assert result.runner.metadata["cookie_httponly"] is True


def test_E06_failure_flaky_and_inconclusive_retained(offline_run, tmp_path):
    value = verify(offline_run)
    output = export(value, offline_run, tmp_path / "export")
    assert (
        "| FAIL |" in (output / "report.md").read_text() and "| FLAKY |" in (output / "report.md").read_text()
    )
    assert "<failure" in (output / "junit.xml").read_text()
    from p007.exports import markdown

    inconclusive = value.results[0].model_copy(update={"status": "INCONCLUSIVE"})
    assert "INCONCLUSIVE" in markdown(
        value.model_copy(update={"results": [inconclusive, *value.results[1:]]})
    )


def test_E07_recorded_offline_reproduction(offline_run):
    value = reproduce(
        offline_run,
        ReproductionRequest(run_id=offline_run.name, test_id="T-offline-cross-tenant", repetitions=2),
    )
    assert (
        value["status"] == "PASS" and len(value["runs"]) == 2 and all(r["consistent"] for r in value["runs"])
    )


def test_E08_dirty_tree_disclosure(monkeypatch):
    from p007.evidence import repository_identity

    state = {"status": "?? synthetic-uncommitted-file", "branch": "synthetic-feature"}

    def git(command, **kwargs):
        if "status" in command:
            return state["status"]
        if "rev-parse" in command:
            return "a" * 40
        return state["branch"]

    monkeypatch.setattr("subprocess.check_output", git)
    repo = repository_identity()
    assert repo["dirty"] is True and repo["commit_represents_working_tree"] is False
    assert repo["head_state"] == "attached" and repo["branch"] == "synthetic-feature"

    # GitHub PR checkouts have an actual commit but no named branch. Preserve
    # that identity without fabricating a branch or classifying it as unknown.
    state.update(status="", branch="")
    detached = repository_identity()
    assert detached["commit_sha"] == "a" * 40
    assert detached["head_state"] == "detached" and detached["branch"] is None
    assert detached["dirty"] is False and detached["commit_represents_working_tree"] is True


def test_manifest_result_edit_detected(offline_run):
    path = offline_run / "manifest.json"
    data = json.loads(path.read_text())
    data["results"][0]["status"] = "FAIL"
    path.write_text(json.dumps(data))
    with pytest.raises(Invalid, match="RESULT-MISMATCH"):
        verify(offline_run)
