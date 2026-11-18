import copy

import pytest

from p009.adapters import import_p007, import_p008, p006_event, wazuh_alert
from p009.safety import REPO, ROOT, Invalid, canonical, digest, load, write_new


def test_actual_p007_report_schema_and_status_preservation():
    original = load(REPO / "p-007/examples/report-export.example.json")
    imported = import_p007(REPO / "p-007/examples/report-export.example.json")
    assert imported["report"] == original and imported["status"] == "REFERENCE_ONLY"
    assert {r["status"] for r in imported["report"]["results"]} == {"PASS", "FAIL", "FLAKY"}


@pytest.mark.parametrize(
    "mutation", ["contract", "version", "traversal", "collision", "unknown", "manifest_ref"]
)
def test_invalid_p007_handoff_refused(tmp_path, mutation):
    value = copy.deepcopy(load(REPO / "p-007/examples/report-export.example.json"))
    if mutation == "contract":
        value["handoff"]["contract"] = "forged"
    elif mutation == "version":
        value["schema_version"] = "9.0"
    elif mutation == "traversal":
        value["handoff"]["p009"]["artifacts"][0]["path"] = "../escape"
    elif mutation == "collision":
        value["handoff"]["p009"]["artifacts"].append(value["handoff"]["p009"]["artifacts"][0])
    elif mutation == "unknown":
        value["handoff"]["p009"]["execute"] = True
    else:
        value["handoff"]["p009"]["manifest_ref"] = "different/manifest.json"
    path = tmp_path / "report.json"
    write_new(path, canonical(value))
    with pytest.raises(Invalid):
        import_p007(path)


def p007_run(tmp_path):
    value = copy.deepcopy(load(REPO / "p-007/examples/report-export.example.json"))
    folder = tmp_path / value["run_id"]
    folder.mkdir(mode=0o700)
    owner = {"owner": "p007", "run_id": value["run_id"]}
    raw = canonical(owner)
    write_new(folder / "owner.json", raw)
    artifact = {
        "path": "owner.json",
        "media_type": "application/json",
        "schema_version": "1.0",
        "sha256": digest(raw),
        "size": len(raw),
    }
    # Build a source-contract fixture, never execute a P007 runner.
    manifest = {
        "schema_version": "1.0",
        "run_id": value["run_id"],
        "started_at": "2026-11-16T12:00:00Z",
        "ended_at": "2026-11-16T12:00:01Z",
        "duration_seconds": 1.0,
        "actor_label": "synthetic",
        "repository": {},
        "plan_digest": "a" * 64,
        "target": {
            "target_id": "fixture",
            "version": "v1",
            "environment": "offline",
            "origin": "http://127.0.0.1",
            "service_identity": "fixture",
            "owner": "p007",
            "ownership_ref": "fixture",
            "instance_id": "fixture",
            "allowed_ips": ["127.0.0.1"],
            "operations": [{"path": "/", "category": "llm"}],
            "capabilities": [],
        },
        "authorization": [],
        "artifacts": [artifact],
        "results": value["results"],
        "source_hash": "b" * 64,
        "redaction": [],
        "limitations": [],
        "reproduction": "fixture-only",
        "provenance": value["provenance"],
    }
    raw = canonical(manifest)
    write_new(folder / "manifest.json", raw)
    value["manifest_sha256"] = digest(raw)
    value["handoff"]["p009"]["artifacts"] = [artifact]
    path = tmp_path / "report.json"
    write_new(path, canonical(value))
    return path, folder


def test_p007_selected_run_bytes_size_and_hash_verified(tmp_path):
    path, folder = p007_run(tmp_path)
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    assert import_p007(path, folder)["status"] == "PASS"
    assert before == {p.name: p.read_bytes() for p in folder.iterdir()}


def test_p007_artifact_tamper_refused(tmp_path):
    path, folder = p007_run(tmp_path)
    (folder / "owner.json").write_bytes(canonical({"owner": "p007", "run_id": "forged"}))
    with pytest.raises(Invalid):
        import_p007(path, folder)


def test_p007_artifact_symlink_refused(tmp_path):
    path, folder = p007_run(tmp_path)
    original = (folder / "owner.json").read_bytes()
    (folder / "owner.json").unlink()
    (tmp_path / "external.json").write_bytes(original)
    (folder / "owner.json").symlink_to(tmp_path / "external.json")
    with pytest.raises(Invalid):
        import_p007(path, folder)


def test_p008_actual_shape_metadata_only():
    value = import_p008(ROOT / "fixtures/p008-handoff.json")
    assert value["status"] == "REFERENCE_ONLY" and value["summary"] is None
    assert "sealed outcomes" in value["excluded"]


@pytest.mark.parametrize("mutation", ["contract", "unknown", "digest", "kind"])
def test_p008_incompatible_handoff_refused(tmp_path, mutation):
    value = copy.deepcopy(load(ROOT / "fixtures/p008-handoff.json"))
    if mutation == "contract":
        value["contract"] = "forged"
    elif mutation == "unknown":
        value["p009"]["raw_trace_path"] = "sealed.json"
    elif mutation == "digest":
        value["p009"]["evidence_manifest_digest"] = "not-a-digest"
    else:
        value["p009"]["kind"] = "raw-outcomes"
    path = tmp_path / "handoff.json"
    write_new(path, canonical(value))
    with pytest.raises(Invalid):
        import_p008(path)


def test_p006_missing_request_is_not_decision_id(cfg):
    row = p006_event(
        cfg,
        {
            "event": "authorization",
            "decision_id": "decision-one",
            "policy_version": "p006-authz-v1",
            "reason": "ALLOW",
            "subject": "synthetic",
            "tenant": "tenant-a",
            "action": "chat",
            "model": "local-basic",
        },
        "2026-11-16T12:00:00Z",
    )
    assert row.request_id is None and row.authorization_decision_id == "decision-one"
    assert row.correlation_status == "partial"


def test_p006_failure_without_tenant_is_quarantined(cfg):
    with pytest.raises(Invalid, match="TENANT-UNAVAILABLE"):
        p006_event(cfg, {"event": "request_failed", "request_id": "request-one"}, "2026-11-16T12:00:00Z")


def test_p006_unknown_tenant_refused(cfg):
    with pytest.raises(Invalid):
        p006_event(
            cfg,
            {
                "event": "authorization",
                "decision_id": "one",
                "policy_version": "p006-authz-v1",
                "reason": "ALLOW",
                "subject": "synthetic",
                "tenant": "forged",
                "action": "chat",
                "model": "local-basic",
            },
            "2026-11-16T12:00:00Z",
        )


def test_wazuh_alert_preserves_reference_and_fixed_level(cfg):
    alert = {
        "id": "100.200",
        "timestamp": "2026-11-16T12:00:00Z",
        "rule": {"id": "110900", "level": 5},
        "data": {"p009": "v1", "signal": "authorization-denials", "count": "3", "event_id": "security-one"},
    }
    event = wazuh_alert(cfg, alert)
    assert event.related_event_id == "security-one" and event.alert_id == "100.200"
    assert event.wazuh_rule_id == "110900" and event.event_severity == 5


def test_wazuh_forged_native_level_refused(cfg):
    with pytest.raises(Invalid):
        wazuh_alert(
            cfg,
            {
                "id": "100.200",
                "timestamp": "2026-11-16T12:00:00Z",
                "rule": {"id": "110900", "level": 15},
                "data": {
                    "p009": "v1",
                    "signal": "authorization-denials",
                    "count": 3,
                    "event_id": "security-one",
                },
            },
        )


def test_p008_summary_omits_sample_results_and_evaluator_content(tmp_path):
    value = copy.deepcopy(load(ROOT / "fixtures/p008-handoff.json"))
    value["p009"].update(run_id="run-fixture", evidence_manifest_digest="a" * 64)
    metrics = {
        key: 0
        for key in (
            "unique_samples",
            "observations",
            "executed",
            "passed",
            "failed",
            "blocked",
            "not_tested",
            "inconclusive",
            "false_accepts",
            "false_rejects",
        )
    }
    metrics.update(
        flaky_sample_ids=[],
        critical_sample_ids=[],
        unique_pass_rate=None,
        wilson95=None,
        categories={},
        definitions="Synthetic aggregate fixture",
        limitations="No native run",
    )
    value["summary"] = {
        "schema_version": "1.0",
        "run_id": "run-fixture",
        "status": "NOT_TESTED",
        "plan_digest": "b" * 64,
        "dataset_manifest_digest": "c" * 64,
        "dataset": ["synthetic-core", "1.0.0"],
        "evaluator": {
            "evaluator_id": "fixture",
            "version": "1.0.0",
            "tool": "offline",
            "tool_version": "1.0.0",
            "adapter_version": "1.0.0",
            "implementation_digest": "d" * 64,
            "provider": "p008-local",
            "model": "deterministic-policy-v1",
            "model_version": "1.0.0",
            "prompt": "P009_PROMPT_CANARY",
            "config": "reviewed-local-v1",
        },
        "metrics": metrics,
        "results": [{"sample_id": "P008_HOLDOUT_sample", "status": "FAIL"}],
        "limitations": ["Synthetic contract fixture"],
        "provenance": {"implementation": "Codex implemented"},
    }
    path = tmp_path / "handoff.json"
    write_new(path, canonical(value))
    result = import_p008(path)
    assert "CANARY" not in canonical(result).decode() and "HOLDOUT" not in canonical(result).decode()
    assert "results" not in result["summary"] and "prompt" not in result["summary"]["evaluator"]
