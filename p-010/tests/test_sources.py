"""Actual pinned source contracts and provenance regressions."""

import copy
import json
from pathlib import Path

import pytest

from p010 import oscal
from p010.demo import AT
from p010.safety import REPO, ROOT, Invalid, canonical, digest, load
from p010.sources import import_file, p003, p005, p007, p008, p009, schema

POLICY = REPO / "p-003/examples/synthetic-approved-policy.json"
ENGAGEMENT = REPO / "p-003/examples/engagement-draft-a.json"
THREATS = REPO / "p-005/examples/reference-architecture/threat-register.json"
MODEL = REPO / "p-005/examples/reference-architecture/model.json"
CASES = REPO / "p-005/examples/reference-architecture/verification-plan.json"
RISK = REPO / "p-005/src/p005/data/risks.json"
P007 = REPO / "p-007/examples/report-export.example.json"
P008 = ROOT / "fixtures/p008-export.json"
P009 = REPO / "p-009/contracts/examples/p009-handoff.json"


@pytest.mark.parametrize(
    ("project", "path", "contract"),
    [
        pytest.param("p003", ENGAGEMENT, "p003-engagement-1.0", id="C01"),
        pytest.param("p005", MODEL, "p005-model-1.0", id="C06"),
        pytest.param("p006", REPO / "p-006/config/hardened.json", "p006-profile-v1", id="D01-profile"),
        pytest.param(
            "p006",
            REPO / "p-006/contracts/architecture/service-inventory.json",
            "p006-inventory-v1",
            id="D01-inventory",
        ),
        pytest.param(
            "p004", REPO / "p-004/fixtures/static/architecture.json", "p004-architecture-v1", id="C06-p004"
        ),
        pytest.param("p007", P007, "p007-handoff-v1", id="D03"),
        pytest.param("p008", P008, "p008-handoff-1.0", id="D09"),
        pytest.param("p009", P009, "p009-handoff-v1", id="D12"),
    ],
)
def test_pinned_source_contract(project, path, contract):
    data = import_file(project, path, imported_at=AT)
    assert data.contract == contract
    assert data.source_sha256 == digest(path.read_bytes())
    assert data.schema_sha256


def test_B04_B05_B07_B10_import_provenance():
    source = import_file("p003", POLICY, imported_at=AT)
    assert (source.project, source.contract, source.source_version) == (
        "P-003",
        "p003-engagement-policy-1.0",
        "1",
    )
    assert source.source_time == "2026-11-15T08:00:00Z"
    assert source.imported_at == AT
    assert source.schema_sha256 == schema("p003", "engagement-policy")[1]
    assert source.transform_version == "p010-source-projection-1.0"


def test_B06_missing_source_provenance_is_null():
    result = import_file("p007", P007)
    assert result.source_commit is None
    assert result.source_time is None
    assert all(row.integrity == "REFERENCE_ONLY" for row in result.artifacts)


def test_B08_E06_import_does_not_edit_source(tmp_path):
    local = tmp_path / "readonly.json"
    local.write_bytes(P007.read_bytes())
    local.chmod(0o400)
    original = local.stat().st_mtime_ns
    import_file("p007", local)
    assert digest(local.read_bytes()) == digest(P007.read_bytes())
    assert local.stat().st_mtime_ns == original


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("p003", id="B09-p003"),
        pytest.param("p007", id="B09-p007"),
        pytest.param("p008", id="B09-p008"),
        pytest.param("p009", id="B09-p009"),
    ],
)
def test_incompatible_versions(tmp_path, name):
    source = load({"p003": POLICY, "p007": P007, "p008": P008, "p009": P009}[name])
    source["schema_version"] = "9.9"
    path = tmp_path / "changed.json"
    path.write_bytes(canonical(source))
    with pytest.raises(Invalid):
        import_file(name, path)


def test_C02_scope_roe_and_evidence_policy_preserved():
    source = load(POLICY)
    result = import_file("p003", POLICY).payload
    for key in ("scope", "window", "expires_at"):
        assert result[key] == source[key]
    assert result["roe"]["allowed"] == source["resource_limits_and_stops"]["allowed"]
    assert result["roe"]["stop_conditions"] == source["resource_limits_and_stops"]["stop_conditions"]
    assert result["evidence_policy"]["retention_days"] == source["evidence_policy"]["retention_days"]


def _seal(data):
    data["content_digest"] = digest({key: child for key, child in data.items() if key != "content_digest"})


@pytest.mark.parametrize(
    ("at", "revoked", "status"),
    [
        pytest.param(AT, False, "EXPIRED", id="C03-expired"),
        pytest.param("2026-11-15T08:30:00Z", False, "OUTSIDE_WINDOW", id="C03-before"),
        pytest.param("2026-11-15T10:00:00Z", False, "HISTORICAL_REFERENCE", id="C03-snapshot"),
        pytest.param("2026-11-15T10:00:00Z", True, "REVOKED", id="C03-revoked"),
    ],
)
def test_policy_snapshot_never_grants_authority(at, revoked, status):
    data = load(POLICY)
    if revoked:
        data["status"] = "REVOKED"
        _seal(data)
    result = p003(data, at)
    assert result["payload"]["snapshot_context"] == status
    assert result["payload"]["real_legal_authority"] == "NOT VERIFIED"


def test_C04_p003_bearer_caveat_preserved():
    source = import_file("p003", POLICY)
    assert "Not a bearer capability" in source.payload["consumption"]
    assert "NOT VERIFIED" in source.payload["enforcement"]


def test_C05_O04_p003_draft_is_not_oscal():
    value = {"schema_version": "1.0", "kind": "oscal-mapping-draft", "conformance": "NOT VALID OSCAL"}
    assert p003(value, AT)["payload"]["conformance"] == "NOT VALID OSCAL"
    assert oscal.structural("assessment-plan", value)["conformance"] == "NOT VALID OSCAL"
    with pytest.raises(Invalid):
        p003({**value, "conformance": "VALID"}, AT)


def test_C07_source_threats_remain_hypotheses():
    original = load(THREATS)
    imported = import_file("p005", THREATS, flavor="threats").payload["threats"]
    assert {row["hypothesis_status"] for row in imported} == {"HYPOTHESIS"}
    assert [row["threat_id"] for row in imported] == [row["threat_id"] for row in original]


def test_C08_planned_verification_stays_unexecuted():
    projected = import_file("p005", CASES, flavor="verification").payload["verification"]
    assert len(projected) > 0 and all(
        not item["executable"] and item["run_status"] == "NOT_TESTED" for item in projected
    )
    changed = copy.deepcopy(load(CASES))
    changed[0]["run_status"] = "PASS"
    with pytest.raises(Invalid):
        p005(changed, "verification")


def test_C09_catalog_source_and_rule_review_are_preserved():
    complete = load(RISK)
    record = import_file("p005", RISK)
    assert record.payload == complete
    assert len(complete["entries"]) == 37
    assert sum(row["available"] for row in complete["entries"]) == 23
    original = load(THREATS)
    threats = import_file("p005", THREATS, flavor="threats").payload["threats"]
    assert [(x["rule_trace"], x["review_status"], x["risk_source"]) for x in threats] == [
        (row["rule_trace"], row["review_status"], row["risk_source"]) for row in original
    ]


def test_D02_p006_applicability_and_validation_state():
    context = REPO / "p-006/contracts/architecture/risk-applicability.json"
    source = import_file("p006", context)
    assert source.payload == load(context)
    assert "untested" in import_file("p006", REPO / "p-006/config/hardened.json").limitations[0].lower()
    assert "BLOCKED" in source.payload["source_status"]


def test_D04_p007_handoff_provenance_remains_source_owned():
    value = load(P007)
    imported = p007(value, None)
    assert imported["payload"]["handoff"]["p010"] == value["handoff"]["p010"]
    assert imported["payload"]["manifest_sha256"] == value["manifest_sha256"]
    with pytest.raises(Invalid):
        value["handoff"]["contract"] = "p007-handoff-v9"
        p007(value, None)


def test_D05_all_p007_result_statuses_and_runner_metadata():
    source = load(P007)
    result = p007(source, None)["payload"]
    assert result["control_status"] == source["control_status"]
    assert result["provenance"] == source["provenance"]
    for original, recorded in zip(source["results"], result["results"], strict=True):
        assert original["status"] == recorded["status"]
        assert original["runner"]["metadata"] == recorded["runner"]["metadata"]
        assert original["compatibility_hash"] == recorded["compatibility_hash"]


def synthetic_p007(root: Path, *, content: bytes = b'{"fixture":"review-only"}\n') -> tuple[dict, Path]:
    root.mkdir()
    original = load(P007)
    source_result = next(row for row in original["results"] if row["status"] == "FAIL")
    path = source_result["test_id"] + ".json"
    artifacts = [
        {
            "path": path,
            "media_type": "application/json",
            "size": len(content),
            "sha256": digest(content),
            "schema_version": "1.0",
        }
    ]
    (root / path).write_bytes(content)
    (root / "owner.json").write_bytes(canonical({"owner": "p007", "run_id": root.name}))
    manifest = {
        "schema_version": "1.0",
        "framework_version": "1.0.0",
        "owner": "p007",
        "run_id": root.name,
        "started_at": "2026-11-15T10:00:00Z",
        "ended_at": "2026-11-15T10:05:00Z",
        "duration_seconds": 300,
        "actor_label": "fixture",
        "repository": {"commit": "d" * 40},
        "plan_digest": "c" * 64,
        "target": {
            "schema_version": "1.0",
            "target_id": "demo-a-health",
            "version": "v1",
            "environment": "offline",
            "origin": "offline-fixture",
            "service_identity": "demo-service",
            "owner": "p007",
            "ownership_ref": "fixture",
            "instance_id": "fixture",
            "allowed_ips": ["127.0.0.1"],
            "operations": [{"schema_version": "1.0", "method": "GET", "path": "/fixture", "category": "api"}],
            "capabilities": [],
        },
        "authorization": [],
        "artifacts": artifacts,
        "results": [source_result],
        "source_hash": "a" * 64,
        "redaction": [],
        "limitations": ["Synthetic manifest for byte validation."],
        "reproduction": "Inspect synthetic byte fixtures.",
        "provenance": original["provenance"],
    }
    manifest_raw = canonical(manifest)
    (root / "manifest.json").write_bytes(manifest_raw)
    return (
        {
            **original,
            "run_id": root.name,
            "results": [source_result],
            "manifest_sha256": digest(manifest_raw),
            "handoff": {
                **original["handoff"],
                "p009": {"artifacts": artifacts, "manifest_ref": root.name + "/manifest.json"},
            },
        },
        root / path,
    )


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("../manifest.json", id="D06-parent"),
        pytest.param("/etc/passwd", id="D06-absolute"),
        pytest.param("folder//record.json", id="D06-noncanonical"),
    ],
)
def test_refuse_unsafe_artifact_paths(path):
    value = load(P007)
    value["handoff"]["p009"]["artifacts"][0]["path"] = path
    with pytest.raises(Invalid, match="Unsafe artifact path"):
        p007(value, None)


def test_D06_refuse_artifact_symlink(tmp_path):
    root = tmp_path / "run-fixture"
    value, artifact = synthetic_p007(root)
    artifact.rename(tmp_path / "target.json")
    artifact.symlink_to(tmp_path / "target.json")
    with pytest.raises(Invalid, match="Symlinks"):
        p007(value, root)


def test_D07_verify_selected_source_bytes(tmp_path):
    root = tmp_path / "run-fixture"
    value, artifact = synthetic_p007(root)
    result = p007(value, root)
    assert result["validation"] == "VERIFIED_BYTES"
    assert result["source_commit"] == "d" * 40
    assert result["artifacts"][0].declared_size == artifact.stat().st_size
    assert result["artifacts"][0].declared_sha256 == digest(artifact.read_bytes())


@pytest.mark.parametrize(
    "changed", [pytest.param(b"different length", id="E03-size"), pytest.param(None, id="E03-hash")]
)
def test_reject_changed_source_bytes(tmp_path, changed):
    root = tmp_path / "run-fixture"
    value, artifact = synthetic_p007(root)
    initial = artifact.read_bytes()
    artifact.write_bytes(changed if changed is not None else b"x" * len(initial))
    with pytest.raises(Invalid, match="artifact size or digest"):
        p007(value, root)


def test_E04_missing_source_bytes_are_unavailable(tmp_path):
    root = tmp_path / "run-fixture"
    value, artifact = synthetic_p007(root)
    artifact.unlink()
    result = p007(value, root)
    assert result["artifacts"][0].integrity == "UNAVAILABLE"
    assert result["validation"] == "REFERENCE_ONLY"


def test_D10_actual_omission_policy_and_metrics():
    raw = load(P008)["summary"]
    result = import_file("p008", P008).payload["summary"]
    assert result["metrics"] == raw["metrics"]
    assert result["results"] == raw["results"]
    assert len(result["results"]) == 38
    assert result["omission_policy"]["sealed_results_excluded"] == 10
    assert result["metrics"]["observations"] == 48


def test_D11_L03_evaluator_prompt_is_dropped():
    raw = load(P008)
    raw["summary"]["evaluator"]["prompt"] = "P010_SECRET_PROMPT"
    raw["summary"]["evaluator"]["judge_prompt"] = "P010_PII_JUDGE"
    clean = p008(raw)
    encoded = canonical(clean)
    assert b"P010_SECRET" not in encoded and b"P010_PII" not in encoded
    assert b'"prompt":' not in encoded and b'"judge_prompt":' not in encoded


@pytest.mark.parametrize(
    "field",
    [
        pytest.param("label_key", id="D11-label"),
        pytest.param("raw_output", id="D11-output"),
        pytest.param("sealed_results", id="D11-sealed"),
    ],
)
def test_sealed_or_unknown_sample_fields_rejected(field):
    raw = load(P008)
    raw["summary"]["results"][0][field] = "fixture"
    with pytest.raises(Invalid, match="sanitized row"):
        p008(raw)


def test_D12_p009_joins_exact_event_digest_and_tenant(tmp_path):
    handoff = load(P009)
    event = load(ROOT / "fixtures/p009-event.json")
    raw = (json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    handoff["objects"] = [{"sha256": digest(raw), "size": len(raw), "kind": "event"}]
    events = tmp_path / "events.json"
    events.write_bytes(canonical([event]))
    result = p009(handoff, events)
    assert result["payload"]["event_references"][0]["trace_id"] == event["trace_id"]
    assert result["payload"]["event_references"][0]["event_time"] == event["event_time"]
    event["tenant_ref"] = "tenant-b"
    events.write_bytes(canonical([event]))
    with pytest.raises(Invalid, match="digest, tenant or redaction"):
        p009(handoff, events)


def p009_event_files(folder: Path, **changes) -> tuple[Path, Path]:
    handoff = load(P009)
    event = {**load(ROOT / "fixtures/p009-event.json"), **changes}
    raw = (json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    handoff["objects"] = [{"sha256": digest(raw), "size": len(raw), "kind": "event"}]
    manifest, events = folder / "handoff.json", folder / "events.json"
    manifest.write_bytes(canonical(handoff))
    events.write_bytes(canonical([event]))
    return manifest, events
