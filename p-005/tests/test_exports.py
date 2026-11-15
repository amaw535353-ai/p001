from copy import deepcopy
import json
import os
import subprocess

import pytest

from p005.adapters.status import statuses, refuse_native
from p005.catalogs import atlas
from p005.evidence.safety import DATA, PROJECT, Invalid, digest, load, redact, read
from p005.export.diagrams import render
from p005.export.reports import md
from p005.export.run import export_run, initialize, manifest, verify_manifest
from p005.modeling.review import decide, records
from p005.modeling.rule_engine import analyze
from test_model import regraph


def test_diagram_markdown_injection_is_inert(model):
    data = model.model_dump()
    data["nodes"][0]["label"] = (
        '"]\nclick bad "javascript:alert(1)"\n%%{init: {}}%%<script>alert(1)</script>![](https://evil.example)'
    )
    m = regraph(data)
    for fmt in ("mermaid", "dot"):
        output = render(m, fmt)
        assert "<script>" not in output and "javascript:" not in output and "%%{" not in output
        assert "\nclick" not in output and "https://" not in output
    assert "<script>" not in md("<script>[x](javascript:1)`x`|")
    assert "[x]" not in md("[x](javascript:1)")


def test_redaction_across_all_public_artifacts(model, tmp_path):
    data = model.model_dump()
    markers = [
        "sk-syntheticCANARY0123456789",
        "password=canary-password-123",
        "Bearer synthetic-token-123456789",
        "fixture.person@example.test",
    ]
    data["nodes"][0]["label"] = " ".join(markers)
    data = redact(data)
    m = regraph(data)
    run = tmp_path / "redacted"
    export_run(run, m, analyze(m))
    for file in run.rglob("*"):
        if file.is_file():
            text = file.read_text()
            assert not any(marker in text for marker in markers)
    assert verify_manifest(run)["status"] == "PASS"
    assert redact({"api_key": "synthetic-canary"}) == {"api_key": "REDACTED"}


def test_catalog_actual_source_checksum_and_ids():
    result = atlas.validate(PROJECT / "catalogs/ATLAS-pinned.yaml")
    assert result == atlas.index()
    assert result["content_version"] == "2026.10" and len(result["techniques"]) == 221
    atlas.validate_technique("AML.T0051")
    with pytest.raises(Invalid, match="UNVERIFIED"):
        atlas.validate_technique("AML.T9999")


def test_catalog_source_version_format_checksum_fail_closed(tmp_path):
    path = tmp_path / "catalog.yaml"
    original = read(PROJECT / "catalogs/ATLAS-pinned.yaml")
    path.write_bytes(original + b"\n# altered\n")
    with pytest.raises(Invalid, match="CHECKSUM"):
        atlas.validate(path)
    pin = deepcopy(load(DATA / "atlas-pin.json"))
    path.write_bytes(original)
    pin["content_version"] = "1900.01"
    with pytest.raises(Invalid, match="VERSION"):
        atlas.validate(path, pin)
    pin["content_version"] = "2026.10"
    pin["format_version"] = "9.0.0"
    with pytest.raises(Invalid, match="VERSION"):
        atlas.validate(path, pin)


def test_catalog_update_is_local_candidate_not_activation(tmp_path):
    out = tmp_path / "candidate-catalog.json"
    result = atlas.update_local(
        PROJECT / "catalogs/ATLAS-pinned.yaml", PROJECT / "catalogs/ATLAS-pin.json", out
    )
    assert result["status"] == "VALIDATED_LOCAL_CANDIDATE" and not result["activated"]
    assert load(out)["index"] == atlas.index()


def test_atlas_mapping_is_not_auto_confirmation(model):
    result = atlas.mapping(analyze(model)["threats"])
    assert {r["status"] for r in result["mappings"]} <= {"CANDIDATE_REVIEW", "UNMAPPED"}
    assert any(r["status"] == "CANDIDATE_REVIEW" for r in result["mappings"])
    assert any(r["status"] == "UNMAPPED" for r in result["mappings"])


def test_absent_adapters_never_verified():
    rows = statuses()
    assert len(rows) == 3
    assert all(r["verification_status"] == "BLOCKED" and not r["executed"] for r in rows)
    assert all(not r["tested_roundtrip"] and r["output_digest"] is None for r in rows)
    with pytest.raises(Invalid, match="no Python executed"):
        refuse_native()


def test_imported_python_not_run(tmp_path, py):
    sentinel = tmp_path / "executed"
    malicious = tmp_path / "untrusted.py"
    malicious.write_text(f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')")
    child = subprocess.run(
        [
            py,
            "-m",
            "p005",
            "model",
            "build",
            "--input",
            str(malicious),
            "--out",
            str(tmp_path / "untrusted-run"),
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == 2 and not sentinel.exists()


def test_manifest_tamper_and_new_files_detected(model, tmp_path):
    run = tmp_path / "manifest"
    export_run(run, model, analyze(model))
    assert verify_manifest(run)["status"] == "PASS"
    (run / "threats.json").write_text("[]")
    with pytest.raises(Invalid, match="INTEGRITY"):
        verify_manifest(run)
    with pytest.raises(Invalid, match="DERIVED-ARTIFACT"):
        manifest(run)


def test_atomic_output_does_not_truncate_hardlinked_file(tmp_path):
    from p005.evidence.safety import write

    source, destination = tmp_path / "source.txt", tmp_path / "destination.txt"
    source.write_text("Preserve user data")
    os.link(source, destination)
    write(destination, b"Owned output")
    assert source.read_text() == "Preserve user data"
    assert destination.read_bytes() == b"Owned output"


def test_run_symlinks_and_unowned_output_fail(model, tmp_path):
    existing = tmp_path / "unowned"
    existing.mkdir()
    (existing / "keep.txt").write_text("user data")
    with pytest.raises(Invalid):
        initialize(existing, model)
    assert (existing / "keep.txt").read_text() == "user data"
    run = tmp_path / "owned"
    export_run(run, model, analyze(model))
    (run / "bad-link").symlink_to("/tmp")
    with pytest.raises(Invalid, match="SYMLINK"):
        manifest(run)


def test_human_editorial_workflow_is_separate_and_digest_bound(model, tmp_path):
    run = tmp_path / "review"
    result = analyze(model)
    export_run(run, model, result)
    assert records(run) == []
    tid = result["threats"][0]["threat_id"]
    decision = decide(
        run,
        model,
        result,
        tid,
        "ACCEPTED_FOR_TESTING",
        "synthetic-reviewer",
        "Candidate retained for independent design review",
        "2026-11-15T01:00:00Z",
        "HIGH",
    )
    assert decision["synthetic_editorial_only"] and not decision["authenticated_identity"]
    assert records(run)[0]["priority_override"] == "HIGH"
    assert load(run / "threats.json")[0]["applicability"] == "PROPOSED"
    data = model.model_dump()
    data["model_version"] = 2
    changed = regraph(data)
    with pytest.raises(Invalid, match="STALE-REVIEW"):
        decide(
            run,
            changed,
            analyze(changed),
            tid,
            "REJECTED_WITH_REASON",
            "reviewer",
            "Changed architecture must be reviewed",
            "2026-11-15T02:00:00Z",
        )


def test_offline_cli_end_to_end_zero_egress(tmp_path, py):
    baseline, changed = tmp_path / "baseline", tmp_path / "changed"
    audit = tmp_path / "egress-attempts.txt"
    env = dict(os.environ, PYTHONPATH=str(PROJECT / "tests/no-network"), P005_EGRESS_AUDIT=str(audit))

    def call(*args):
        child = subprocess.run(
            [py, "-m", "p005", *map(str, args)], env=env, capture_output=True, text=True, timeout=120
        )
        assert child.returncode == 0, child.stderr
        return json.loads(child.stdout)

    # Prove the guard is active, then clear only its own synthetic probe record.
    probe = subprocess.run(
        [py, "-c", "import socket; socket.getaddrinfo('invalid.example',443)"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert probe.returncode != 0 and audit.read_text() == "NETWORK_ATTEMPT\n"
    audit.unlink()
    call("model", "build", "--input", PROJECT / "fixtures/baseline/architecture.yaml", "--out", baseline)
    assert call("model", "validate", "--input", baseline / "model.json")["status"] == "PASS"
    assert call("analyze", "--model", baseline / "model.json", "--out", baseline)["threats"] > 0
    call(
        "graph",
        "render",
        "--model",
        baseline / "model.json",
        "--format",
        "mermaid",
        "--out",
        baseline / "diagrams/architecture.mmd",
    )
    call("report", "--run", baseline, "--format", "markdown")
    call("tests", "plan", "--run", baseline, "--out", baseline / "verification-plan.json")
    call(
        "model",
        "build",
        "--input",
        PROJECT / "fixtures/variants/tenant-boundary-change.yaml",
        "--out",
        changed,
    )
    call("analyze", "--model", changed / "model.json", "--out", changed)
    call(
        "diff",
        "--before",
        baseline / "model.json",
        "--after",
        changed / "model.json",
        "--out",
        tmp_path / "model-diff.json",
    )
    call("evidence", "manifest", "--run", baseline)
    assert call("evidence", "verify", "--run", baseline)["status"] == "PASS"
    assert not audit.exists(), "Even a caught network attempt invalidates zero-egress claim"
    manifest_data = load(baseline / "run-manifest.json")
    assert manifest_data["sanitizer"]["status"] == "PASS"
    assert digest(read(baseline / "model.json")) == manifest_data["files"]["model.json"]
    assert "no vulnerabilities confirmed" in (baseline / "reports/threat-model.md").read_text()
    assert not (baseline / "adapters").exists()


def test_cli_fallback_and_malformed_no_silent_fallback(tmp_path, py):
    child = subprocess.run(
        [
            py,
            "-m",
            "p005",
            "model",
            "build",
            "--input",
            str(tmp_path / "missing.json"),
            "--source",
            "p004",
            "--fallback-fixture",
            str(PROJECT / "fixtures/baseline/architecture.yaml"),
            "--out",
            str(tmp_path / "fallback"),
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == 0
    assert load(tmp_path / "fallback/model.json")["integrations"][0]["status"] == "NOT_TESTED"
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version":"99"}')
    child = subprocess.run(
        [
            py,
            "-m",
            "p005",
            "model",
            "build",
            "--input",
            str(bad),
            "--source",
            "p004",
            "--fallback-fixture",
            str(PROJECT / "fixtures/baseline/architecture.yaml"),
            "--out",
            str(tmp_path / "bad-fallback"),
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == 2 and not (tmp_path / "bad-fallback").exists()
