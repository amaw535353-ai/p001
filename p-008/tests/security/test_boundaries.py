import json
import subprocess
import sys

import pytest

from p008.adapters import HERE, environment, run_process
from p008.cli import main
from p008.models import Limits
from p008.pipeline import execute, make_plan
from p008.safety import Invalid, canonical, load, read_bytes, safe_path, write_new


def test_path_traversal_absolute_and_parent_rejected(tmp_path):
    for part in ("../foreign", "/tmp/foreign", "nested/../../foreign"):
        with pytest.raises(Invalid):
            safe_path(tmp_path, part)


def test_symlink_read_and_write_refused(tmp_path):
    real = tmp_path / "real.json"
    real.write_text("{}")
    link = tmp_path / "alias.json"
    link.symlink_to(real)
    with pytest.raises(Invalid, match="SYMLINK"):
        load(link)
    with pytest.raises(Invalid, match="SYMLINK"):
        write_new(link, b"{}")
    assert real.read_text() == "{}"


def test_yaml_object_constructor_and_alias_refused(tmp_path):
    path = tmp_path / "untrusted.yaml"
    path.write_text("!!python/object/apply:os.system ['echo should-never-run']")
    with pytest.raises(Invalid):
        load(path)
    path.write_text("a: &a [1,2]\nb: *a\n")
    with pytest.raises(Invalid, match="ALIASES"):
        load(path)


def test_json_duplicate_keys_nonfinite_and_bad_encoding(tmp_path):
    path = tmp_path / "untrusted.json"
    for content in (b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff"):
        path.write_bytes(content)
        with pytest.raises((Invalid, UnicodeError)):
            load(path)


def test_oversized_and_unsupported_archive_refused(tmp_path):
    path = tmp_path / "large.json"
    with path.open("wb") as file:
        file.truncate(4194305)
    with pytest.raises(Invalid, match="FILE-LIMIT"):
        read_bytes(path)
    archive = tmp_path / "untrusted.zip"
    archive.write_bytes(b"not-extracted")
    with pytest.raises(Invalid, match="ONLY-JSON"):
        load(archive)


def test_provider_keys_not_in_worker_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional-never-real-test-key")
    monkeypatch.setenv("PYTHONSTARTUP", "/untrusted.py")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/untrusted.cjs")
    env = environment(tmp_path)
    assert "OPENAI_API_KEY" not in env and "PYTHONSTARTUP" not in env
    assert str(HERE / "network_guard.cjs") in env["NODE_OPTIONS"]


def test_python_network_and_dns_disabled_in_actual_child(tmp_path):
    command = [sys.executable, "-c", "import socket; socket.getaddrinfo('example.invalid',443)"]
    result = subprocess.run(command, env=environment(tmp_path), capture_output=True, timeout=10)
    assert result.returncode != 0 and b"P008-OFFLINE-NETWORK-DISABLED" in result.stderr


def test_actual_subprocess_timeout_kills_process_group(tmp_path):
    limits = Limits(timeout_seconds=1, cpu_seconds=2)
    result = run_process([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, limits)
    assert result["status"] == "BLOCKED" and result["error_class"] == "timeout"


def test_actual_output_file_limit(tmp_path):
    result = run_process(
        [sys.executable, "-c", "import os; os.write(1,b'x'*5000000)"], tmp_path, Limits(output_bytes=1024)
    )
    assert (tmp_path / "stdout.txt").stat().st_size <= 1024
    assert result["status"] == "BLOCKED" and result["error_class"] == "resource"


def test_baseline_cleanup_protected_and_confirmation_required(registry, run):
    with pytest.raises(Invalid, match="CONFIRMATION"):
        registry.cleanup(run.run_id, "wrong")
    with pytest.raises(Invalid, match="PROTECTED-BASELINE"):
        registry.cleanup(run.run_id, "p008-owned-artifacts")
    disposable = execute(registry, run.plan.plan_id)
    registry.cleanup(disposable.run_id, "p008-owned-artifacts")
    assert not registry.path("runs", disposable.run_id).exists()
    assert registry.path("runs", run.run_id).is_dir()


def test_cli_invalid_run_and_repetition_are_explicit_errors(registry, capsys):
    assert main(["--root", str(registry.root), "eval", "--repetitions", "6"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"
    assert main(["--root", str(registry.root), "report", "--run", "../../foreign"]) == 2


def test_untrusted_prompt_remains_data_not_code(bundle, tmp_path):
    from p008.respond import respond

    marker = tmp_path / "must-not-exist"
    text = "__import__('pathlib').Path(" + repr(str(marker)) + ").write_text('executed')"
    sample = bundle.samples[0].input.model_copy(update={"prompt": text})
    observation = respond(sample)
    assert observation.decision == "ALLOW" and not marker.exists()


def test_native_assertion_exception_is_blocked_not_pass(registry, monkeypatch):
    import p008.adapters as adapters
    from p008.respond import respond
    from p008.models import VisibleInput

    original_capability = adapters.capability
    monkeypatch.setattr(
        adapters,
        "capability",
        lambda tool: (
            original_capability(tool)
            if tool == "offline"
            else {"tool": tool, "version": "0.125.1", "status": "PASS"}
        ),
    )

    def broken_assertion(command, folder, limits):
        payload = load(folder / "tool-input.json")
        rows = [
            {
                "testCase": {"description": r["id"] + "__r0"},
                "success": False,
                "error": "Custom function threw error: synthetic assertion syntax failure",
                "response": {"output": canonical(respond(VisibleInput.model_validate(r["input"]))).decode()},
                "gradingResult": {"pass": False},
            }
            for r in payload["samples"]
        ]
        write_new(folder / "tool-output.json", canonical({"results": {"results": rows}}))
        return {"status": "tool-error", "exit_code": 100, "error_class": "provider"}

    monkeypatch.setattr(adapters, "run_process", broken_assertion)
    result = execute(registry, make_plan(registry, tool="promptfoo", family="authorization").plan_id)
    assert result.status == "BLOCKED" and result.metrics.blocked == 8 and result.metrics.executed == 0
