import sys
import pytest
from p007.catalog import plan, verify_plan
from p007.cli import main
from p007.models import Limits
from p007.runners import environment, execute
from p007.safety import Invalid, read_bytes, safe_path, write_new


def test_traversal_symlink_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("synthetic")
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(Invalid, match="TRAVERSAL"):
        safe_path(tmp_path, "../outside")
    with pytest.raises(Invalid, match="SYMLINK"):
        read_bytes(tmp_path / "link")


def test_atomic_write_collision(tmp_path):
    path = tmp_path / "artifact.json"
    write_new(path, b"original")
    with pytest.raises(FileExistsError):
        write_new(path, b"modified")
    assert path.read_bytes() == b"original"


def test_payload_argument_not_shell(tmp_path):
    payload = "$(touch forbidden); `touch forbidden`"
    code, out, error = execute(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", payload], tmp_path, Limits()
    )
    assert code == 0 and payload.encode() in out and error == "none" and not (tmp_path / "forbidden").exists()


def test_subprocess_timeout_bounded(tmp_path):
    code, _, error = execute(
        [sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, Limits(timeout_seconds=1)
    )
    assert code is None and error == "timeout"


def test_child_credentials_excluded(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-do-not-copy")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "synthetic-do-not-copy")
    assert "OPENAI_API_KEY" not in environment(tmp_path) and "AWS_SESSION_TOKEN" not in environment(tmp_path)


def test_mutated_plan_refused():
    value = plan()
    value.fixtures["policy"]["isolation"] = False
    with pytest.raises(Invalid, match="PLAN-INTEGRITY"):
        verify_plan(value)


def test_network_scope_absent_blocks_with_nonzero(capsys):
    assert main(["run", "--target", "local-fixture", "--profile", "playwright"]) == 2
    assert '"BLOCKED"' in capsys.readouterr().out


def test_cleanup_needs_explicit_confirmation(capsys):
    assert main(["cleanup", "--run", "run-synthetic"]) == 2
    assert "CLEANUP-REQUIRES" in capsys.readouterr().out
