"""Readiness and repository-scope checks used by the delivery workflow."""

import os
import socket
import subprocess

import pytest

from p010.demo import ENGAGEMENT, FINDING, REPORT, run
from p010.models import RECORDS
from p010.safety import REPO, ROOT, Invalid, parse
from p010.store import Workspace

BASE = "f6f975f3c570631098e82d8b8690b636a84ee9ee"


def git(*args):
    return subprocess.check_output(["git", "-C", str(REPO), *args], text=True).strip()


def test_A01_approved_base_is_an_ancestor():
    subprocess.run(["git", "-C", str(REPO), "merge-base", "--is-ancestor", BASE, "HEAD"], check=True)
    assert git("show", "-s", "--format=%P", BASE).split()[1] == "6cbde5ef20bbb2a335bce4b360001170528f300e"


def test_A02_A03_sibling_tree_matches_approved_base():
    scoped_change = ["p-010/", ".github/workflows/p010-offline.yml"]
    try:
        current_base = git("merge-base", "origin/p001-initial", "HEAD")
    except subprocess.CalledProcessError:
        current_base = BASE
    changed = (
        git("diff", current_base, "--name-only").splitlines()
        + git("ls-files", "--others", "--exclude-standard").splitlines()
    )
    assert all(path.startswith(scoped_change[0]) or path == scoped_change[1] for path in changed)
    assert git("rev-parse", current_base + ":p-009") == git("rev-parse", "HEAD:p-009")


@pytest.mark.parametrize(
    "file",
    [
        "reports/report.json",
        ".runtime/private.sqlite3",
        ".env",
        ".venv/bin/python",
        "evidence/raw.json",
        "generated/private.md",
    ],
)
def test_A06_runtime_data_is_ignored(file):
    assert git("check-ignore", "p-010/" + file) == "p-010/" + file


def test_A09_missing_source_is_explicit(tmp_path):
    from p010.sources import import_file

    with pytest.raises(Invalid, match="unavailable"):
        import_file("p009", tmp_path / "missing.json")


@pytest.mark.parametrize("kind", sorted(RECORDS))
def test_B02_canonical_models_forbid_additional_properties(kind):
    assert RECORDS[kind].model_json_schema()["additionalProperties"] is False


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":Infinity}', b'{"a":NaN}', b"[" * 34 + b"]" * 34])
def test_bounded_json_rejects_ambiguous_input(raw):
    with pytest.raises(Invalid):
        parse(raw)


def test_default_offline_guard_blocks_sockets_and_dns():
    env = {**os.environ, "PYTHONPATH": str(ROOT / "tests/offline_guard")}
    subprocess.run(
        [
            os.path.abspath(os.sys.executable),
            "-c",
            "import pytest, socket\n"
            "with pytest.raises(AssertionError): socket.socket(socket.AF_INET)\n"
            "with pytest.raises(AssertionError): socket.getaddrinfo('example.invalid', 443)",
        ],
        env=env,
        check=True,
    )
    if socket.socket.__name__ == "OfflineSocket":
        with pytest.raises(AssertionError):
            socket.socket(socket.AF_INET)


def test_workspace_refuses_symlinks_unowned_or_overbroad_modes(tmp_path):
    stranger = tmp_path / "stranger"
    stranger.mkdir(mode=0o700)
    (stranger / "existing").write_text("preserve")
    with pytest.raises(Invalid, match="unowned"):
        Workspace(stranger).init()
    alias = tmp_path / "alias"
    alias.symlink_to(stranger, target_is_directory=True)
    with pytest.raises(Invalid, match="Symlinks"):
        Workspace(alias)
    permissive = tmp_path / "permissive"
    permissive.mkdir()
    permissive.chmod(0o755)
    with pytest.raises(Invalid, match="private"):
        Workspace(permissive).init()
    assert (stranger / "existing").read_text() == "preserve"


def test_demo_repeats_exact_bytes(tmp_path):
    first = run(Workspace(tmp_path / "one"), p008=ROOT / "fixtures/p008-export.json")
    second = run(Workspace(tmp_path / "two"), p008=ROOT / "fixtures/p008-export.json")
    assert first["manifest_sha256"] == second["manifest_sha256"]
    assert first["report_sha256"] == second["report_sha256"]
    assert first["draft_approval_rejected"] and first["canaries_removed"]
    assert first["report_status"] == "REVIEW_READY"
    assert first["finding"] == FINDING and first["engagement"] == ENGAGEMENT
    assert first["package"].endswith(REPORT + "-v3")
