import json
import os
import subprocess
import sys

import pytest

from p003 import demo
from p003.util import ROOT


def cli(store, *args):
    return subprocess.run(
        [sys.executable, "-m", "p003.cli", "--store", str(store), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )


def test_real_cli_workflow_and_exit_statuses(tmp_path):
    store = tmp_path / "cli-store"
    spec = demo.engagement()
    commands = [
        (0, ["demo", "init", "--seed", "42"]),
        (0, ["engagement", "list", "--actor", "demo-a-assessor"]),
        (0, ["engagement", "show", "--id", "ENG-DEMO-A", "--actor", "demo-a-assessor"]),
        (3, ["scope", "evaluate", "--request", "examples/check-allow.json"]),
        (
            0,
            [
                "engagement",
                "submit",
                "--id",
                "ENG-DEMO-A",
                "--actor",
                "demo-a-requestor",
                "--version",
                "1",
                "--at",
                "2026-11-15T08:10:00Z",
                "--reason",
                "Synthetic review request",
            ],
        ),
        (
            0,
            [
                "engagement",
                "approve",
                "--id",
                "ENG-DEMO-A",
                "--actor",
                "demo-a-reviewer",
                "--version",
                "1",
                "--at",
                "2026-11-15T08:20:00Z",
                "--reason",
                "Explicit simulated training approval",
                "--simulate-review",
                "--evidence-ref",
                "training-review-a-v1",
                "--scope-digest",
                spec.content_digest,
            ],
        ),
        (
            0,
            [
                "engagement",
                "activate",
                "--id",
                "ENG-DEMO-A",
                "--actor",
                "demo-a-owner",
                "--version",
                "1",
                "--at",
                demo.START,
                "--reason",
                "Synthetic window opened",
            ],
        ),
        (0, ["scope", "evaluate", "--request", "examples/check-allow.json"]),
        (3, ["scope", "evaluate", "--request", "examples/check-deny-unknown-path.json"]),
        (0, ["evidence", "manifest", "--id", "ENG-DEMO-A", "--actor", "demo-a-reviewer"]),
        (
            0,
            [
                "redmine",
                "sync",
                "--id",
                "ENG-DEMO-A",
                "--actor",
                "demo-a-reviewer",
                "--target",
                "lab",
                "--dry-run",
            ],
        ),
        (
            0,
            [
                "scope",
                "diff",
                "--old",
                "examples/engagement-draft-a.json",
                "--new",
                "examples/scope-extension-v2.json",
            ],
        ),
        (2, ["engagement", "show", "--id", "ENG-DEMO-B", "--actor", "demo-a-assessor"]),
        (0, ["reset", "--confirm", "p003-local"]),
        (0, ["demo", "init", "--seed", "42"]),
    ]
    # Evaluate pending approval via pure engine elsewhere; avoid backdating the ledger here.
    commands.pop(3)
    for expected, args in commands:
        result = cli(store, *args)
        assert result.returncode == expected, (args, result.stdout, result.stderr)
        assert json.loads(result.stdout)["notice"] == spec.notice
    result = cli(store, "engagement", "show", "--id", "ENG-DEMO-A", "--actor", "demo-a-assessor")
    assert json.loads(result.stdout)["result"]["status"] == "DRAFT"


@pytest.mark.parametrize(
    "commands",
    [
        [],
        ["engagement"],
        ["scope", "evaluate"],
        ["export", "markdown"],
        ["redmine", "sync", "--target", "public"],
    ],
)
def test_help_and_invalid_cli(tmp_path, commands):
    result = cli(tmp_path / "absent", *commands)
    assert result.returncode == 2
    assert "usage:" in result.stderr


@pytest.mark.parametrize(
    "commands",
    [
        ["--help"],
        ["scope", "evaluate", "--help"],
        ["engagement", "approve", "--help"],
        ["redmine", "sync", "--help"],
    ],
)
def test_help_text_executed(tmp_path, commands):
    result = cli(tmp_path / "absent", *commands)
    assert result.returncode == 0 and "usage:" in result.stdout


def test_cli_does_not_echo_sensitive_validation_errors(tmp_path):
    store = tmp_path / "store"
    assert cli(store, "demo", "init").returncode == 0
    path = tmp_path / "bad.json"
    secret = "ghp_" + "b" * 36
    path.write_text(json.dumps({"unexpected": secret}))
    result = cli(store, "engagement", "validate", "--file", str(path))
    assert result.returncode == 2 and secret not in result.stdout + result.stderr
