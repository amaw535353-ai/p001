"""Execute real checks and preserve exit statuses, current JUnit counts and hashes."""

import importlib.metadata
import json
import platform
import subprocess
import sys
from time import time_ns
from uuid import uuid4
import xml.etree.ElementTree as ET

from p003 import NOTICE
from p003.frameworks import sources
from p003.models import Artifact, sealed
from p003.util import ROOT, digest, now, safe


def code_files():
    paths = [
        p
        for base in ("src", "tests", "scripts", "schemas", "examples")
        for p in (ROOT / base).rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    ]
    paths += [ROOT / n for n in ("pyproject.toml", "requirements.in", "requirements.lock")]
    return {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in sorted(paths)}


def versions():
    return {
        "python": platform.python_version(),
        **{
            name: importlib.metadata.version(name)
            for name in (
                "p003-engagement-governance",
                "pydantic",
                "PyYAML",
                "jsonschema",
                "regex",
                "pytest",
                "hypothesis",
                "ruff",
                "mypy",
            )
        },
    }


def verify():
    run_dir = ROOT / "evidence" / ("engineering-" + str(time_ns()))
    run_dir.mkdir(parents=True, mode=0o700)
    junit = run_dir / "pytest.xml"
    py = str(ROOT / ".venv/bin/python")
    commands = [
        (ROOT, [py, "-m", "pytest", "tests", "--junitxml=" + str(junit)]),
        (ROOT, [str(ROOT / ".venv/bin/ruff"), "check", "src", "tests"]),
        (ROOT, [str(ROOT / ".venv/bin/ruff"), "format", "--check", "src", "tests"]),
        (ROOT, [str(ROOT / ".venv/bin/mypy"), "src/p003"]),
        (ROOT, [py, "-m", "pip", "check"]),
        (ROOT.parent, ["make", "unit", "static"]),
    ]
    rows = []
    for cwd, cmd in commands:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=180)
        excerpt = (result.stdout + result.stderr)[-6000:]
        try:
            safe(excerpt)
        except ValueError:
            excerpt = "Content omitted by sanitization gate."
        rows.append(
            {
                "working_directory": str(cwd),
                "command": cmd,
                "exit_code": result.returncode,
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "excerpt": excerpt,
            }
        )
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    if junit.exists():
        suites = ET.parse(junit).getroot()
        cases = suites.findall(".//testcase")
        counts["failed"] = sum(x.find("failure") is not None for x in cases)
        counts["errors"] = sum(x.find("error") is not None for x in cases)
        counts["skipped"] = sum(x.find("skipped") is not None for x in cases)
        counts["passed"] = len(cases) - sum(counts.values())
    if not counts["passed"]:
        rows[0]["status"] = "FAIL"
    files = code_files()
    git = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report = sealed(
        Artifact,
        id=str(uuid4()),
        source="p003 actual engineering command execution",
        author="codex-builder",
        created_at=now(),
    ).model_dump(mode="json")
    report.update(
        kind="engineering-verification",
        base_commit=git,
        code_manifest=files,
        code_sha256=digest(files),
        fixture_sha256=digest((ROOT / "examples/engagement-draft-a.json").read_bytes()),
        versions=versions(),
        framework_sources=sources(),
        commands=rows,
        test_counts=counts,
        result="PASS" if all(x["status"] == "PASS" for x in rows) else "FAIL",
        optional_integrations={
            "Redmine live": "NOT TESTED",
            "P-001 cluster": "BLOCKED by host cgroup delegation",
            "OSCAL AP conformance": "NOT IMPLEMENTED; draft rejected as expected",
        },
        authority="NOT VERIFIED",
        learner_gates="G1–G4 NOT DEMONSTRATED",
    )
    report["content_digest"] = digest({k: v for k, v in report.items() if k != "content_digest"})
    safe(report)
    dest = run_dir / "manifest.json"
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return {
        "notice": NOTICE,
        "result": report["result"],
        "test_counts": counts,
        "commands_passed": sum(x["status"] == "PASS" for x in rows),
        "commands_total": len(rows),
        "evidence": str(dest.relative_to(ROOT)),
        "sha256": digest(dest.read_bytes()),
        "exit_code": 0 if report["result"] == "PASS" else 1,
    }


if __name__ == "__main__":
    result = verify()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(result["exit_code"])
