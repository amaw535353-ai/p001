#!/usr/bin/env python3
"""Record real exit statuses, JUnit counts and code hashes; never turn skips into passes."""

import importlib.metadata
import json
from pathlib import Path
import subprocess
import shutil
import sys
import time
import xml.etree.ElementTree as ET

from p004.cli import git_commit
from p004.policy import utc_now
from p004.reporting import json_bytes, verify_run
from p004.safety import digest, text

ROOT = Path(__file__).resolve().parents[1]
out = ROOT / "evidence" / ("engineering-" + str(time.time_ns()))
out.mkdir(parents=True, mode=0o700)
py = str(ROOT / ".venv/bin/python")
commands = [
    (
        ROOT,
        [
            py,
            "-m",
            "pytest",
            "tests",
            "--junitxml=" + str(out / "pytest.xml"),
            "--basetemp=" + str(out / "test-state"),
        ],
    ),
    (ROOT, [str(ROOT / ".venv/bin/ruff"), "check", "src", "tests", "scripts"]),
    (ROOT, [str(ROOT / ".venv/bin/ruff"), "format", "--check", "src", "tests", "scripts"]),
    (ROOT, [str(ROOT / ".venv/bin/mypy"), "src/p004"]),
    (ROOT, [py, "scripts/build-schemas.py", "--check"]),
    (ROOT, [py, "-m", "pip", "check"]),
    (ROOT.parent, ["make", "unit", "static"]),
]
results = []
for cwd, cmd in commands:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=240)
    results.append(
        dict(
            command=cmd,
            cwd=str(cwd),
            exit_code=r.returncode,
            status="PASS" if r.returncode == 0 else "FAIL",
            excerpt=text(r.stdout + r.stderr, 12000),
        )
    )
    print(json.dumps({k: v for k, v in results[-1].items() if k != "excerpt"}), flush=True)
cases = ET.parse(out / "pytest.xml").getroot().findall(".//testcase")
counts = {
    "failed": sum(c.find("failure") is not None for c in cases),
    "errors": sum(c.find("error") is not None for c in cases),
    "skipped": sum(c.find("skipped") is not None for c in cases),
}
counts["passed"] = len(cases) - sum(counts.values())
paths = [
    p
    for base in ("src", "tests", "schemas", "config", "fixtures", "scripts", "docs")
    for p in (ROOT / base).rglob("*")
    if p.is_file() and "__pycache__" not in p.parts
]
paths += [
    ROOT / name
    for name in ("pyproject.toml", "requirements.in", "requirements.lock", "Makefile", "README.md")
]
files = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in sorted(paths)}
result = dict(
    schema_version="p004-engineering-v1",
    timestamp_utc=utc_now(),
    base_commit=git_commit(),
    code_manifest=files,
    code_sha256=digest(files),
    commands=results,
    test_counts=counts,
    dependency_versions={
        name: importlib.metadata.version(name)
        for name in ("pydantic", "PyYAML", "jsonschema", "pytest", "hypothesis", "ruff", "mypy")
    },
    result="PASS" if counts["passed"] >= 35 and all(r["exit_code"] == 0 for r in results) else "FAIL",
    optional={
        "Playwright": "BLOCKED independent network containment unavailable",
        "ZAP": "NOT TESTED live; passive contract tested",
        "Onyx": "NOT TESTED",
        "OpenHands": "NOT TESTED",
        "Kubernetes": "BLOCKED host cgroups and no read-only namespace identity",
    },
    learner_gates="G1–G4 NOT DEMONSTRATED",
)
live_runs = list(out.glob("test-state/test_real_observe_cli*/out"))
if live_runs:
    shutil.copytree(live_runs[0], out / "local-http-run")
    result["local_http_evidence"] = dict(
        path="local-http-run", verification=verify_run(out / "local-http-run")
    )
(out / "manifest.json").write_bytes(json_bytes(result))
print(json.dumps(dict(result=result["result"], counts=counts, evidence=str(out.relative_to(ROOT)))))
sys.exit(0 if result["result"] == "PASS" else 1)
