#!/usr/bin/env python3
"""Run and record actual engineering checks. No skipped test is counted as PASS."""

from datetime import datetime, timezone
import importlib.metadata
from pathlib import Path
import platform
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from p005.evidence.safety import PROJECT, REPO, canonical, digest, redact, write

out = PROJECT / "evidence/engineering" / ("run-" + str(time.time_ns()))
out.mkdir(parents=True, exist_ok=True)
python = sys.executable
binpath = Path(python).parent
commands = [
    (
        PROJECT,
        [
            python,
            "-m",
            "pytest",
            "tests",
            "--basetemp=" + str(out / "test-state"),
            "--junitxml=" + str(out / "pytest.xml"),
        ],
    ),
    (PROJECT, [str(binpath / "ruff"), "check", "src", "tests", "scripts"]),
    (PROJECT, [str(binpath / "ruff"), "format", "--check", "src", "tests", "scripts"]),
    (PROJECT, [str(binpath / "mypy"), "src/p005"]),
    (PROJECT, [python, "scripts/build-schemas.py", "--check"]),
    (PROJECT, [python, "-m", "pip", "check"]),
    (PROJECT, [python, "scripts/check-sources.py"]),
    (PROJECT, ["make", "demo-offline", "demo-integrations"]),
    (REPO, ["make", "unit", "static"]),
]
results = []
for index, (cwd, command) in enumerate(commands):
    started = datetime.now(timezone.utc).isoformat()
    try:
        run = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=240)
        code = run.returncode
        log = redact(run.stdout + run.stderr)
    except subprocess.TimeoutExpired:
        code, log = 124, "TIMEOUT: engineering check did not complete"
    name = f"command-{index + 1:02}.log"
    write(out / name, log.encode())
    item = dict(
        command=command,
        cwd=str(cwd),
        started_utc=started,
        exit_code=code,
        status="PASS" if code == 0 else "FAIL",
        log=name,
        log_sha256=digest(log.encode()),
    )
    results.append(item)
    print(f"{item['status']} {command}", flush=True)
cases = ET.parse(out / "pytest.xml").getroot().findall(".//testcase") if (out / "pytest.xml").exists() else []
counts = dict(
    total=len(cases),
    failed=sum(c.find("failure") is not None for c in cases),
    errors=sum(c.find("error") is not None for c in cases),
    skipped=sum(c.find("skipped") is not None for c in cases),
)
counts["passed"] = counts["total"] - counts["failed"] - counts["errors"] - counts["skipped"]
sources = {}
for folder in ("src", "tests", "schemas", "rules", "fixtures", "scripts"):
    for path in (PROJECT / folder).rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc",):
            sources[str(path.relative_to(PROJECT))] = digest(path.read_bytes())
for name in ("requirements.lock", "requirements.in", "pyproject.toml", "Makefile"):
    sources[name] = digest((PROJECT / name).read_bytes())
result = dict(
    schema_version="p005-engineering-evidence-1.0",
    results=results,
    test_counts=counts,
    source_hashes=sources,
    content_root_sha256=digest(sources),
    python=platform.python_version(),
    packages={
        p: importlib.metadata.version(p)
        for p in ("pytest", "hypothesis", "pydantic", "PyYAML", "jsonschema", "ruff", "mypy")
    },
    target_test_status="NOT_TESTED",
    learner_gates="UNVERIFIED",
    native_adapters="BLOCKED",
    full_taxonomy="BLOCKED_MISSING_SOURCE",
)
write(out / "manifest.json", canonical(result))
write(
    PROJECT / "evidence/engineering/manifest.json",
    canonical(dict(evidence_run=str(out.relative_to(PROJECT)), **result)),
)
print(counts)
raise SystemExit(0 if counts["passed"] > 0 and not any(r["exit_code"] for r in results) else 1)
