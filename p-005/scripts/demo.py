#!/usr/bin/env python3
"""Offline, repeatable demonstration. Guarded subprocesses; no target operations."""

import subprocess
import sys

from p005.evidence.safety import PROJECT, canonical, write

root = PROJECT / "generated"
commands = [
    ["model", "build", "--input", "fixtures/baseline/architecture.yaml", "--out", "generated/demo-baseline"],
    ["model", "validate", "--input", "generated/demo-baseline/model.json"],
    ["analyze", "--model", "generated/demo-baseline/model.json", "--out", "generated/demo-baseline"],
    [
        "graph",
        "render",
        "--model",
        "generated/demo-baseline/model.json",
        "--format",
        "mermaid",
        "--out",
        "generated/demo-baseline/diagrams/architecture.mmd",
    ],
    ["report", "--run", "generated/demo-baseline", "--format", "markdown"],
    [
        "tests",
        "plan",
        "--run",
        "generated/demo-baseline",
        "--out",
        "generated/demo-baseline/verification-plan.json",
    ],
    [
        "model",
        "build",
        "--input",
        "fixtures/variants/tenant-boundary-change.yaml",
        "--out",
        "generated/demo-changed",
    ],
    ["analyze", "--model", "generated/demo-changed/model.json", "--out", "generated/demo-changed"],
    [
        "diff",
        "--before",
        "generated/demo-baseline/model.json",
        "--after",
        "generated/demo-changed/model.json",
        "--out",
        "generated/model-diff.json",
    ],
    ["catalog", "validate", "--input", "catalogs/ATLAS-pinned.yaml"],
    ["adapters", "status"],
    ["evidence", "manifest", "--run", "generated/demo-baseline"],
    ["evidence", "verify", "--run", "generated/demo-baseline"],
]
logs = []
for args in commands:
    result = subprocess.run(
        [sys.executable, "-m", "p005", *args], cwd=PROJECT, capture_output=True, text=True, timeout=120
    )
    logs.append(
        dict(
            command=["p005", *args],
            exit_code=result.returncode,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
        )
    )
    print(" ".join(["p005", *args]), result.returncode, flush=True)
    if result.returncode:
        write(root / "demo-commands.json", canonical(logs))
        raise SystemExit(result.returncode)
write(root / "demo-commands.json", canonical(logs))
