#!/usr/bin/env python3
"""Build and install the real wheel in a fresh venv; verify it outside the checkout.

--offline requires a previously populated .runtime/wheels hash-locked wheel cache.
The default first populates that cache with verified PyPI downloads.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from time import time_ns
from uuid import uuid4

from p003 import demo
from p003.models import Artifact, sealed
from p003.util import ROOT, digest, now, safe

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--offline", action="store_true")
args = parser.parse_args()
run_id = "reconstruction-" + str(time_ns())
work = ROOT / ".runtime" / run_id
work.mkdir(parents=True, mode=0o700)
evidence = ROOT / "evidence" / run_id
evidence.mkdir(parents=True, mode=0o700)
cache = ROOT / ".runtime/wheels"
rows = []
environment = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}


def run(command, cwd=ROOT, expected=0):
    result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, timeout=180)
    excerpt = (result.stdout + result.stderr)[-2000:]
    safe(excerpt)
    rows.append({"command": list(map(str, command)), "cwd": str(cwd), "expected_exit_code": expected,
                 "exit_code": result.returncode, "status": "PASS" if result.returncode == expected else "FAIL",
                 "excerpt": excerpt})
    if result.returncode != expected:
        raise RuntimeError("clean reconstruction check failed")


success = False
try:
    if not args.offline:
        run([sys.executable, "-m", "pip", "download", "--require-hashes", "--only-binary=:all:",
             "--dest", str(cache), "-r", "requirements.lock"])
    run([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--no-build-isolation",
         "--wheel-dir", str(work / "dist"), "."])
    run([sys.executable, "-m", "venv", str(work / ".venv")])
    py = str(work / ".venv/bin/python")
    run([py, "-m", "pip", "install", "--no-index", "--find-links=" + str(cache), "--require-hashes",
         "--only-binary=:all:", "-r", str(ROOT / "requirements.lock")])
    wheel = next((work / "dist").glob("p003_*.whl"))
    run([py, "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)])
    run([py, "-m", "pip", "check"], work)
    # The entrypoint and module now come from the installed wheel, not src/PYTHONPATH.
    entrypoint = str(work / ".venv/bin/p003")
    run([entrypoint, "--version"], work)
    run([entrypoint, "aisvs", "list"], work)
    run([entrypoint, "demo", "init"], work)
    run([entrypoint, "engagement", "submit", "--id", "ENG-DEMO-A", "--actor", "demo-a-requestor",
         "--version", "1", "--at", "2026-11-15T08:10:00Z", "--reason", "Synthetic review request"], work)
    run([entrypoint, "engagement", "approve", "--id", "ENG-DEMO-A", "--actor", "demo-a-reviewer",
         "--version", "1", "--at", "2026-11-15T08:20:00Z", "--reason", "Explicit simulated review",
         "--simulate-review", "--scope-digest", demo.engagement().content_digest,
         "--evidence-ref", "training-review-a-v1"], work)
    run([entrypoint, "engagement", "activate", "--id", "ENG-DEMO-A", "--actor", "demo-a-owner",
         "--version", "1", "--at", demo.START, "--reason", "Fictional prerequisites met"], work)
    run([entrypoint, "scope", "evaluate", "--request", str(ROOT / "examples/check-allow.json")], work)
    run([entrypoint, "scope", "evaluate", "--request", str(ROOT / "examples/check-deny-unknown-path.json")], work, 3)
    for fmt, name in [("policy", "engagement-policy.json"), ("oscal", "assessment-plan.mapping-draft.json")]:
        run([entrypoint, "export", fmt, "--id", "ENG-DEMO-A", "--actor", "demo-a-assessor",
             "--output", "generated/" + name], work)
    run([entrypoint, "reset", "--confirm", "p003-local"], work)
    run([entrypoint, "demo", "init"], work)
    success = True
finally:
    report = sealed(Artifact, id=str(uuid4()), source="actual isolated wheel reconstruction commands",
                    author="codex-builder", created_at=now()).model_dump(mode="json")
    report.update(kind="clean-wheel-reconstruction", commands=rows,
                  result="PASS" if success else "FAIL", offline_install=True,
                  outputs={str(p.relative_to(work)): digest(p.read_bytes()) for p in work.rglob("*.whl")})
    report["content_digest"] = digest({k: v for k, v in report.items() if k != "content_digest"})
    dest = evidence / "manifest.json"
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"status": report["result"], "commands": len(rows), "evidence": str(dest.relative_to(ROOT)),
                      "sha256": digest(dest.read_bytes())}, indent=2))
