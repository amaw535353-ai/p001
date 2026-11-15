#!/usr/bin/env python3
"""Execute separate simulated approval commands and record observed CLI results.

Initialization alone NEVER approves. This named training demonstration explicitly
invokes submit, simulated review and activation using fictional actors and evidence.
It neither contacts targets nor creates a normal-looking real authorization.
"""
import json
from pathlib import Path
import subprocess
import sys
from time import time_ns
from uuid import uuid4

from p003 import demo
from p003.models import Artifact, sealed
from p003.util import ROOT, digest, now

run_id = "demo-" + str(time_ns())
store = ROOT / ".runtime" / run_id
output = ROOT / "generated" / run_id
evidence = ROOT / "evidence" / run_id
evidence.mkdir(parents=True, mode=0o700)
rows = []


def command(expected, *args):
    cmd = [sys.executable, "-m", "p003.cli", "--store", str(store), *args]
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=30)
    value = json.loads(result.stdout)
    rows.append({"command": cmd, "exit_code": result.returncode, "expected_exit_code": expected,
                 "status": "PASS" if result.returncode == expected else "FAIL", "observed": value})
    if result.returncode != expected:
        raise RuntimeError("demonstration failed; inspect owned synthetic evidence")
    return value["result"]


command(0, "demo", "init", "--seed", "42")
command(0, "engagement", "validate", "--file", "examples/engagement-draft-a.json")
command(0, "engagement", "validate", "--file", "examples/engagement-draft-a.yaml")
command(0, "engagement", "submit", "--id", "ENG-DEMO-A", "--actor", "demo-a-requestor",
        "--version", "1", "--at", "2026-11-15T08:10:00Z", "--reason", "Synthetic review request")
command(0, "engagement", "approve", "--id", "ENG-DEMO-A", "--actor", "demo-a-reviewer",
        "--version", "1", "--at", "2026-11-15T08:20:00Z", "--reason", "Explicit simulated review",
        "--simulate-review", "--scope-digest", demo.engagement().content_digest,
        "--evidence-ref", "training-review-a-v1")
command(0, "engagement", "activate", "--id", "ENG-DEMO-A", "--actor", "demo-a-owner",
        "--version", "1", "--at", demo.START, "--reason", "Fictional window prerequisites met")
command(0, "scope", "evaluate", "--request", "examples/check-allow.json")
command(3, "scope", "evaluate", "--request", "examples/check-deny-unknown-path.json")
for fmt, name in [("markdown", "engagement-brief.md"), ("policy", "engagement-policy.json"),
                  ("oscal", "assessment-plan.mapping-draft.json")]:
    command(0, "export", fmt, "--id", "ENG-DEMO-A", "--actor", "demo-a-assessor",
            "--output", str(output / name))
manifest = command(0, "evidence", "manifest", "--id", "ENG-DEMO-A", "--actor", "demo-a-reviewer")
(output / "evidence-manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
command(0, "redmine", "sync", "--id", "ENG-DEMO-A", "--actor", "demo-a-reviewer", "--target", "lab", "--dry-run")
command(0, "engagement", "submit", "--id", "ENG-DEMO-B", "--actor", "demo-b-requestor",
        "--version", "1", "--reason", "Pending expired training exercise")
command(0, "engagement", "expire", "--id", "ENG-DEMO-B", "--actor", "demo-b-owner",
        "--version", "1", "--reason", "Fictional window already elapsed")
command(0, "scope", "diff", "--old", "examples/engagement-draft-a.json", "--new", "examples/scope-extension-v2.json")
command(0, "engagement", "amend", "--id", "ENG-DEMO-A", "--actor", "demo-a-requestor",
        "--version", "1", "--file", "examples/scope-extension-v2.json", "--reason", "Request metadata path")
command(3, "scope", "evaluate", "--request", "examples/check-allow.json")
command(0, "engagement", "suspend", "--id", "ENG-DEMO-A", "--actor", "demo-a-owner",
        "--version", "2", "--reason", "Fictional emergency stop")
command(3, "scope", "evaluate", "--request", "examples/check-allow.json")
command(0, "reset", "--confirm", "p003-local")
command(0, "demo", "init", "--seed", "42")
command(0, "engagement", "show", "--id", "ENG-DEMO-A", "--actor", "demo-a-assessor")
report = sealed(Artifact, id=str(uuid4()), source="actual separate CLI demonstration commands",
                author="codex-builder", created_at=now()).model_dump(mode="json")
report.update(kind="executed-training-demonstration", commands=rows,
              counts={"PASS": sum(r["status"] == "PASS" for r in rows), "FAIL": sum(r["status"] == "FAIL" for r in rows)},
              outputs={str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in output.iterdir()},
              real_legal_authority="NOT VERIFIED", target_enforcement="NOT VERIFIED")
report["content_digest"] = digest({k: v for k, v in report.items() if k != "content_digest"})
dest = evidence / "manifest.json"
dest.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
print(json.dumps({"status": "PASS", "counts": report["counts"], "evidence": str(dest.relative_to(ROOT)),
                  "sha256": digest(dest.read_bytes()), "outputs": str(output.relative_to(ROOT))}, indent=2))
