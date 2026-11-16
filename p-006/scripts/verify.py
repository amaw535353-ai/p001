#!/usr/bin/env python3
"""Local engineering verification; native service observations are separate."""

import datetime
import hashlib
import json
import os
import secrets
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from p006.safety import secret_detected

ROOT = Path(__file__).resolve().parents[1]


def main():
    run_id = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    directory = ROOT / "reports" / run_id
    directory.mkdir(parents=True, mode=0o700)
    steps = []
    env = dict(os.environ, PYTHONPATH=str(ROOT / "tests/no-network") + os.pathsep + str(ROOT / "src"))
    commands = [[sys.executable, "-m", "pytest", "tests", "-q", "--junitxml=" + str(directory / "offline.xml")],
                [str(ROOT / ".venv/bin/ruff"), "check", "src", "scripts", "tests"],
                [str(ROOT / ".venv/bin/mypy"), "src"], ["make", "-C", str(ROOT.parent), "unit", "static"]]
    for index, args in enumerate(commands):
        print("Executing", " ".join(args), flush=True)
        step_env = env if index == 0 else dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        result = subprocess.run(args, cwd=ROOT, env=step_env, text=True, capture_output=True)
        print(result.stdout + result.stderr, end="", flush=True)
        steps.append({"command": args, "exit_code": result.returncode})
        if result.returncode:
            (directory / "commands.json").write_text(json.dumps(steps, indent=2) + "\n")
            raise SystemExit(result.returncode)
    groups = {}
    for case in ET.parse(directory / "offline.xml").getroot().iter("testcase"):
        stats = groups.setdefault(case.attrib.get("classname", "unknown"),
                                  {s: 0 for s in ["PASS", "FAIL", "BLOCKED", "NOT_TESTED", "INCONCLUSIVE"]})
        status = "FAIL" if any(case.find(tag) is not None for tag in ["failure", "error"]) else "NOT_TESTED" if case.find("skipped") is not None else "PASS"
        stats[status] += 1
    hashes = {relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() for relative in
              ["requirements.lock", "config/hardened.json", "config/images.lock.json", "policy/opa/authz.rego", "policy/opa/data.json", "compose.yaml"]}
    summary = {"schema_version": "p006-verification-v1", "run_id": run_id, "offline_groups": groups,
               "commands": steps, "hashes": hashes, "provenance": "Codex tested",
               "native_integration": "Separate evidence/*/results.json; adapter fixtures do not prove native enforcement",
               "human_independent_reproduction": "NOT_DEMONSTRATED"}
    encoded = json.dumps(summary, indent=2) + "\n"
    if secret_detected(encoded):
        raise RuntimeError("summary secret scan failed")
    (directory / "summary.json").write_text(encoded)
    print(json.dumps({"summary": str(directory.relative_to(ROOT)), "groups": groups}, indent=2))


if __name__ == "__main__":
    main()
