"""Sanitized, append-only test run records and local diagnostics."""

import json
import importlib.metadata
import os
import platform
import subprocess
import time
from collections import Counter
from p002 import __version__, NOTICE
from p002.adapters import utc, RUNTIME
from p002.exporters import canonical, code_hash
from p002.scenarios import ROOT
from p002.validation import digest


def revision():
    p = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else "uncommitted-checkout"


def record_run(kind, rows, d=None, args=""):
    evidence = ROOT / "evidence"
    evidence.mkdir(exist_ok=True)
    dest = evidence / (kind + "-" + str(time.time_ns()) + ".json")
    versions = {
        "python": platform.python_version(),
        "pydantic": __import__("pydantic").__version__,
        "p002": __version__,
    }
    for name in ["pytest", "sdv", "torch", "hypothesis", "ruff", "mypy", "jsonschema"]:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "NOT INSTALLED"
    for p in sorted(RUNTIME.glob("*-version.json")) if RUNTIME.exists() else []:
        versions[p.stem] = json.loads(p.read_text())
    config = {
        "code_sha256": code_hash(),
        "dependency_lock_sha256": digest((ROOT / "requirements.lock").read_bytes()),
        "sdv_lock_sha256": digest((ROOT / "requirements-sdv.lock").read_bytes()),
        "schema_version": "1.0",
        "profile": d.profile if d else None,
        "seed": d.seed if d else None,
        "logical_clock": d.logical_time if d else None,
        "mode": d.mode if d else "fixtures",
        "dataset_sha256": digest(canonical(d.model_dump(mode="json"))) if d else None,
    }
    for r in rows:
        r.setdefault("precondition", "Owned local fixture; no real data or production service")
        r.setdefault("expected", r.get("expected_outcome", "test assertion passes"))
        r.setdefault(
            "observed", {"outcome": r.get("outcome", r["status"]), "http_status": r.get("http_status")}
        )
        r.setdefault("utc", utc())
        r["command"] = args
        r["commit"] = revision()
        r["code_sha256"] = config["code_sha256"]
        r["versions"] = versions
        r["evidence_path"] = str(dest.relative_to(ROOT))
        r["human_verifier"] = None
    run = {
        "notice": NOTICE,
        "utc": utc(),
        "commit": revision(),
        "uncommitted_code_sha256": config["code_sha256"],
        "command": args,
        "versions": versions,
        "config": config,
        "results": rows,
        "counts": dict(Counter(r["status"] for r in rows)),
        "assessment_coverage": "NOT DEMONSTRATED",
        "human_findings": None,
    }
    # Exclusive creation; an observation run is never edited to turn FAIL into PASS.
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical(run))
    return dest


def command(args):
    if args.command == "doctor":
        from p002.adapters import command as adapters

        class A:
            operation = "status"

        return {
            "notice": NOTICE,
            "python": platform.python_version(),
            "core": "AVAILABLE",
            "adapters": adapters(A()),
            "p001_contract": "marker only; no general document API",
            "kind": "BLOCKED: rootless cgroup driver none (P-001 doctor)",
            "secret_variable_presence": {
                k: bool(os.environ.get(k))
                for k in ["P002_NEXTCLOUD_TOKEN", "P002_REDMINE_TOKEN", "P002_LABELSTUDIO_TOKEN"]
            },
            "native_permission_parity": "NOT VERIFIED",
            "human_gates": {g: "NOT DEMONSTRATED" for g in ["G1", "G2", "G3", "G4"]},
        }
    if args.command == "down":
        from p002.lab import down

        return down("all", args.confirm)
    # Summarize latest evidence per suite without deleting earlier failures.
    files = sorted((ROOT / "evidence").glob("*.json"))
    runs = [
        {
            "path": str(p.relative_to(ROOT)),
            "sha256": digest(p.read_bytes()),
            "counts": json.loads(p.read_text())["counts"],
        }
        for p in files
        if p.name != "manifest.json"
    ]
    return {"notice": NOTICE, "utc": utc(), "runs": runs, "human_assessment": "NOT DEMONSTRATED"}
