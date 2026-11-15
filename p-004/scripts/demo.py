#!/usr/bin/env python3
"""Real sibling fixture generation followed by offline discovery, never approvals."""

import json
from pathlib import Path
import sys
import time

from p002.generators import generate
from p004.cli import main
from p004.safety import digest

ROOT = Path(__file__).resolve().parents[1]
runtime = ROOT / ".runtime"
runtime.mkdir(exist_ok=True)
data = generate(seed=2026, profile="tiny", mode="fixtures")
(runtime / "p002-seed2026.json").write_text(data.model_dump_json(indent=2) + "\n")
name = "demo-" + str(time.time_ns())
first = ROOT / "reports" / (name + "-A")
code = main(
    [
        "discover-offline",
        "--root",
        str(ROOT.parent),
        "--config",
        "p-004/config/offline.example.json",
        "--out",
        str(first),
    ]
)
if code:
    sys.exit(code)
result = {
    "run": str(first.relative_to(ROOT)),
    "dataset_sha256": digest((runtime / "p002-seed2026.json").read_bytes()),
}
if "--diff" in sys.argv:
    changed = json.loads((ROOT / "fixtures/static/architecture.json").read_text())
    changed["assets"].append(
        {
            "key": "new-telemetry",
            "kind": "telemetry",
            "tenant_id": "tenant-a",
            "label": "Controlled new telemetry fixture",
        }
    )
    (runtime / "changed.json").write_text(json.dumps(changed))
    cfg = {
        "schema_version": "p004-input-v1",
        "inputs": [{"kind": "architecture", "path": "p-004/.runtime/changed.json"}],
    }
    original_cfg = {
        "schema_version": "p004-input-v1",
        "inputs": [{"kind": "architecture", "path": "p-004/fixtures/static/architecture.json"}],
    }
    (runtime / "changed-config.json").write_text(json.dumps(cfg))
    (runtime / "base-config.json").write_text(json.dumps(original_cfg))
    baseline = ROOT / "reports" / (name + "-baseline")
    after = ROOT / "reports" / (name + "-changed")
    for config, out, extra in [
        ("base-config.json", baseline, []),
        ("changed-config.json", after, ["--baseline", str(baseline)]),
    ]:
        code = main(
            [
                "discover-offline",
                "--root",
                str(ROOT.parent),
                "--config",
                "p-004/.runtime/" + config,
                "--out",
                str(out),
                *extra,
            ]
        )
        if code:
            sys.exit(code)
    result.update(before=str(baseline.relative_to(ROOT)), after=str(after.relative_to(ROOT)))
(runtime / "latest-demo.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
