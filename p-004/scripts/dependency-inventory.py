#!/usr/bin/env python3
"""Inspect installed metadata/license files without guessing repository licensing."""

import importlib.metadata
import json
from pathlib import Path

from p004.safety import digest, text

ROOT = Path(__file__).resolve().parents[1]
rows = []
for dist in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
    name = dist.metadata["Name"]
    if name.startswith(("p002-", "p003-", "p004-")):
        continue
    files = [p for p in dist.files or [] if "license" in str(p).lower() or "copying" in str(p).lower()]
    licenses = {
        str(p): digest(Path(dist.locate_file(p)).read_bytes())
        for p in files
        if Path(dist.locate_file(p)).is_file()
    }
    classifiers = [
        c.split(" :: ")[-1] for c in dist.metadata.get_all("Classifier", []) if c.startswith("License ::")
    ]
    rows.append(
        dict(
            name=name,
            version=dist.version,
            license_expression=dist.metadata.get("License-Expression"),
            license_summary=text(dist.metadata.get("License", ""), 200),
            license_classifiers=classifiers,
            license_file_sha256=licenses,
            requires=dist.requires or [],
        )
    )
result = dict(
    source="actual installed Python distribution metadata; not legal advice",
    dependencies=rows,
    repository_license="NOT ASSUMED; human owner review required",
    optional_not_bundled=["Onyx", "OpenHands", "ZAP", "Playwright browsers"],
)
(ROOT / "docs/dependency-inventory.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(f"Inspected license metadata/files for {len(rows)} installed distributions")
