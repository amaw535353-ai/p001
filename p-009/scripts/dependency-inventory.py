#!/usr/bin/env python3
"""Installed metadata, not a full image SBOM or legal assessment."""

import importlib.metadata
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
rows = []
for distribution in importlib.metadata.distributions():
    metadata = distribution.metadata
    rows.append(
        {
            "name": metadata.get("Name"),
            "version": distribution.version,
            "license": (metadata.get("License-Expression") or metadata.get("License") or "UNKNOWN")[:160],
        }
    )
rows.sort(key=lambda x: x["name"].lower())
(root / "docs/dependency-inventory.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
print(f"Recorded {len(rows)} installed distributions; unknown licenses require review")
