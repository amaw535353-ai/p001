#!/usr/bin/env python3
"""Generate schema contracts from actual strict models; --check detects drift."""

import json
from pathlib import Path
import sys
from typing import Literal

from pydantic import create_model
from p004.models import (
    ArchitectureDeclaration,
    Asset,
    Boundary,
    Context,
    Coverage,
    Endpoint,
    Flow,
    InputConfig,
    SHA,
    Snapshot,
    Strict,
)
from p004.policy import LiveContext, OwnedTarget

ROOT = Path(__file__).resolve().parents[1]
models = {
    "snapshot": Snapshot,
    "discovery-policy": LiveContext,
    "owned-target": OwnedTarget,
    "input": InputConfig,
    "architecture": ArchitectureDeclaration,
}
for name, record in {
    "assets": Asset,
    "endpoints": Endpoint,
    "flows": Flow,
    "trust_boundaries": Boundary,
    "identities": Asset,
    "coverage": Coverage,
}.items():
    models[name] = create_model(
        name + "Export",
        __base__=Strict,
        schema_version=(Literal["1.0"], ...),
        context=(Context, ...),
        snapshot_digest=(SHA, ...),
        records=(list[record], ...),
    )
for name, model in models.items():
    data = model.model_json_schema()
    data["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    data["$id"] = "urn:p004:" + name + ":1.0"
    raw = json.dumps(data, indent=2, sort_keys=True) + "\n"
    path = ROOT / "schemas" / (name + ".schema.json")
    if "--check" in sys.argv:
        if not path.exists() or path.read_text() != raw:
            raise SystemExit("Schema drift: " + name)
    else:
        path.parent.mkdir(exist_ok=True)
        path.write_text(raw)
print("PASS: strict versioned schema contracts")
