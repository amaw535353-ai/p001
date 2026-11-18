#!/usr/bin/env python3
"""Generate explicit versioned JSON Schema contracts; --check detects drift."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from p009 import models
from p009.config import Config
from p009.detection import Rule

parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
contracts = {
    "detection-rule": Rule,
    "normalized-event": models.Event,
    "source-event": models.SourceEvent,
    "evidence-object": models.ObjectRef,
    "evidence-manifest": models.Manifest,
    "correlation": models.Link,
    "timeline": models.Timeline,
    "source-config": models.Source,
    "retention-policy": models.Retention,
    "pipeline-config": Config,
    "p009-handoff-v1": models.Handoff,
}
for name, model in contracts.items():
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", **model.model_json_schema()}
    raw = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    path = root / "schemas" / (name + ".schema.json")
    if args.check:
        if not path.exists() or path.read_text() != raw:
            raise SystemExit("schema drift: " + name)
    else:
        path.write_text(raw)
print(f"PASS {len(contracts)} generated schemas")
