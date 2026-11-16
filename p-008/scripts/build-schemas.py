#!/usr/bin/env python3
"""Generate strict JSON Schemas from the public typed models; check without mutation."""

import argparse

from p008.models import CONTRACTS
from p008.safety import PROJECT, REPO, canonical, load

parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
for name, model in CONTRACTS.items():
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://p008.invalid/schemas/1.0/{name}.schema.json"
    if name == "p007-report-import":
        original = load(REPO / "p-007/schemas/report-export.schema.json")
        definitions = original.pop("$defs", {})

        def rebase(value):
            if isinstance(value, dict):
                return {
                    k: (v.replace("#/$defs/", "#/$defs/P007_") if k == "$ref" else rebase(v))
                    for k, v in value.items()
                }
            if isinstance(value, list):
                return [rebase(v) for v in value]
            return value

        schema.setdefault("$defs", {}).update({"P007_" + k: rebase(v) for k, v in definitions.items()})
        schema["properties"]["report"] = rebase(original)
    path = PROJECT / "schemas" / (name + ".schema.json")
    raw = canonical(schema)
    if args.check:
        if not path.is_file() or path.read_bytes() != raw:
            raise SystemExit("SCHEMA-DRIFT:" + name)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
print(f"PASS {len(CONTRACTS)} generated schemas" + (" unchanged" if args.check else " written"))
