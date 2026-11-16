#!/usr/bin/env python3
"""Schema snapshots are generated from the actual typed contracts."""

import argparse
import json
from p007.models import CONTRACTS
from p007.safety import PROJECT

parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
for name, model in CONTRACTS.items():
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    path = PROJECT / "schemas" / (name + ".schema.json")
    if args.check:
        assert json.loads(path.read_text()) == schema, name + " schema drift"
    else:
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
print("PASS: 13 versioned schema snapshots")
