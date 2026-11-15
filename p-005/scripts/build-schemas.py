#!/usr/bin/env python3
"""Generate or compare public schemas against the actual typed contracts."""

import sys

from p005.domain.schemas import (
    AdapterResult,
    ControlRequirement,
    HumanReview,
    Model,
    ThreatScenario,
    VerificationCase,
)
from p005.evidence.safety import PROJECT, canonical
from p005.modeling.risk_catalog import RiskCatalog
from p005.modeling.rule_engine import Rule

contracts = dict(
    model=Model,
    threat=ThreatScenario,
    risk=RiskCatalog,
    control=ControlRequirement,
    verification=VerificationCase,
    adapter=AdapterResult,
    review=HumanReview,
    rule=Rule,
)
failed = []
for name, cls in contracts.items():
    path = PROJECT / "schemas" / (name + ".schema.json")
    data = cls.model_json_schema()
    data["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    raw = canonical(data)
    if "--check" in sys.argv:
        if not path.exists() or path.read_bytes() != raw:
            failed.append(name)
    else:
        path.write_bytes(raw)
if failed:
    raise SystemExit("SCHEMA-DRIFT: " + ", ".join(failed))
print("PASS: eight generated schemas match typed contracts")
