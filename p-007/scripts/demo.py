#!/usr/bin/env python3
"""Immutable synthetic baseline, remediation, introduced regression and reproduction."""

from p007.catalog import plan
from p007.evidence import baseline, reproduce, run, verify
from p007.exports import export
from p007.models import ReproductionRequest
from p007.regression import compare
from p007.safety import PROJECT, canonical, write_new

first = run(plan())
baseline(first, "baseline-" + first.name)
fixed = run(
    plan(variant="remediated"), remediation_ref="SIMULATED-output-validator-fix", retest_of=first.name
)
broken = run(
    plan(variant="regressed"), remediation_ref="SIMULATED-regression-introduced", retest_of=fixed.name
)
improvement = compare(verify(first), verify(fixed), "synthetic-remediation-v1")
regression = compare(verify(fixed), verify(broken), "synthetic-regression-v1")
assert any(e.classification == "IMPROVED" for e in improvement.entries)
assert any(e.classification == "REGRESSION" for e in regression.entries)
reproduction = reproduce(
    first, ReproductionRequest(run_id=first.name, test_id="T-offline-cross-tenant", repetitions=2)
)
for folder in (first, fixed, broken):
    export(verify(folder), folder, PROJECT / "reports" / folder.name)
summary = {
    "baseline": first.name,
    "remediated": fixed.name,
    "regressed": broken.name,
    "improvement": improvement.model_dump(mode="json"),
    "regression": regression.model_dump(mode="json"),
    "reproduction": reproduction,
    "evidence_verified": True,
    "independent_human": "NOT DEMONSTRATED",
}
out = PROJECT / "reports" / ("demo-" + first.name + ".json")
write_new(out, canonical(summary))
print(canonical(summary).decode())
