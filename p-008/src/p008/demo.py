"""Entire offline workflow; no optional tool or hosted provider required."""

import uuid

from p008.comparison import compare
from p008.exports import export
from p008.generation import generate
from p008.integrations import siblings
from p008.laboratory import laboratory
from p008.pipeline import execute, make_plan, reproduce
from p008.quality import audit
from p008.safety import canonical, digest, write_new


def demo(registry, seed=20261116):
    # Each demo owns a fresh child registry; rerunning never overwrites a previous baseline.
    from p008.registry import Registry

    child = Registry(registry.root / ("demo-" + uuid.uuid4().hex))
    original = generate(seed)
    child.save_draft(original)
    manifest = child.freeze(original)
    baseline_plan = make_plan(child)
    baseline = execute(child, baseline_plan.plan_id, baseline=True)
    same = execute(child, baseline_plan.plan_id)
    # A changed seed and dataset version create a separate immutable dataset, not an in-place update.
    child.freeze(generate(seed + 1, "1.1.0"))
    changed = execute(child, make_plan(child, version="1.1.0").plan_id)
    manipulation = laboratory(child, baseline)
    reproduction = reproduce(child, baseline.run_id, "p008-injection-04")
    handoff = export(child, run_id=baseline.run_id)
    result = {
        "schema_version": "1.0",
        "status": "PASS",
        "registry": str(child.root),
        "dataset_manifest_sha256": digest(manifest),
        "audit": audit(original),
        "baseline": baseline.run_id,
        "baseline_evaluation_status": baseline.status,
        "baseline_metrics": baseline.metrics.model_dump(mode="json"),
        "same_identity_run": same.run_id,
        "same_identity_comparison": compare(baseline, same).model_dump(mode="json"),
        "changed_run": changed.run_id,
        "changed_comparison": compare(baseline, changed).model_dump(mode="json"),
        "manipulation_lab": manipulation["lab_id"],
        "manipulation_checks": manipulation["status"],
        "reproduction": reproduction,
        "export": str(handoff),
        "siblings": siblings(),
        "limit": "PASS means demonstration mechanics completed, not that the baseline model passed. Synthetic simulator only.",
        "learner_gates": {f"G{n}": "NOT DEMONSTRATED" for n in range(1, 5)},
    }
    if manipulation["status"] != "PASS" or not reproduction["output_match"]:
        result["status"] = "FAIL"
    write_new(child.root / "demo-summary.json", canonical(result))
    return result
