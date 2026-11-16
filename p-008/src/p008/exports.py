"""Sanitized local handoffs; exports do not publish anything."""

from p008.models import Bundle
from p008.quality import audit, model_visible
from p008.safety import Invalid, canonical, digest, write_new


def publication_eligible(bundle: Bundle) -> None:
    for provenance in [bundle.card.provenance] + [s.provenance for s in bundle.samples]:
        if provenance.source_type == "upstream_benchmark" and provenance.redistribution != "allowed":
            raise Invalid("UPSTREAM-LICENSE-OR-REDISTRIBUTION-REVIEW-REQUIRED")


def report(run) -> str:
    m = run.metrics
    rows = [
        "# P-008 synthetic evaluation " + run.run_id,
        "",
        "Codex implemented / Codex tested.",
        "Human independently reproduced: NOT DEMONSTRATED. External human reviewer verified: NOT DEMONSTRATED.",
        "",
        f"Status: {run.status}; unique samples: {m.unique_samples}; observations: {m.observations}; executed: {m.executed}.",
        f"PASS {m.passed}; FAIL {m.failed}; BLOCKED {m.blocked}; NOT_TESTED {m.not_tested}; INCONCLUSIVE {m.inconclusive}.",
        "Critical sample IDs: " + (", ".join(m.critical_sample_ids) or "none"),
        "Unique pass rate: " + str(m.unique_pass_rate),
        "",
        m.definitions,
        "",
        m.limitations,
        "",
        "| Sample | Repeat | Status | Critical | Dimensions |",
        "|---|---:|---|---|---|",
    ]
    rows += [
        f"| {r.sample_id} | {r.repetition} | {r.status} | {r.critical_failure} | {r.dimensions} |"
        for r in run.results
    ]
    rows += [
        "",
        "Model/provider: " + run.plan.evaluator.provider + "/" + run.plan.evaluator.model,
        "Network: " + run.plan.network,
        "",
        *run.limitations,
    ]
    return "\n".join(rows) + "\n"


def sanitized_run(run) -> dict:
    # Deliberate allowlist: never include model prompts, raw observations, label keys or traces.
    return {
        "schema_version": "1.0",
        "run_id": run.run_id,
        "status": run.status,
        "plan_digest": run.plan_digest,
        "dataset_manifest_digest": run.plan.manifest_digest,
        "dataset": [run.plan.dataset_id, run.plan.dataset_version],
        "evaluator": run.plan.evaluator.model_dump(mode="json"),
        "metrics": run.metrics.model_dump(mode="json"),
        "results": [
            {
                "sample_id": r.sample_id,
                "repetition": r.repetition,
                "status": r.status,
                "dimensions": r.dimensions,
                "critical_failure": r.critical_failure,
                "scorer_digest": r.scorer_digest,
                "rubric_version": r.rubric_version,
                "threshold": r.threshold,
            }
            for r in run.results
        ],
        "limitations": run.limitations,
        "provenance": {
            "implementation": "Codex implemented",
            "validation": "Codex tested",
            "Human independently reproduced": "NOT DEMONSTRATED",
            "External human reviewer verified": "NOT DEMONSTRATED",
        },
    }


def export(registry, dataset="synthetic-core", version="1.0.0", run_id=None):
    bundle, manifest = registry.dataset(dataset, version)
    publication_eligible(bundle)
    from p008.pipeline import verified_run

    run = verified_run(registry, run_id) if run_id else None
    if run and (run.plan.dataset_id, run.plan.dataset_version) != (dataset, version):
        raise Invalid("EXPORT-RUN-DATASET-MISMATCH")
    safe = sanitized_run(run) if run else None
    if safe and run is not None:
        # Sealed sample-level statuses/dimensions can reveal label correctness; exclude them entirely.
        sealed = {s.sample_id for s in bundle.samples if s.split == "sealed_holdout"}
        safe["results"] = [r for r in safe["results"] if r["sample_id"] not in sealed]
        for key in ("critical_sample_ids", "flaky_sample_ids"):
            safe["metrics"][key] = [sid for sid in safe["metrics"][key] if sid not in sealed]
        safe["omission_policy"] = {
            "sealed_results_excluded": len(run.results) - len(safe["results"]),
            "reason": "Sealed holdout results remain private; aggregate counts explicitly include them.",
        }
    files = {
        "dataset-card.json": canonical(bundle.card),
        "dataset-inputs.json": canonical(
            [
                {"sample_id": s.sample_id, "input": model_visible(s), "split": s.split}
                for s in bundle.samples
                if s.split != "sealed_holdout"
            ]
        ),
        "quality.json": canonical(audit(bundle)),
        "provenance.json": canonical(
            {
                "schema_version": "1.0",
                "source": bundle.card.provenance.model_dump(mode="json"),
                "frozen_manifest_sha256": digest(manifest),
                "publish_status": "REVIEW_REQUIRED_LOCAL_EXPORT_ONLY",
            }
        ),
        "handoff.json": canonical(
            {
                "schema_version": "1.0",
                "contract": "p008-handoff-1.0",
                "p007": {
                    "kind": "evaluation-metadata-only",
                    "dataset": dataset,
                    "manifest": digest(manifest),
                },
                "p009": {
                    "kind": "evaluation-event-references",
                    "run_id": run_id,
                    "evidence_manifest_digest": digest(run) if run else None,
                },
                "p010": {
                    "kind": "synthetic-evaluation-summary",
                    "findings": [],
                    "limitations": bundle.card.limitations,
                },
                "summary": safe,
            }
        ),
    }
    if safe and run is not None:
        files["evaluation-report.json"] = canonical(safe)
        # Public markdown uses no sealed sample-level outcomes.
        files["evaluation-report.md"] = (
            "# P-008 sanitized synthetic evaluation\n\nStatus: "
            + run.status
            + "\n\nAggregate metrics include sealed cases; per-sample public rows exclude them.\n\n"
            + run.metrics.limitations
            + "\n"
        ).encode()
    for raw in files.values():
        if b"P008_DUMMY_SECRET" in raw or b"P008_HOLDOUT_" in raw or b'"label_key"' in raw:
            raise Invalid("EXPORT-REDACTION-FAILURE")
    key = "export-" + digest({k: digest(v) for k, v in files.items()})[:24]
    folder = registry.path("exports", key)
    if folder.exists():
        from p008.safety import read_bytes

        if any(not (folder / k).is_file() or read_bytes(folder / k) != v for k, v in files.items()):
            raise Invalid("EXPORT-COLLISION-OR-MUTATION")
    else:
        for name, raw in files.items():
            write_new(folder / name, raw)
    return folder
