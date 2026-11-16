"""Strict run identity comparison, with sample-level transitions retained."""

from p008.models import Comparison, Classification
from p008.safety import digest


def compare(before, after) -> Comparison:
    a, b = before.plan, after.plan
    reasons = []
    kind: Classification = "NOT_COMPARABLE"
    if set(a.sample_ids) != set(b.sample_ids):
        kind = "NEW_OR_REMOVED_SAMPLES"
        reasons.append("Planned sample set differs.")
    if (a.dataset_id, a.dataset_version, a.manifest_digest, a.split, a.split_hash) != (
        b.dataset_id,
        b.dataset_version,
        b.manifest_digest,
        b.split,
        b.split_hash,
    ):
        kind = "DATASET_CHANGED"
        reasons.append("Dataset/split identity changed.")
    if (a.evaluator.provider, a.evaluator.model, a.evaluator.model_version) != (
        b.evaluator.provider,
        b.evaluator.model,
        b.evaluator.model_version,
    ):
        kind = "MODEL_OR_PROVIDER_CHANGED"
        reasons.append("Model/provider identity changed.")

    def evaluator_rest(plan):
        return {
            k: v
            for k, v in plan.evaluator.model_dump(mode="json").items()
            if k not in ("provider", "model", "model_version")
        }

    if (
        a.scorer_hash != b.scorer_hash
        or digest(evaluator_rest(a)) != digest(evaluator_rest(b))
        or a.task_hash != b.task_hash
    ):
        if kind != "MODEL_OR_PROVIDER_CHANGED":
            kind = "SCORER_OR_EVALUATOR_CHANGED"
        reasons.append("Task/scorer/evaluator/prompt/configuration identity changed.")
    if (a.runtime, a.source_hashes, a.dependency_lock_hash, a.seed, a.repetitions, a.limits) != (
        b.runtime,
        b.source_hashes,
        b.dependency_lock_hash,
        b.seed,
        b.repetitions,
        b.limits,
    ):
        reasons.append("Runtime, implementation, seed, budget or repetitions changed.")

    def statuses(run):
        return {
            sid: sorted(r.status for r in run.results if r.sample_id == sid) for sid in run.plan.sample_ids
        }

    old, new = statuses(before), statuses(after)
    transitions = {
        sid: [",".join(old.get(sid, ["ABSENT"])), ",".join(new.get(sid, ["ABSENT"]))]
        for sid in sorted(set(old) | set(new))
    }
    comparable = not reasons
    delta = None
    if comparable:
        if "BLOCKED" in (before.status, after.status):
            kind = "BLOCKED"
        elif before.metrics.flaky_sample_ids or after.metrics.flaky_sample_ids:
            kind = "FLAKY"
        elif any(r.status not in ("PASS", "FAIL") for r in before.results + after.results):
            kind = "INCONCLUSIVE"
        else:
            improved = any("FAIL" in old[s] and all(v == "PASS" for v in new[s]) for s in old)
            regressed = any(all(v == "PASS" for v in old[s]) and "FAIL" in new[s] for s in old)
            kind = (
                "MIXED"
                if improved and regressed
                else "IMPROVED"
                if improved
                else "REGRESSED"
                if regressed
                else "UNCHANGED"
            )
            delta = after.metrics.unique_pass_rate - before.metrics.unique_pass_rate
    return Comparison(
        baseline=before.run_id,
        current=after.run_id,
        classification=kind,
        comparable=comparable,
        reasons=reasons,
        transitions=transitions,
        pass_rate_delta=delta,
    )
