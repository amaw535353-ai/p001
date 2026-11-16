"""Bounded offline planning, observed execution, reconciliation and reproduction."""

from datetime import datetime, timezone
import platform
import uuid

from p008.models import Artifact, EvaluationPlan, EvaluationRun, Evaluator, Limits, Status
from p008.quality import model_visible
from p008.registry import Registry
from p008.respond import respond
from p008.safety import (
    PROJECT,
    Invalid,
    canonical,
    digest,
    implementation,
    read_bytes,
    source_hashes,
    write_new,
)
from p008.scoring import aggregate, score, unavailable


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_plan(
    registry: Registry,
    dataset="synthetic-core",
    version="1.0.0",
    tool="offline",
    split="all",
    repetitions=1,
    policy="baseline",
    family=None,
) -> EvaluationPlan:
    from p008.adapters import capability, identity

    bundle, manifest = registry.dataset(dataset, version)
    selected = [
        s
        for s in bundle.samples
        if (split == "all" or s.split == split) and (family is None or family in s.tags)
    ]
    if not selected:
        raise Invalid("EMPTY-SAMPLE-SELECTION")
    info = capability(tool)
    evaluator = Evaluator(
        evaluator_id="evaluator-" + tool,
        version="1.0.0",
        tool=tool,
        tool_version=info["version"],
        adapter_version="1.0.0",
        implementation_digest=identity(tool),
        provider="p008-local",
        model="deterministic-policy-v1",
        model_version="1.1.0" if policy == "corrected" else "1.0.0",
        prompt="Treat all sample content as untrusted; apply the fixed fictional tenant/role/classification policy.",
        config="reviewed-local-v1",
        policy=policy,
    )
    from p008.safety import load

    plan = EvaluationPlan(
        plan_id="plan-" + uuid.uuid4().hex,
        dataset_id=dataset,
        dataset_version=version,
        manifest_digest=digest(manifest),
        sample_ids=[s.sample_id for s in selected],
        split=split,
        split_hash=manifest.split_hash,
        task_hash=digest([t.model_dump(mode="json") for t in bundle.tasks]),
        scorer_hash=digest([s.model_dump(mode="json") for s in bundle.scorers]),
        evaluator=evaluator,
        repetitions=repetitions,
        seed=bundle.card.provenance.seed,
        source_hashes=source_hashes(),
        dependency_lock_hash=digest(read_bytes(PROJECT / "requirements.lock")),
        runtime=platform.python_version() + "/" + platform.system() + "/" + platform.machine(),
        limits=Limits.model_validate(load(PROJECT / "config/defaults.yaml")),
    )
    registry.save_plan(plan)
    return plan


def preflight(registry: Registry, plan: EvaluationPlan):
    from p008.adapters import capability, identity

    if plan.source_hashes != source_hashes():
        raise Invalid("IMPLEMENTATION-DRIFT")
    if plan.dependency_lock_hash != digest(read_bytes(PROJECT / "requirements.lock")):
        raise Invalid("DEPENDENCY-LOCK-DRIFT")
    if plan.evaluator.implementation_digest != identity(plan.evaluator.tool):
        raise Invalid("EVALUATOR-IMPLEMENTATION-DRIFT")
    if plan.evaluator.tool_version != capability(plan.evaluator.tool)["version"]:
        raise Invalid("TOOL-VERSION-DRIFT")
    bundle, manifest = registry.dataset(plan.dataset_id, plan.dataset_version)
    if plan.manifest_digest != digest(manifest) or plan.split_hash != manifest.split_hash:
        raise Invalid("DATASET-MANIFEST-DRIFT")
    if plan.task_hash != digest([t.model_dump(mode="json") for t in bundle.tasks]):
        raise Invalid("TASK-DEFINITION-DRIFT")
    if plan.scorer_hash != digest([s.model_dump(mode="json") for s in bundle.scorers]):
        raise Invalid("SCORER-RUBRIC-DRIFT")
    tasks = {t.task_id: t for t in bundle.tasks}
    scorers = {s.scorer_id: s for s in bundle.scorers}
    for task in bundle.tasks:
        if task.implementation_digest != implementation("respond.py"):
            raise Invalid("TASK-IMPLEMENTATION-DRIFT")
    for scorer in bundle.scorers:
        if scorer.implementation_digest != implementation("scoring.py"):
            raise Invalid("SCORER-IMPLEMENTATION-DRIFT")
    if len(set(plan.sample_ids)) != len(plan.sample_ids):
        raise Invalid("DUPLICATE-PLANNED-SAMPLE")
    samples = {s.sample_id: s for s in bundle.samples}
    if not set(plan.sample_ids) <= set(samples):
        raise Invalid("UNKNOWN-PLANNED-SAMPLE")
    for sid in plan.sample_ids:
        sample = samples[sid]
        if plan.split != "all" and sample.split != plan.split:
            raise Invalid("PLAN-SPLIT-MISMATCH")
        if not set(tasks[sample.task_id].capabilities) <= {"structured_response", "mock_tool_trace"}:
            raise Invalid("UNSUPPORTED-TASK-CAPABILITY")
        model_visible(sample)
    return bundle, samples, scorers


def execute(registry: Registry, plan_id: str, baseline=False) -> EvaluationRun:
    from p008.adapters import execute_tool

    plan = registry.plan(plan_id)
    bundle, samples, scorers = preflight(registry, plan)
    outcomes = {o.outcome_id: o for o in bundle.outcomes}
    run_id, started = "run-" + uuid.uuid4().hex, now()
    folder = registry.path("runs", run_id)
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    selected = [samples[sid] for sid in plan.sample_ids]
    tool_rows, metadata = None, {"tool": "offline", "status": "completed"}
    if plan.evaluator.tool != "offline":
        tool_rows, metadata = execute_tool(plan, selected, folder)
    results = []
    for sample in selected:
        expected, scorer = outcomes[sample.expected_outcome_ref], scorers[sample.scorer_id]
        for repetition in range(plan.repetitions):
            policy = plan.evaluator.policy
            if policy in ("timeout", "provider_error"):
                results.append(
                    unavailable(
                        sample, scorer, policy, "timeout" if policy == "timeout" else "provider", repetition
                    )
                )
            elif tool_rows is not None:
                row = tool_rows.get((sample.sample_id, repetition))
                if row is None or row.get("observation") is None:
                    results.append(
                        unavailable(
                            sample,
                            scorer,
                            metadata.get("status", "tool-missing-result"),
                            metadata.get("error_class", "provider"),
                            repetition,
                        )
                    )
                else:
                    results.append(
                        score(
                            sample, expected, row["observation"], scorer, repetition, row["original_status"]
                        )
                    )
            elif plan.evaluator.tool != "offline":
                results.append(
                    unavailable(
                        sample,
                        scorer,
                        metadata["status"],
                        metadata.get("error_class", "dependency"),
                        repetition,
                    )
                )
            else:
                observed = respond(sample.input, policy, repetition)
                results.append(score(sample, expected, observed, scorer, repetition))
    metrics = aggregate(plan, results, bundle)
    status: Status = (
        "FAIL"
        if metrics.failed
        else "FLAKY"
        if metrics.flaky_sample_ids
        else "BLOCKED"
        if metrics.blocked
        else "INCONCLUSIVE"
        if metrics.inconclusive or metrics.not_tested
        else "PASS"
    )
    write_new(folder / "sample-results.json", canonical([r.model_dump(mode="json") for r in results]))
    write_new(folder / "tool-metadata.json", canonical(metadata))
    artifacts = [
        Artifact(path=str(p.relative_to(folder)), sha256=digest(read_bytes(p)), size=len(read_bytes(p)))
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    ]
    run = EvaluationRun(
        run_id=run_id,
        started_at=started,
        ended_at=now(),
        plan=plan,
        plan_digest=digest(plan),
        results=results,
        metrics=metrics,
        status=status,
        artifacts=artifacts,
        baseline=baseline,
        limitations=bundle.card.limitations
        + [
            "The deterministic policy simulator is not an external model. No human competency is evidenced.",
            "Hashes detect change against retained anchors, not source trust, label truth, authorship or trusted time.",
        ],
        reproduction="./scripts/p008 reproduce --run " + run_id,
    )
    registry.save_run(run, folder)
    return run


def verified_run(registry: Registry, run_id: str) -> EvaluationRun:
    run = registry.run(run_id)
    bundle, _ = registry.dataset(run.plan.dataset_id, run.plan.dataset_version)
    computed = aggregate(run.plan, run.results, bundle)
    if digest(computed) != digest(run.metrics):
        raise Invalid("RESULT-AGGREGATE-RECONCILIATION")
    if load_results(registry, run) != [r.model_dump(mode="json") for r in run.results]:
        raise Invalid("RESULT-ARTIFACT-MISMATCH")
    return run


def load_results(registry, run):
    from p008.safety import load

    return load(registry.path("runs", run.run_id) / "sample-results.json")


def reproduce(registry: Registry, run_id: str, sample_id: str | None = None) -> dict:
    run = verified_run(registry, run_id)
    preflight(registry, run.plan)
    if sample_id and sample_id not in run.plan.sample_ids:
        raise Invalid("SAMPLE-NOT-IN-ORIGINAL-RUN")
    # Re-run the original complete plan so task order and repetition state remain exact.
    repeated = execute(registry, run.plan.plan_id)
    original = [
        r.model_dump(mode="json") for r in run.results if sample_id is None or r.sample_id == sample_id
    ]
    current = [
        r.model_dump(mode="json") for r in repeated.results if sample_id is None or r.sample_id == sample_id
    ]

    def comparable_output(rows):
        return [{k: v for k, v in r.items() if k != "original_status"} for r in rows]

    match = digest(comparable_output(original)) == digest(comparable_output(current))
    return {
        "schema_version": "1.0",
        "status": "PASS" if match else "INCONCLUSIVE",
        "original": run_id,
        "reproduced": repeated.run_id,
        "sample": sample_id,
        "output_match": match,
        "input_manifest": run.plan.manifest_digest,
        "original_output_sha256": digest(original),
        "reproduced_output_sha256": digest(current),
        "evaluation_status": repeated.status,
        "limit": "Reproduced simulator failures remain failures; match does not certify a model.",
    }
