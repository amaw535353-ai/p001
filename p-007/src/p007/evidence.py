"""Immutable runs, evidence verification, reproduction and honest repository identity."""

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import platform
import time
from uuid import uuid4

from p007 import __version__
from p007.assertions import normalize
from p007.catalog import source_hash, verify_plan
from p007.models import Artifact, BaselineReference, EvidenceManifest, ExecutionPlan, ReproductionRequest
from p007.runners import blocked, offline
from p007.safety import (
    PROJECT,
    REPO,
    Invalid,
    canonical,
    digest,
    load,
    read_bytes,
    redact,
    safe_path,
    write_new,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repository_identity() -> dict:
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=REPO, text=True, timeout=5).strip()

    try:
        return {
            "repository": "amaw535353-ai/p001",
            "commit_sha": git("rev-parse", "HEAD"),
            "branch": git("branch", "--show-current"),
            "dirty": bool(git("status", "--porcelain")),
            "source_hash": source_hash(),
            "runtime": {"python": platform.python_version(), "platform": platform.platform()},
            "commit_represents_working_tree": not bool(git("status", "--porcelain")),
        }
    except (subprocess.SubprocessError, OSError):
        return {
            "repository": "UNKNOWN",
            "commit_sha": None,
            "branch": None,
            "dirty": True,
            "source_hash": source_hash(),
            "commit_represents_working_tree": False,
        }


def artifact(folder: Path, name: str, value, media="application/json") -> Artifact:
    data = canonical(value) if not isinstance(value, bytes) else value
    if len(data) > 1_048_576:
        raise Invalid("ARTIFACT-SIZE-LIMIT")
    write_new(safe_path(folder, name), data)
    return Artifact(path=name, size=len(data), sha256=digest(data), media_type=media)


def run(
    plan: ExecutionPlan,
    *,
    root: Path | None = None,
    actor="codex",
    remediation_ref=None,
    retest_of=None,
    guard=None,
) -> Path:
    verify_plan(plan)
    if plan.source_hash != source_hash():
        raise Invalid("SOURCE-CHANGED-SINCE-PLAN")
    root = safe_path(root or PROJECT / "evidence")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:16]
    folder = safe_path(root, run_id)
    folder.mkdir(mode=0o700)
    started, timer = utc_now(), time.monotonic()
    artifacts = [artifact(folder, "owner.json", {"owner": "p007", "run_id": run_id})]
    artifacts.append(artifact(folder, "plan.json", plan.model_dump(mode="json")))
    results = []
    for test in plan.tests:
        if test.adapter == "offline":
            raw = offline(test, plan.fixtures)
        elif test.adapter == "p006":
            raw = blocked("p006", "P006-IMPLEMENTATION-ABSENT")
        else:
            from p007.adapters import execute_test

            raw = execute_test(test, plan, guard)
        compatibility = {
            "target_id": plan.target.target_id,
            "target_version": plan.target.version,
            "origin": plan.target.origin,
            "service_identity": plan.target.service_identity,
            "environment": plan.target.environment,
            "ownership_instance": plan.target.instance_id,
            "fixture_version": plan.fixtures["fixture_version"],
            "adapter": test.adapter,
            "source_hash": plan.source_hash,
            "seed": 7,
            "oracle": test.oracle.version,
            "controls": [c.model_dump(mode="json") for c in plan.controls],
            "fixture_cases_hash": digest(plan.fixtures["cases"]),
            "policy_version": plan.fixtures["policy_version"],
            "policy_hash": digest(plan.fixtures["policy"]),
            "model": raw.metadata.get("model"),
            "settings": raw.metadata.get("settings"),
            "browser": raw.metadata.get("browser"),
        }
        result = normalize(test, raw, compatibility=compatibility)
        results.append(result)
        artifacts.append(artifact(folder, test.test_id + ".json", result.model_dump(mode="json")))
    artifacts.append(
        artifact(
            folder,
            "results.jsonl",
            b"".join(canonical(r.model_dump(mode="json")) for r in results),
            "application/x-ndjson",
        )
    )
    manifest = EvidenceManifest(
        run_id=run_id,
        started_at=started,
        ended_at=utc_now(),
        duration_seconds=time.monotonic() - timer,
        actor_label=actor,
        repository=repository_identity(),
        plan_digest=plan.digest,
        target=plan.target,
        authorization=guard.decisions if guard else [],
        artifacts=artifacts,
        results=results,
        source_hash=plan.source_hash,
        redaction=[
            "credential keys and synthetic marker values removed before persistence",
            "raw prompts/outputs omitted except safe synthetic structured observations",
        ],
        limitations=[
            *plan.limitations,
            "Hashes establish consistency only, not identity, trusted time or oracle correctness",
            "No independent human reproduction recorded",
            "No hard RSS/cgroup limit on this host; tool heap, CPU/time/file-size limits used",
        ],
        reproduction=f"./scripts/p007 reproduce --run {run_id} --test <test-id>",
        provenance={
            "Codex implemented": __version__,
            "Codex tested": "see per-test executed/status fields",
            "Human independently reproduced": "NOT DEMONSTRATED",
            "External human reviewer verified": "NOT DEMONSTRATED",
        },
        remediation_ref=redact(remediation_ref),
        retest_of=retest_of,
    )
    write_new(folder / "manifest.json", canonical(manifest.model_dump(mode="json")))
    return folder


def verify(folder: Path) -> EvidenceManifest:
    manifest = EvidenceManifest.model_validate(load(safe_path(folder, "manifest.json")))
    if folder.name != manifest.run_id:
        raise Invalid("RUN-IDENTITY-MISMATCH")
    names = set()
    for ref in manifest.artifacts:
        if ref.path in names:
            raise Invalid("DUPLICATE-ARTIFACT")
        names.add(ref.path)
        try:
            data = read_bytes(safe_path(folder, ref.path))
        except FileNotFoundError as exc:
            raise Invalid("MISSING-ARTIFACT") from exc
        if len(data) != ref.size or digest(data) != ref.sha256:
            raise Invalid("MODIFIED-ARTIFACT")
    plan = ExecutionPlan.model_validate(load(folder / "plan.json"))
    verify_plan(plan)
    if plan.digest != manifest.plan_digest:
        raise Invalid("MANIFEST-PLAN-MISMATCH")
    if {r.test_id for r in manifest.results} != {t.test_id for t in plan.tests}:
        raise Invalid("MANIFEST-RESULT-SET-MISMATCH")
    for result in manifest.results:
        definition = next(t for t in plan.tests if t.test_id == result.test_id)
        if result.definition_hash != digest(
            definition.model_dump(mode="json")
        ) or result.compatibility_hash != digest(result.compatibility):
            raise Invalid("RESULT-IDENTITY-HASH-MISMATCH")
        if load(safe_path(folder, result.test_id + ".json")) != result.model_dump(mode="json"):
            raise Invalid("MANIFEST-RESULT-MISMATCH")
    return manifest


def baseline(folder: Path, name: str) -> Path:
    manifest = verify(folder)
    value = BaselineReference(
        baseline_id=name, run_id=manifest.run_id, manifest_sha256=digest(read_bytes(folder / "manifest.json"))
    )
    path = safe_path(folder.parent, name + ".baseline.json")
    write_new(path, canonical(value.model_dump(mode="json")))
    return path


def reproduce(folder: Path, request: ReproductionRequest) -> dict:
    previous = verify(folder)
    if previous.run_id != request.run_id:
        raise Invalid("REPRODUCTION-RUN-MISMATCH")
    plan = ExecutionPlan.model_validate(load(folder / "plan.json"))
    test = next((t for t in plan.tests if t.test_id == request.test_id), None)
    if test is None or test.adapter != "offline":
        raise Invalid("ONLY-RECORDED-OFFLINE-TESTS-REPRODUCIBLE-WITHOUT-FRESH-AUTHORIZATION")
    if plan.source_hash != source_hash():
        raise Invalid("REPRODUCTION-SOURCE-MISMATCH")
    # Preserve the recorded test definition; repetitions run complete original cases.
    from p007.regression import compare
    from p007.catalog import verify_plan

    raw = plan.model_dump(mode="json", exclude={"plan_id", "digest"})
    raw["tests"] = [test.model_dump(mode="json")]
    raw["request_estimate"] = test.limits.requests * test.repetitions
    checksum = digest(raw)
    selected = ExecutionPlan.model_validate({**raw, "plan_id": "plan-" + checksum[:24], "digest": checksum})
    verify_plan(selected)
    reruns = []
    expected = next(r for r in previous.results if r.test_id == test.test_id)
    for _ in range(request.repetitions):
        rerun = run(selected, root=folder.parent, retest_of=previous.run_id)
        actual = verify(rerun).results[0]
        reruns.append(
            {
                "run_id": rerun.name,
                "consistent": actual.status == expected.status
                and actual.observed == expected.observed
                and actual.runner.samples == expected.runner.samples,
                "comparison": compare(previous, verify(rerun)).model_dump(mode="json"),
            }
        )
    return {"status": "PASS" if all(r["consistent"] for r in reruns) else "FLAKY", "runs": reruns}
