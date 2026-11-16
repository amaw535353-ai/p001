"""Catalog ingestion and stable execution plans with complete input snapshots."""

from pathlib import Path

from p007.models import Catalog, ExecutionPlan, Target
from p007.safety import PROJECT, Blocked, Invalid, digest, load, read_bytes


def source_hash() -> str:
    files = sorted(
        [p for p in (PROJECT / "src").rglob("*") if p.suffix in (".py", ".cjs")]
        + list((PROJECT / "config").glob("*.json"))
        + list(PROJECT.glob("requirements*.lock"))
        + [PROJECT / "tools/package-lock.json", PROJECT / "pyproject.toml"]
    )
    return digest({str(f.relative_to(PROJECT)): digest(read_bytes(f)) for f in files})


def catalog(path: Path | None = None) -> Catalog:
    return Catalog.model_validate(load(path or PROJECT / "catalog/catalog.json"))


def fixtures(variant: str = "baseline") -> dict:
    if variant not in ("baseline", "remediated", "regressed"):
        raise Invalid("UNKNOWN-FIXTURE-VARIANT")
    return load(PROJECT / "fixtures" / (variant + ".json"))


def plan(
    target_id="offline-demo",
    profile="offline",
    *,
    variant="baseline",
    test_id=None,
    target: Target | None = None,
) -> ExecutionPlan:
    data = catalog()
    registered = next((t for t in data.targets if t.target_id == target_id), None)
    if registered is None:
        raise Blocked("UNREGISTERED-TARGET")
    if target is not None and target.target_id != registered.target_id:
        raise Blocked("TARGET-BINDING-MISMATCH")
    selected = [
        t
        for t in data.tests
        if t.target_id == target_id and t.adapter == profile and (test_id is None or t.test_id == test_id)
    ]
    if not selected:
        raise Blocked("NO-APPLICABLE-TESTS-OR-UNSUPPORTED-CAPABILITY")
    effective = target or registered
    if target_id == "offline-demo":
        effective = effective.model_copy(
            update={
                "version": {"baseline": "offline-v1", "remediated": "offline-v2", "regressed": "offline-v3"}[
                    variant
                ]
            }
        )
    values = dict(
        schema_version="1.0",
        profile=profile,
        target=effective.model_dump(mode="json"),
        tests=[t.model_dump(mode="json") for t in selected],
        controls=[
            c.model_dump(mode="json")
            for c in data.controls
            if any(c.control_id in t.control_ids for t in selected)
        ],
        fixtures=fixtures(variant),
        source_hash=source_hash(),
        request_estimate=sum(t.limits.requests * t.repetitions for t in selected),
        limitations=["Synthetic finite fixtures; no claim of broad jailbreak resistance or vendor security"],
    )
    checksum = digest(values)
    return ExecutionPlan.model_validate(dict(plan_id="plan-" + checksum[:24], digest=checksum, **values))


def verify_plan(value: ExecutionPlan) -> None:
    raw = value.model_dump(mode="json", exclude={"plan_id", "digest"})
    if digest(raw) != value.digest or value.plan_id != "plan-" + value.digest[:24]:
        raise Invalid("PLAN-INTEGRITY")
