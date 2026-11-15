"""Owned run artifacts and integrity verification; imported paths never become outputs."""

from datetime import datetime, timezone
from pathlib import Path
import platform
import importlib.metadata

from p005 import NOTICE, __version__
from p005.adapters.status import statuses
from p005.catalogs.atlas import mapping
from p005.evidence.safety import DATA, PROJECT, Invalid, canonical, digest, load, read, redact, write
from p005.export.diagrams import render
from p005.export.reports import gaps, report
from p005.ingestion.fixtures import read_model
from p005.modeling.review import records
from p005.modeling.rule_engine import validate_analysis

OWNER = b'{"owner":"p005-offline-v1"}\n'


def owned(run: Path) -> None:
    if read(run / ".p005-owned.json") != OWNER:
        raise Invalid("RUN-OWNERSHIP-REQUIRED")


def initialize(run: Path, model) -> None:
    if run.exists():
        owned(run)
        if digest(read_model(run / "model.json").model_dump()) != digest(model.model_dump()):
            raise Invalid("RUN-MODEL-MISMATCH: choose a fresh owned run")
        write(run / "model.json", canonical(model.model_dump()))
        return
    write(run / ".p005-owned.json", OWNER, replace=False)
    write(run / "model.json", canonical(model.model_dump()))
    write(run / "review-log.jsonl", b"")


def json_file(run, name, data) -> None:
    write(run / name, canonical(redact(data)))


def export_run(run: Path, model, analysis: dict) -> dict:
    initialize(run, model)
    validate_analysis(model, analysis)
    for attr, name in [
        ("nodes", "assets"),
        ("zones", "trust-zones"),
        ("flows", "flows"),
        ("boundaries", "trust-boundaries"),
    ]:
        json_file(run, name + ".json", [x.model_dump() for x in getattr(model, attr)])
    json_file(
        run,
        "actors.json",
        [n.model_dump() for n in model.nodes if n.kind in ("Actor", "HumanIdentity", "WorkloadIdentity")],
    )
    for key, name in [
        ("threats", "threats"),
        ("attack_paths", "attack-paths"),
        ("controls", "controls"),
        ("mitigations", "mitigations"),
        ("verification_plan", "verification-plan"),
    ]:
        json_file(run, name + ".json", analysis[key])
    json_file(run, "analysis.json", analysis)
    json_file(
        run,
        "risk-traceability.json",
        dict(
            schema_version="p005-traceability-1.0",
            taxonomy=load(DATA / "risks.json"),
            applicability=analysis["risk_applicability"],
            links=[
                dict(
                    threat_id=t["threat_id"],
                    risks=t["risk_ids"],
                    nodes=t["node_ids"],
                    edges=t["edge_ids"],
                    controls=t["control_ids"],
                    tests=t["test_ids"],
                    evidence=t["evidence_refs"],
                )
                for t in analysis["threats"]
            ],
        ),
    )
    json_file(
        run,
        "rule-trace.json",
        dict(fired=[t["rule_trace"] for t in analysis["threats"]], suppressed=analysis["suppressions"]),
    )
    json_file(run, "atlas-mapping.json", mapping(analysis["threats"]))
    json_file(run, "adapter-status.json", statuses(analysis["model_digest"]))
    missing = [
        dict(
            project=p,
            status="NOT_TESTED",
            evidence_refs=[],
            reason="Not used by this run; offline fixture is independent",
        )
        for p in ("P-001", "P-002", "P-003", "P-004")
        if p not in {i.project for i in model.integrations}
    ]
    json_file(run, "integration-status.json", [i.model_dump() for i in model.integrations] + missing)
    write(run / "diagrams/architecture.mmd", render(model).encode())
    write(run / "diagrams/trust-boundaries.mmd", render(model, boundaries_only=True).encode())
    write(run / "diagrams/architecture.dot", render(model, "dot").encode())
    write(run / "reports/threat-model.md", redact(report(model, analysis, records(run))).encode())
    write(run / "reports/assumptions-and-gaps.md", gaps(model).encode())
    write(
        run / "reports/changes.md",
        ("# Changes\n\nNo prior model supplied. Use p005 diff for versioned comparison.\n").encode(),
    )
    write(
        run / "reports/assessment-handover.md",
        (
            "# Assessment handover\n\n" + NOTICE + "\n\n"
            "Consumers P-006/P-007/P-009/P-010/P-083: use versioned JSON and manifest hashes.\n"
            "No executable queue. Accept hypotheses independently and obtain fresh P-003 authorization.\n"
            "Reviewer: __________\nAssessor: __________\nG1-G4: UNVERIFIED\n"
        ).encode(),
    )
    return manifest(run)


def files(run: Path) -> list[Path]:
    owned(run)
    found = []
    for count, path in enumerate(run.rglob("*")):
        if count > 160:
            raise Invalid("RUN-ENTRY-BUDGET")
        if path.is_symlink():
            raise Invalid("SYMLINK-IN-RUN")
        if path.is_file() and path.name != "run-manifest.json":
            found.append(path)
        if len(found) > 128:
            raise Invalid("RUN-FILE-BUDGET")
    return sorted(found)


def manifest(run: Path) -> dict:
    model = read_model(run / "model.json")
    analysis = load(run / "analysis.json")
    validate_analysis(model, analysis)
    for key, name in [
        ("threats", "threats"),
        ("attack_paths", "attack-paths"),
        ("controls", "controls"),
        ("mitigations", "mitigations"),
        ("verification_plan", "verification-plan"),
    ]:
        if load(run / (name + ".json")) != redact(analysis[key]):
            raise Invalid("RUN-DERIVED-ARTIFACT-MISMATCH")
    hashes = {}
    for path in files(run):
        raw = read(path)
        if redact(raw.decode("utf-8")) != raw.decode("utf-8"):
            raise Invalid("UNSANITIZED-OUTPUT: publication blocked")
        hashes[str(path.relative_to(run))] = digest(raw)
    result = dict(
        schema_version="p005-manifest-1.0",
        notice=NOTICE,
        files=hashes,
        content_root_sha256=digest(hashes),
        model_digest=digest(model.model_dump()),
        source_snapshot_hash=model.source_snapshot_hash,
        source_refs=[e.model_dump() for e in model.evidence],
        run_clock_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        tool_versions={
            "p005": __version__,
            "python": platform.python_version(),
            **{p: importlib.metadata.version(p) for p in ("pydantic", "PyYAML", "jsonschema")},
        },
        environment=model.environment_id,
        seed=model.dataset_seed,
        rules_sha256=digest(read(DATA / "rules.json")),
        risk_catalog_sha256=digest(read(DATA / "risks.json")),
        dependency_lock_sha256=digest(read(PROJECT / "requirements.lock")),
        sanitizer=dict(
            status="PASS",
            method="Pattern redaction before public hashes; no guarantee of arbitrary secret detection",
        ),
        target_test_status="NOT_TESTED",
        engineering_tests="See evidence/engineering/manifest.json; separate from target tests",
        limitations=["Full taxonomy source BLOCKED", "Native tool adapters BLOCKED", "No real assessment"],
        git_commit=model.git_commit,
    )
    json_file(run, "run-manifest.json", result)
    return result


def verify_manifest(run: Path) -> dict:
    saved = load(run / "run-manifest.json")
    actual = {str(p.relative_to(run)): digest(read(p)) for p in files(run)}
    if actual != saved["files"] or digest(actual) != saved["content_root_sha256"]:
        raise Invalid("RUN-INTEGRITY-MISMATCH")
    return dict(
        status="PASS",
        files=len(actual),
        authenticity="NOT_ASSERTED: hashes detect changes, not malicious re-signing",
    )
