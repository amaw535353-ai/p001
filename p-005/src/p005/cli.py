"""All ordinary commands operate on local data. No live import command exists."""

import argparse
import importlib.metadata
import json
from pathlib import Path
import sys

from pydantic import ValidationError

from p005 import __version__
from p005.adapters.status import refuse_native, statuses
from p005.catalogs import atlas
from p005.evidence.safety import REPO, Invalid, canonical, load, redact, write
from p005.export.diagrams import render
from p005.export.reports import report
from p005.export.run import export_run, initialize, manifest, owned, verify_manifest
from p005.ingestion.fixtures import build, read_model
from p005.ingestion import predecessors
from p005.modeling.diff import compare
from p005.modeling.review import decide, records
from p005.modeling.rule_engine import analyze, validate_analysis


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="P-005 offline synthetic threat modeling; never executes attacks")
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor")
    model = commands.add_parser("model").add_subparsers(dest="action", required=True)
    b = model.add_parser("build")
    b.add_argument("--input", type=Path, required=True)
    b.add_argument("--source", choices=["fixture", "p001", "p002", "p004"], default="fixture")
    b.add_argument("--fallback-fixture", type=Path)
    b.add_argument("--context", type=Path, help="Actual sealed P-003 Engagement, static context only")
    b.add_argument("--out", type=Path, required=True)
    v = model.add_parser("validate")
    v.add_argument("--input", type=Path, required=True)
    a = commands.add_parser("analyze")
    a.add_argument("--model", type=Path, required=True)
    a.add_argument("--rules", type=Path)
    a.add_argument("--suppressions", type=Path, help="JSON rule_id -> nonempty reason")
    a.add_argument("--out", type=Path, required=True)
    graph = commands.add_parser("graph").add_subparsers(dest="action", required=True)
    r = graph.add_parser("render")
    r.add_argument("--model", type=Path, required=True)
    r.add_argument("--format", choices=["mermaid", "dot"], default="mermaid")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--boundaries-only", action="store_true")
    rep = commands.add_parser("report")
    rep.add_argument("--run", type=Path, required=True)
    rep.add_argument("--format", choices=["markdown"], default="markdown")
    diff = commands.add_parser("diff")
    diff.add_argument("--before", type=Path, required=True)
    diff.add_argument("--after", type=Path, required=True)
    diff.add_argument("--out", type=Path, required=True)
    test = commands.add_parser("tests").add_subparsers(dest="action", required=True)
    plan = test.add_parser("plan")
    plan.add_argument("--run", type=Path, required=True)
    plan.add_argument("--out", type=Path, required=True)
    plan.add_argument("--accepted-only", action="store_true")
    catalog = commands.add_parser("catalog").add_subparsers(dest="action", required=True)
    c = catalog.add_parser("validate")
    c.add_argument("--input", type=Path, required=True)
    catalog.add_parser("list")
    c = catalog.add_parser("update")
    c.add_argument("--from-local-file", type=Path, required=True)
    c.add_argument("--metadata", type=Path, required=True)
    c.add_argument("--out", type=Path, required=True)
    adapters = commands.add_parser("adapters").add_subparsers(dest="action", required=True)
    adapters.add_parser("status")
    c = adapters.add_parser("export")
    c.add_argument("--tool", choices=["threat-dragon", "pytm", "threagile"], required=True)
    c.add_argument("--model", type=Path, required=True)
    evidence = commands.add_parser("evidence").add_subparsers(dest="action", required=True)
    for name in ("manifest", "verify"):
        e = evidence.add_parser(name)
        e.add_argument("--run", type=Path, required=True)
    review = commands.add_parser("review").add_subparsers(dest="action", required=True)
    r = review.add_parser("decide")
    r.add_argument("--run", type=Path, required=True)
    r.add_argument("--threat", required=True)
    r.add_argument(
        "--decision",
        required=True,
        choices=["ACCEPTED_FOR_TESTING", "REJECTED_WITH_REASON", "NOT_APPLICABLE", "NEEDS_INFORMATION"],
    )
    r.add_argument("--reviewer-role", required=True)
    r.add_argument("--reason", required=True)
    r.add_argument("--at", required=True)
    r.add_argument("--priority", choices=["HIGH", "MEDIUM", "LOW"])
    r.add_argument("--simulate-review", action="store_true", required=True)
    return p


def doctor() -> dict:
    from p005.modeling.risk_catalog import catalog

    sources = {}
    for name, path in {
        "P-001": REPO / "infra/kubernetes/resources.json",
        "P-002": REPO / "p-002/schemas/dataset.schema.json",
        "P-003": REPO / "p-003/examples/engagement-draft-a.json",
        "P-004": REPO / "p-004/schemas/snapshot.schema.json",
    }.items():
        sources[name] = dict(
            present=path.is_file(), status="CONTRACT_ONLY" if path.is_file() else "NOT_TESTED"
        )
    return dict(
        status="PASS",
        workflow="OFFLINE_CORE",
        python=sys.version.split()[0],
        versions={p: importlib.metadata.version(p) for p in ("pydantic", "PyYAML", "jsonschema")},
        predecessor_contracts=sources,
        adapters=statuses(),
        risks=dict(status=catalog().source_status, authoritative_catalog="BLOCKED_MISSING_SOURCE"),
        atlas=dict(status="PINNED_OFFLINE", techniques=len(atlas.index()["techniques"])),
        execution="No target operations, URL fetching, LLM or native adapter execution",
    )


def run_data(run):
    owned(run)
    model = read_model(run / "model.json")
    result = load(run / "analysis.json")
    validate_analysis(model, result)
    return model, result


def execute(a):
    if a.command == "doctor":
        return doctor()
    if a.command == "model":
        if a.action == "validate":
            m = read_model(a.input)
            return dict(status="PASS", nodes=len(m.nodes), flows=len(m.flows))
        if a.source == "p004" and not a.input.exists() and a.fallback_fixture:
            m = build(a.fallback_fixture)
            data = m.model_dump()
            data["integrations"] = [
                dict(
                    project="P-004",
                    status="NOT_TESTED",
                    evidence_refs=[],
                    reason="Snapshot absent; using independent offline fixture",
                )
            ]
            m = type(m).model_validate(data)
        else:
            builder = build if a.source == "fixture" else getattr(predecessors, a.source)
            m = builder(a.input)
        if a.context:
            m = predecessors.p003_context(m, a.context)
        initialize(a.out, m)
        return dict(status="BUILT", nodes=len(m.nodes), flows=len(m.flows), boundaries=len(m.boundaries))
    if a.command == "analyze":
        m = read_model(a.model)
        result = analyze(m, rule_path=a.rules, suppressions=load(a.suppressions) if a.suppressions else None)
        export_run(a.out, m, result)
        return dict(status="PASS", threats=len(result["threats"]), classification="HYPOTHESES_ONLY")
    if a.command == "graph":
        write(a.out, render(read_model(a.model), a.format, a.boundaries_only).encode())
        return dict(status="RENDERED_TEXT", native_renderer_executed=False)
    if a.command == "report":
        m, result = run_data(a.run)
        write(a.run / "reports/threat-model.md", redact(report(m, result, records(a.run))).encode())
        manifest(a.run)
        return dict(status="PASS", report="reports/threat-model.md")
    if a.command == "diff":
        result = compare(read_model(a.before), read_model(a.after))
        write(a.out, canonical(result))
        return dict(status="PASS", review_state=result["review_state"], previous_decisions="INVALIDATED")
    if a.command == "tests":
        m, result = run_data(a.run)
        planned = result["verification_plan"]
        if a.accepted_only:
            latest = {
                r["threat_id"]: r for r in records(a.run) if r["model_digest"] == result["model_digest"]
            }
            planned = [
                t
                for t in planned
                if latest.get(t["threat_id"], {}).get("decision") == "ACCEPTED_FOR_TESTING"
                and t["scope_state"] != "OUT_OF_SCOPE"
            ]
        write(a.out, canonical(planned))
        return dict(status="NOT_TESTED", plans=len(planned), executed=0)
    if a.command == "catalog":
        if a.action == "validate":
            result = atlas.validate(a.input)
            return dict(
                status="PASS", content_version=result["content_version"], techniques=len(result["techniques"])
            )
        if a.action == "list":
            return atlas.index()
        return atlas.update_local(a.from_local_file, a.metadata, a.out)
    if a.command == "adapters":
        if a.action == "status":
            return dict(adapters=statuses())
        read_model(a.model)
        refuse_native()
    if a.command == "review":
        m, result = run_data(a.run)
        decision = decide(a.run, m, result, a.threat, a.decision, a.reviewer_role, a.reason, a.at, a.priority)
        write(a.run / "reports/threat-model.md", redact(report(m, result, records(a.run))).encode())
        manifest(a.run)
        return dict(
            status="RECORDED_SYNTHETIC_EDITORIAL_DECISION",
            sequence=decision["sequence"],
            target_authority=False,
        )
    if a.command == "evidence":
        return (
            verify_manifest(a.run)
            if a.action == "verify"
            else dict(status="PASS", files=len(manifest(a.run)["files"]))
        )
    raise Invalid("UNSUPPORTED-COMMAND")


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        result = execute(args)
        print(json.dumps(redact(result), sort_keys=True, ensure_ascii=True))
        return 0
    except ValidationError:
        print(
            json.dumps(
                dict(
                    status="ERROR",
                    code="SCHEMA-OR-SEMANTIC-VALIDATION-FAILED",
                    detail="Check schema_version, required fields, types, IDs, provenance and references",
                )
            ),
            file=sys.stderr,
        )
    except (Invalid, ValueError, KeyError, TypeError, OSError) as exc:
        # Never echo arbitrary imported content, exception paths or library text.
        detail = str(exc) if isinstance(exc, Invalid) else "INVALID-LOCAL-CONTRACT-OR-OPERATION"
        print(json.dumps(dict(status="ERROR", code=detail)), file=sys.stderr)
    return 2
