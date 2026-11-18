"""Local operator commands for P-010."""

import argparse
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from p010 import atlas, langfuse, oscal, redmine, reports, retention
from p010.models import (
    RECORDS,
    AcceptanceInput,
    AtlasInput,
    Engagement,
    Evidence,
    Finding,
    Link,
    ObservationDraft,
    RemediationInput,
    ReportNarrative,
    RetestInput,
    RetestPlanInput,
    RiskInput,
    SeverityInput,
    SourceRecord,
    TraceReference,
    Validation,
)
from p010.safety import ROOT, Invalid, canonical, digest, load, read, relative_parts
from p010.sources import PROJECTS, import_file
from p010.store import Workspace, validate
from p010.workflow import Workflow, register_engagement, rubric, suggest

_DISPOSITIONS = (
    "CONFIRMED",
    "INCONCLUSIVE",
    "NOT_REPRODUCIBLE",
    "FALSE_POSITIVE",
    "OUT_OF_SCOPE",
    "BLOCKED",
    "NOT_TESTED",
    "WITHDRAWN",
)


def _path(value: str) -> Path:
    # Explicit operator input paths can use shell-relative syntax. Indirect artifact paths cannot.
    return Path(os.path.abspath(value))


def _args(parser, *, id_: bool = False, file: bool = False, reason: bool = False, authored: bool = True):
    if id_:
        parser.add_argument("--id", required=True)
    if file:
        parser.add_argument("--file", required=True, type=_path)
    if reason:
        why = parser.add_mutually_exclusive_group(required=True)
        why.add_argument("--rationale")
        why.add_argument("--rationale-file", type=_path)
        if authored:
            parser.add_argument(
                "--authorship", required=True, choices=("HUMAN_AUTHORED", "AI_ASSISTED", "TRAINING_FIXTURE")
            )
    return parser


def _group(root, name: str):
    return root.add_parser(name).add_subparsers(dest="action", required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="p010", description="Synthetic findings, risk and consultancy reporting"
    )
    root.add_argument("--workspace", help="Name of a private P-010 workspace")
    root.add_argument("--engagement", help="Synthetic engagement ID")
    root.add_argument("--actor", help="Role reference from the engagement manifest")
    use = root.add_subparsers(dest="command", required=True)
    use.add_parser("doctor")
    use.add_parser("rubric")
    demo = use.add_parser("demo")
    for name in ("p008", "p009", "events"):
        demo.add_argument("--" + name, type=_path)
    _args(use.add_parser("init"), file=True)

    source = _group(use, "source")
    for op in ("validate", "import"):
        sub = _args(source.add_parser(op), file=True)
        sub.add_argument("project", choices=sorted(PROJECTS))
        sub.add_argument("--flavor", choices=("threats", "verification", "reviews"))
        sub.add_argument("--run-root", type=_path)
        sub.add_argument("--events", type=_path)
    source.add_parser("list")
    records = _group(use, "record")
    show = _args(records.add_parser("show"), id_=True)
    show.add_argument("kind", choices=RECORDS)
    show.add_argument("--version", type=int)
    listing = records.add_parser("list")
    listing.add_argument("--kind", choices=RECORDS)
    listing.add_argument("--history", action="store_true")

    observation = _group(use, "observation")
    _args(observation.add_parser("draft"), id_=True, file=True)
    _args(observation.add_parser("submit"), id_=True)
    review = _args(observation.add_parser("review"), id_=True, reason=True)
    review.add_argument("--decision", required=True, choices=_DISPOSITIONS)
    review.add_argument("--finding")
    review.add_argument("--file", type=_path)

    evidence = _group(use, "evidence")
    link = _args(evidence.add_parser("link"), id_=True)
    link.add_argument("--source", required=True, help="P-010 source ID")
    link.add_argument("--source-item", required=True, help="Exact upstream record or test ID")
    link.add_argument("--artifact")
    link.add_argument("--excerpt-file", type=_path)
    _args(evidence.add_parser("verify"), id_=True).add_argument("--run-root", type=_path)

    finding = _group(use, "finding")
    for op in ("severity", "withdraw", "close", "validate"):
        _args(finding.add_parser(op), id_=True, file=op == "severity", reason=op != "validate")
    risk = _group(use, "risk")
    for op in ("set", "accept"):
        _args(risk.add_parser(op), id_=True, file=True, reason=True)
    _args(risk.add_parser("suggest"), file=True).add_argument(
        "--evidence-quality",
        required=True,
        choices=("UNKNOWN", "INSUFFICIENT", "LIMITED", "CORROBORATED"),
    )
    remediation = _group(use, "remediation")
    _args(remediation.add_parser("plan"), id_=True, file=True, reason=True).add_argument(
        "--finding", required=True
    )
    _args(remediation.add_parser("implemented"), id_=True, reason=True)
    retests = _group(use, "retest")
    for operation in ("plan", "record"):
        _args(retests.add_parser(operation), id_=True, file=True, reason=True).add_argument(
            "--finding", required=True
        )

    atlas_cli = _group(use, "atlas")
    atlas_cli.add_parser("lookup").add_argument("technique")
    _args(atlas_cli.add_parser("map"), id_=True, file=True, reason=True).add_argument(
        "--finding", required=True
    )
    report = _group(use, "report")
    for op in ("build", "preview", "review", "approve", "verify", "export", "handoff"):
        sub = _args(
            report.add_parser(op),
            id_=True,
            file=op == "build",
            reason=op in {"build", "review", "approve"},
            authored=op != "build",
        )
        if op in {"review", "approve"}:
            sub.add_argument("--sha256", required=True, help="Digest of the reviewed report version")
        elif op != "build":
            sub.add_argument("--version", type=int)
        if op == "verify":
            sub.add_argument("--directory", type=_path)

    oscal_cli = _group(use, "oscal")
    _args(oscal_cli.add_parser("export"), id_=True).add_argument("--context", type=_path)
    check_oscal = _args(oscal_cli.add_parser("validate"), file=True)
    check_oscal.add_argument("model", choices=sorted(oscal.PIN))
    check_oscal.add_argument("--context", type=_path)
    redmine_cli = _group(use, "redmine")
    redmine_cli.add_parser("up")
    redmine_cli.add_parser("down").add_argument("--confirm", required=True)
    sync = redmine_cli.add_parser("sync")
    sync.add_argument("--finding", required=True)
    sync.add_argument("--project", default=redmine.PROJECT)
    sync.add_argument("--confirm-local-write")
    trace = _group(use, "langfuse").add_parser("show")
    pick = trace.add_mutually_exclusive_group(required=True)
    pick.add_argument("--file", type=_path)
    pick.add_argument("--source")
    trace.add_argument("--event")
    trace.add_argument("--project-ref")
    trace.add_argument("--binding", type=_path)
    trace.add_argument("--local-port", type=int)
    trace.add_argument("--record-id", help="Persist a minimized trace source reference")
    _group(use, "audit").add_parser("verify")
    retain = _group(use, "retention")
    retain.add_parser("audit")
    purge = retain.add_parser("purge")
    purge.add_argument("--plan-sha256", required=True)
    purge.add_argument("--confirm", required=True)
    return root


def _reason(args) -> str:
    if args.rationale_file:
        raw = read(args.rationale_file, limit=8192)
        assert raw is not None
        return raw.decode()
    return args.rationale


def _workspace(name: str | None) -> Workspace:
    if not name or len(relative_parts(name)) != 1:
        raise Invalid("Select a P-010 workspace by name")
    runtime = ROOT / ".runtime"
    rooms = runtime / "workspaces"
    for current in (runtime, rooms):
        if current.is_symlink():
            raise Invalid("Workspace symlinks are refused")
        current.mkdir(mode=0o700, exist_ok=True)
    return Workspace(rooms / name)


def _source(args):
    return import_file(
        args.project, args.file, flavor=args.flavor, run_root=args.run_root, events=args.events
    )


def _list(flow, kind, history=False):
    found = [
        row
        for row in flow.store.versions(flow.id, current=not history)
        if kind is None or row.link.kind == kind
    ]
    flow.audit("record-list", "Listed local record versions")
    return found


def _record(flow, args):
    if args.action == "list":
        return [row.link.model_dump(mode="json") for row in _list(flow, args.kind, args.history)]
    found = (
        flow.store.get(args.kind, args.id, args.version, flow.id)
        if args.version is not None
        else flow.current(args.kind, args.id)
    )
    flow.audit("record-access", "Read a scoped local record version", [found.link])
    return found.export()


def _report(flow, workspace, args):
    op = args.action
    if op == "build":
        return reports.build(
            flow, args.id, validate(ReportNarrative, load(args.file)), _reason(args)
        ).export()
    if op in {"review", "approve"}:
        current = flow.current("report", args.id)
        expected = validate(Link, {**current.link.model_dump(), "sha256": args.sha256})
        return reports.review(
            flow, args.id, _reason(args), args.authorship, approve=op == "approve", expected=expected
        ).export()
    version = (
        flow.store.get("report", args.id, args.version, flow.id)
        if args.version is not None
        else flow.current("report", args.id)
    )
    if op == "preview":
        flow.audit("report-preview", "Rendered a local report preview", [version.link])
        return reports.files(flow, version)["assessment.md"].decode()
    if op == "verify":
        checked = reports.verify(flow, version, args.directory)
        flow.audit("report-verify", "Verified report and source versions", [version.link])
        return checked
    if op == "export":
        target = reports.export(flow, version, workspace.root)
        return {"directory": str(target), **reports.verify(flow, version, target)}
    return reports.handoff(flow, version).model_dump(mode="json")


def _evidence(flow, args):
    if args.action == "link":
        source = flow.current("source", args.source)
        raw = read(args.excerpt_file, limit=4096) if args.excerpt_file else None
        return flow.make_evidence(
            args.id, source.link, args.source_item, args.artifact, excerpt=raw.decode() if raw else None
        ).export()
    ref = flow.current("evidence", args.id)
    value = ref.as_type(Evidence)
    source = flow.resolve(value.source).as_type(SourceRecord)
    rechecked = False
    if args.run_root:
        if source.project != "P-007" or not value.source_artifact_ref:
            raise Invalid("This evidence reference is outside the P-007 run-root verifier")
        path = args.run_root.joinpath(*relative_parts(value.source_artifact_ref))
        if args.run_root.name != source.source_record_id or load(args.run_root / "owner.json") != {
            "owner": "p007",
            "run_id": source.source_record_id,
        }:
            raise Invalid("The selected P-007 run root does not own this evidence")
        declared = next(a for a in source.artifacts if a.path == value.source_artifact_ref)
        contents = read(path, limit=1_048_576, missing=True)
        if contents is not None and (
            digest(contents) != declared.declared_sha256 or len(contents) != declared.declared_size
        ):
            raise Invalid("Evidence bytes differ from the source digest or size")
        rechecked = contents is not None
    flow.audit("evidence-verify", "Verified an exact local evidence reference", [ref.link])
    return {
        "status": "UNAVAILABLE" if args.run_root and not rechecked else value.integrity_status,
        "rechecked_original": rechecked,
        "evidence": ref.export(),
    }


def _langfuse(flow, args):
    if args.file:
        ref = validate(TraceReference, load(args.file))
        if ref.source != "operator-provided":
            raise Invalid("A manually selected trace file must use operator-provided provenance")
    else:
        if not args.event or not args.project_ref:
            raise Invalid("Select the P-009 event and a local Langfuse project reference")
        ref = langfuse.from_event(flow, args.source, args.event, args.project_ref)
    binding = validate(langfuse.Binding, load(args.binding)) if args.binding else None
    result = langfuse.show(ref, port=args.local_port, binding=binding)
    if args.record_id:
        flow.require("AUTHOR", "CUSTODIAN")
        record = langfuse.source_record(args.record_id, ref, result, flow.at)
        result["source"] = flow.import_source(record).link.model_dump(mode="json")
    flow.audit("langfuse-reference", "Inspected metadata for a supporting trace reference")
    return result


def _workflow(flow, workspace, args, loaded_source):
    command, op = args.command, getattr(args, "action", None)
    if command == "source":
        return (
            flow.import_source(loaded_source).export()
            if loaded_source is not None
            else [row.export() for row in _list(flow, "source")]
        )
    if command == "record":
        return _record(flow, args)
    if command == "observation":
        if op == "draft":
            return flow.observation(args.id, validate(ObservationDraft, load(args.file))).export()
        if op == "submit":
            return flow.submit(args.id).export()
        validation = validate(Validation, load(args.file)) if args.file else None
        return flow.review_observation(
            args.id,
            args.decision,
            _reason(args),
            args.authorship,
            validation=validation,
            finding_id=args.finding,
        ).export()
    if command == "evidence":
        return _evidence(flow, args)
    if command == "finding":
        if op == "validate":
            version = flow.current("finding", args.id)
            finding = version.as_type(Finding)
            flow.resolve(finding.observation)
            for link in finding.validation.inspected_evidence:
                flow.resolve(link)
            flow.store.verify()
            flow.audit(
                "finding-validate", "Verified the finding and inspected evidence links", [version.link]
            )
            return {
                "status": finding.validation_status,
                "integrity": "PASS",
                "finding": version.link.model_dump(),
            }
        if op == "severity":
            return flow.severity(
                args.id, validate(SeverityInput, load(args.file)), _reason(args), args.authorship
            ).export()
        action = flow.withdraw if op == "withdraw" else flow.close
        return action(args.id, _reason(args), args.authorship).export()
    if command == "risk":
        action, model = (flow.risk, RiskInput) if op == "set" else (flow.accept, AcceptanceInput)
        return action(args.id, validate(model, load(args.file)), _reason(args), args.authorship).export()
    if command == "remediation":
        if op == "plan":
            return flow.remediation(
                args.id,
                args.finding,
                validate(RemediationInput, load(args.file)),
                _reason(args),
                args.authorship,
            ).export()
        return flow.implemented(args.id, _reason(args), args.authorship).export()
    if command == "retest":
        if op == "plan":
            return flow.retest_plan(
                args.id,
                args.finding,
                validate(RetestPlanInput, load(args.file)),
                _reason(args),
                args.authorship,
            ).export()
        return flow.retest(
            args.id,
            args.finding,
            validate(RetestInput, load(args.file)),
            _reason(args),
            args.authorship,
        ).export()
    if command == "atlas":
        return atlas.record(
            flow, args.id, args.finding, validate(AtlasInput, load(args.file)), _reason(args), args.authorship
        ).export()
    if command == "report":
        return _report(flow, workspace, args)
    if command == "oscal":
        version = flow.current("report", args.id)
        result = oscal.export(flow, version, args.context)
        flow.audit("oscal-export", "Generated a local OSCAL validation result or mapping", [version.link])
        return result
    if command == "redmine":
        return redmine.preview(flow, args.finding)
    if command == "langfuse":
        return _langfuse(flow, args)
    if command == "retention":
        return (
            retention.purge(flow, args.plan_sha256, args.confirm) if op == "purge" else retention.plan(flow)
        )
    raise Invalid("Unsupported command")


def _with_workspace(args):
    workspace = _workspace(args.workspace)
    if args.command == "audit":
        with workspace.session() as store:
            return store.verify()
    if not (args.engagement and args.actor):
        raise Invalid("An engagement ID and an operator reference are required")
    if args.command == "init":
        value = validate(Engagement, load(args.file))
        workspace.init()
        with workspace.session() as store:
            return register_engagement(store, args.engagement, value, args.actor).export()
    if args.command == "redmine" and args.confirm_local_write:
        return redmine.synchronize(
            workspace,
            args.engagement,
            args.actor,
            args.finding,
            confirmation=args.confirm_local_write,
            project=args.project,
        )
    loaded_source = _source(args) if args.command == "source" and args.action == "import" else None
    with workspace.session() as store:
        flow = Workflow(store, args.engagement, args.actor)
        return _workflow(flow, workspace, args, loaded_source)


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    result: Any
    try:
        if args.command == "doctor":
            result = {
                "python": sys.version.split()[0],
                "offline": "AVAILABLE",
                "redmine_host": redmine.doctor(),
                "langfuse": "REFERENCE_ONLY",
                "project": "P-010",
            }
        elif args.command == "rubric":
            result = rubric()
        elif args.command == "demo":
            from p010.demo import run

            result = run(
                _workspace(args.workspace or "demo-" + uuid4().hex[:12]),
                p008=args.p008,
                p009=args.p009,
                events=args.events,
            )
        elif args.command == "source" and args.action == "validate":
            result = _source(args).model_dump(mode="json")
        elif args.command == "atlas" and args.action == "lookup":
            match = atlas.techniques().get(args.technique)
            result = {
                "status": "PINNED" if match else "UNRESOLVED_HISTORICAL",
                "catalog": atlas.CATALOG_VERSION,
                "commit": atlas.CATALOG_COMMIT,
                "sha256": atlas.CATALOG_SHA256,
                "technique": {key: match[key] for key in ("id", "title", "url")} if match else None,
            }
        elif args.command == "oscal" and args.action == "validate":
            result = oscal.validate_file(args.model, args.file, args.context)
        elif args.command == "redmine" and args.action in {"up", "down"}:
            result = redmine.up() if args.action == "up" else redmine.down(args.confirm)
        elif args.command == "risk" and args.action == "suggest":
            score = suggest(validate(SeverityInput, load(args.file)), args.evidence_quality)
            result = {
                "suggested_severity": score,
                "status": "REVIEW_REQUIRED",
                "rubric_sha256": rubric()["sha256"],
            }
        else:
            result = _with_workspace(args)
        print(result, end="") if isinstance(result, str) else print(canonical(result).decode())
        if (
            isinstance(result, dict)
            and result.get("kind") == "oscal-validation"
            and result.get("conformance") == "NOT VALID OSCAL"
        ):
            return 2
        return 0
    except Invalid as error:
        print(str(error), file=sys.stderr)
    except (OSError, TypeError, ValueError, KeyError, sqlite3.DatabaseError, ValidationError):
        print("Invalid input or unavailable local resource", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
