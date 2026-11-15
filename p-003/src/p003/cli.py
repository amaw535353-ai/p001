"""JSON CLI. Exit 0 success, 2 invalid/unavailable, 3 denied. No target interaction."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys

import yaml

from p003 import NOTICE, __version__
from p003 import adapters, demo, exports, frameworks, redmine
from p003.models import Engagement, verified
from p003.store import Store
from p003.util import ROOT, load, now, safe, write_output


def parser():
    p = argparse.ArgumentParser(description=NOTICE)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--store", type=Path, default=ROOT / ".runtime/store")
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("demo").add_subparsers(dest="operation", required=True)
    d.add_parser("init").add_argument("--seed", type=int, default=42)
    e = sub.add_parser("engagement").add_subparsers(dest="operation", required=True)
    e.add_parser("list").add_argument("--actor", required=True)
    show = e.add_parser("show")
    show.add_argument("--id", required=True)
    show.add_argument("--actor", required=True)
    e.add_parser("validate").add_argument("--file", type=Path, required=True)
    create = e.add_parser("create")
    create.add_argument("--file", type=Path, required=True)
    for name in ("submit", "approve", "activate", "amend", "suspend", "revoke", "close", "expire", "reject"):
        item = e.add_parser(name)
        item.add_argument("--id", required=True)
        item.add_argument("--actor", required=True)
        item.add_argument("--version", type=int, required=True)
        item.add_argument("--at", default=None)
        item.add_argument("--reason", required=True)
        if name == "approve":
            item.add_argument("--simulate-review", action="store_true")
            item.add_argument("--evidence-ref", required=True)
            item.add_argument("--scope-digest", required=True)
        if name == "amend":
            item.add_argument("--file", type=Path, required=True)
    sc = sub.add_parser("scope").add_subparsers(dest="operation", required=True)
    diff = sc.add_parser("diff")
    diff.add_argument("--old", type=Path, required=True)
    diff.add_argument("--new", type=Path, required=True)
    ev = sc.add_parser("evaluate")
    ev.add_argument(
        "--request", type=Path, required=True, help="Complete request with explicit context and budgets"
    )
    for name in ("id", "actor", "target", "test-class", "at"):
        ev.add_argument("--" + name)
    evidence = sub.add_parser("evidence").add_subparsers(dest="operation", required=True)
    man = evidence.add_parser("manifest")
    man.add_argument("--id", required=True)
    man.add_argument("--actor", required=True)
    ex = sub.add_parser("export").add_subparsers(dest="operation", required=True)
    for name in ("markdown", "policy", "oscal"):
        item = ex.add_parser(name)
        item.add_argument("--id", required=True)
        item.add_argument("--actor", required=True)
        item.add_argument("--output", type=Path, required=True)
    ais = sub.add_parser("aisvs").add_subparsers(dest="operation", required=True)
    ais.add_parser("list")
    ais.add_parser("show").add_argument("--id", required=True)
    imp = sub.add_parser("import").add_subparsers(dest="operation", required=True)
    imp.add_parser("p001").add_argument("--root", type=Path, default=ROOT.parent)
    p2 = imp.add_parser("p002")
    p2.add_argument("--root", type=Path, default=ROOT.parent / "p-002")
    p2.add_argument("--dataset", type=Path, default=ROOT.parent / "p-002/generated/standard")
    red = sub.add_parser("redmine").add_subparsers(dest="operation", required=True)
    own = red.add_parser("ownership-init")
    own.add_argument("--confirm", required=True)
    own.add_argument("--target", choices=["lab"], required=True)
    sync = red.add_parser("sync")
    sync.add_argument("--id", required=True)
    sync.add_argument("--actor", required=True)
    sync.add_argument("--target", choices=["lab"], required=True)
    mode = sync.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--write", action="store_true")
    sync.add_argument("--confirm")
    reset = sub.add_parser("reset")
    reset.add_argument("--confirm", required=True)
    test = sub.add_parser("test")
    test.add_argument("--offline", action="store_true", required=True)
    return p


def run(args):
    if args.command == "engagement" and args.operation == "validate":
        spec = Engagement.model_validate(load(args.file))
        verified(spec)
        return {"status": "VALID", "policy_digest": spec.content_digest}, 0
    if args.command == "scope" and args.operation == "diff":
        old = Engagement.model_validate(load(args.old))
        new = Engagement.model_validate(load(args.new))
        verified(old)
        verified(new)
        return {
            "old_digest": old.content_digest,
            "new_digest": new.content_digest,
            "changed_fields": [k for k in type(old).model_fields if getattr(old, k) != getattr(new, k)],
            "authorization": "NEW VERSION AND FRESH APPROVAL REQUIRED",
        }, 0
    if args.command == "aisvs":
        registry = frameworks.catalog()
        return (list(registry.values()) if args.operation == "list" else registry[args.id]), 0
    if args.command == "import":
        return (
            adapters.p001_inventory(args.root)
            if args.operation == "p001"
            else adapters.p002_inventory(args.root, args.dataset)
        ), 0
    if args.command == "test":
        from p003.verification import verify

        report = verify()
        return report, report["exit_code"]
    store = Store(
        args.store,
        create=args.command == "demo" or (args.command == "engagement" and args.operation == "create"),
    )
    if args.command == "demo":
        return demo.init(store, args.seed), 0
    if args.command == "reset":
        return {"status": "ARCHIVED-OWNED-STORE", "archive": store.reset(args.confirm)}, 0
    if args.command == "engagement":
        if args.operation == "create":
            spec = Engagement.model_validate(load(args.file))
            verified(spec)
            view = store.create(spec)
        elif args.operation == "list":
            return [
                {"id": v.spec.engagement_id, "version": v.current, "status": v.state}
                for v in store.list_for(args.actor)
            ], 0
        elif args.operation == "show":
            view = store.read(args.id, args.actor)
            return {
                "engagement": view.spec.model_dump(mode="json"),
                "status": view.state,
                "version_states": view.states,
                "ledger_head": view.events[-1].content_digest,
            }, 0
        else:
            mapped = {"suspend": "SUSPENDED", "revoke": "REVOKED", "close": "CLOSED", "expire": "EXPIRED"}
            kind = "stop" if args.operation in mapped else args.operation
            view = store.transition(
                args.id,
                args.actor,
                kind,
                version=args.version,
                at=args.at or now(),
                purpose=args.reason,
                evidence_ref=getattr(args, "evidence_ref", None),
                simulate_review=getattr(args, "simulate_review", False),
                expected_digest=getattr(args, "scope_digest", None),
                spec=Engagement.model_validate(load(args.file)) if kind == "amend" else None,
                stop_status=mapped.get(args.operation),
            )
        return {
            "id": view.spec.engagement_id,
            "version": view.current,
            "status": view.state,
            "policy_digest": view.spec.content_digest,
            "ledger_head": view.events[-1].content_digest,
        }, 0
    if args.command == "scope":
        request = load(args.request)
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        for name, field in [
            ("id", "engagement_id"),
            ("actor", "actor"),
            ("test_class", "test_class"),
            ("at", "at"),
        ]:
            if getattr(args, name):
                request[field] = getattr(args, name)
        if args.target:
            request["target"] = {"kind": "url", "value": args.target}
        result = store.check(request)
        return result.model_dump(mode="json"), 0 if result.decision == "ALLOW" else 3
    if args.command == "redmine" and args.operation == "ownership-init":
        value = redmine.initialize_ownership(store.path / "redmine-ownership.json", args.confirm)
        return {"status": "OWNERSHIP-MANIFEST-CREATED", "project": value["project"]}, 0
    view = store.read(args.id, args.actor)
    if args.command == "evidence":
        return exports.evidence_manifest(view), 0
    if args.command == "redmine":
        return redmine.sync(
            redmine.milestone_items(view),
            store.path / "redmine-ownership.json",
            write=args.write,
            confirm=args.confirm,
        ), 0
    if args.command == "export":
        value = (
            exports.markdown(view)
            if args.operation == "markdown"
            else exports.policy_manifest(view)
            if args.operation == "policy"
            else frameworks.oscal_draft(view.spec)
        )
        write_output(args.output, value)
        return {
            "status": "EXPORTED",
            "format": args.operation,
            "output": str(args.output),
            "conformance": "NOT VALID OSCAL" if args.operation == "oscal" else "p003 artifact",
        }, 0
    raise ValueError("unsupported command")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        value, code = run(args)
        safe(value)
        print(json.dumps({"notice": NOTICE, "result": value}, indent=2, ensure_ascii=False))
        return code
    except (ValueError, OSError, KeyError, TypeError, yaml.YAMLError, RecursionError, sqlite3.Error):
        # Validation exceptions can contain the original unsafe input; never echo them.
        print(
            json.dumps(
                {
                    "notice": NOTICE,
                    "error": "INVALID-OR-UNAVAILABLE",
                    "detail": "Operation refused. Check schema, role, version, ownership and prerequisites; input values omitted.",
                }
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
