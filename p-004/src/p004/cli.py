"""Offline by default. Live HTTP is an explicit, fail-closed, local-only command."""

import argparse
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
from urllib.parse import urlsplit
from uuid import uuid4

from p004 import __version__
from p004.graph import Graph, diff
from p004.models import Context, Coverage, Source
from p004.parsers import inventory
from p004.policy import Denied, Guard, LiveContext, P003Adapter, read_owned, utc_now
from p004.reporting import memo, mermaid, read_snapshot, reset_owned, verify_run, versions, write_run
from p004.safety import Invalid, load
from p004.transport import GuardedHTTP


def git_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL, timeout=3
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return "UNVERIFIED"


def context(mode="offline", **kw):
    return Context(
        run_id="run-" + uuid4().hex, timestamp_utc=utc_now(), git_commit=git_commit(), mode=mode, **kw
    )


def observe(args):
    g = Graph(
        context("guarded-http", engagement_id=args.engagement, approved_engagement_version=args.version)
    )
    outcome = 0
    guard = None
    try:
        if args.profile != "safe-readonly" or not all(
            [args.store, args.context, args.owned, args.engagement, args.version]
        ):
            raise Denied("P003-CONTEXT-STORE-OWNERSHIP-AND-VERSION-REQUIRED")
        cfg_path = Path(args.context).absolute()
        cfg = LiveContext.model_validate(load(cfg_path.parent, cfg_path.name))
        if cfg.engagement_id != args.engagement or cfg.approved_engagement_version != args.version:
            raise Denied("ENGAGEMENT-VERSION-REPLAY")
        g.context.policy_digest = cfg.policy_digest
        owned = read_owned(Path(args.owned).absolute())
        adapter = P003Adapter(Path(args.store).absolute(), cfg)
        guard = Guard(adapter, owned, max_requests=args.max_requests, max_seconds=args.max_seconds)
        transport = GuardedHTTP(guard)
        for target in [args.target, *args.additional_target]:
            response = transport.request(target)
            decision = guard.decisions[-1]
            ref = Source(
                path="p003-ledger:" + cfg.engagement_id,
                sha256=cfg.policy_digest,
                pointer="decision:" + decision["decision_id"],
            )
            p = urlsplit(response["url"])
            origin = f"{p.scheme}://{p.netloc}"
            asset = g.asset(
                "local-fixture:" + owned.instance_id,
                "api-service",
                owned.tenant_id,
                ref,
                "guarded-http",
                label="Owned synthetic local fixture",
                address=origin,
                status="OBSERVED",
            )
            endpoint = g.endpoint(
                asset,
                p.path,
                response["method"],
                ref,
                "guarded-http",
                origin=origin,
                status="OBSERVED",
                response_codes=[response["status"]],
            )
            g.note(
                "OBSERVED",
                "request",
                "Guarded local HTTP metadata; response content discarded",
                [ref],
                [endpoint],
                response,
            )
        g.coverage.append(
            Coverage(
                source="guarded-http",
                target="explicit reviewed targets",
                status="discovered",
                known_denominator=1 + len(args.additional_target),
                processed=guard.used,
                reason="Fixed GET operations only; browser/unknown routes not explored",
            )
        )
    except (ValueError, TypeError, KeyError, OSError, ImportError) as exc:
        g.context.outcome = "PARTIAL" if guard and guard.used else "BLOCKED"
        g.note(
            "BLOCKED",
            "error",
            str(exc) if isinstance(exc, Invalid) else "LIVE-PREREQUISITE-OR-TRANSPORT-FAILED",
        )
        g.coverage.append(
            Coverage(
                source="guarded-http",
                target="explicit reviewed targets",
                status="blocked",
                known_denominator=1 + len(args.additional_target),
                processed=guard.used if guard else 0,
                reason="Fail-closed; no automatic resume or scope expansion",
            )
        )
        outcome = 3
    if guard:
        for decision in guard.decisions:
            g.note(
                "OBSERVED",
                "policy-decision",
                "Real P003 point-in-time governance ALLOW; not legal authority",
                details=decision,
            )
    result = write_run(
        g.snapshot(), Path(args.out).absolute(), ["p004", "observe-local", "private context paths omitted"]
    )
    result["exit_code"] = outcome
    return result, outcome


def doctor():
    base = Path(__file__).resolve().parents[2]
    return dict(
        p004=__version__,
        python=platform.python_version(),
        dependencies=versions(),
        p001="static source available"
        if (base.parent / "infra/kubernetes/resources.json").exists()
        else "NOT AVAILABLE",
        p002="real model available" if importlib.util.find_spec("p002") else "NOT AVAILABLE",
        p003="real engine available; approval not implied"
        if importlib.util.find_spec("p003")
        else "NOT AVAILABLE",
        playwright="BLOCKED: no independent egress sandbox",
        zap="NOT TESTED: contract/fixture only",
        onyx="NOT TESTED: no supplied local checkout",
        openhands="NOT TESTED: no supplied local checkout",
        kubernetes="BLOCKED: no reviewed namespace identity; host cgroup limitation",
        default_mode="offline; no network",
    )


def parser():
    p = argparse.ArgumentParser(
        prog="p004", description="Offline architecture inventory; no vulnerability conclusions"
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    scan = sub.add_parser("discover-offline")
    scan.add_argument("--root", required=True)
    scan.add_argument("--config", required=True, help="input config relative to --root")
    scan.add_argument("--out", required=True)
    scan.add_argument("--baseline")
    live = sub.add_parser("observe-local")
    live.add_argument("--engagement")
    live.add_argument("--version", type=int)
    live.add_argument("--target", required=True)
    live.add_argument("--additional-target", action="append", default=[])
    live.add_argument("--profile", default="safe-readonly")
    live.add_argument("--context")
    live.add_argument("--store")
    live.add_argument("--owned")
    live.add_argument("--max-requests", type=int, default=30)
    live.add_argument("--max-seconds", type=int, default=120)
    live.add_argument("--out", required=True)
    for name, format in [("inventory", "json"), ("graph", "mermaid"), ("report", "markdown")]:
        command = sub.add_parser(name)
        command.add_argument("--input" if name != "report" else "--run", dest="input", required=True)
        command.add_argument("--format", choices=[format], default=format)
    delta = sub.add_parser("diff")
    delta.add_argument("--before", required=True)
    delta.add_argument("--after", required=True)
    delta.add_argument("--out", required=True, help="new JSON file; existing files are never overwritten")
    correlation = sub.add_parser("correlate")
    correlation.add_argument("--declared", required=True)
    correlation.add_argument("--observed", required=True)
    correlation.add_argument("--mapping", help="reviewed JSON object: observed asset ID -> declared asset ID")
    correlation.add_argument("--out", required=True)
    check = sub.add_parser("verify-artifacts")
    check.add_argument("--input", required=True)
    reset = sub.add_parser("reset-owned")
    reset.add_argument("--input", required=True)
    reset.add_argument("--confirm")
    reset.add_argument("--delete-evidence", action="store_true")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            result = doctor()
        elif args.command == "discover-offline":
            g = Graph(context())
            snap = inventory(Path(args.root).absolute(), args.config, g)
            result = write_run(
                snap,
                Path(args.out).absolute(),
                ["p004", "discover-offline", "--config", args.config],
                read_snapshot(Path(args.baseline)) if args.baseline else None,
            )
            print(json.dumps(result, sort_keys=True))
            return 0 if snap.context.outcome == "COMPLETE" else 2
        elif args.command == "observe-local":
            result, code = observe(args)
            print(json.dumps(result, sort_keys=True))
            return code
        elif args.command in ("inventory", "graph", "report"):
            snap = read_snapshot(Path(args.input).absolute())
            if args.command == "inventory":
                result = snap.model_dump(mode="json")
            else:
                print(mermaid(snap) if args.command == "graph" else memo(snap), end="")
                return 0
        elif args.command == "diff":
            from p004.reporting import json_bytes
            from p004.safety import contained

            out = Path(args.out).absolute()
            contained(out.parent, out.name)
            value = diff(
                read_snapshot(Path(args.before).absolute()), read_snapshot(Path(args.after).absolute())
            )
            with out.open("xb") as stream:
                stream.write(json_bytes(value))
            result = dict(output=str(out), before=value["before"], after=value["after"])
        elif args.command == "correlate":
            from p004.correlation import correlate

            declared = Path(args.declared).absolute()
            observed = Path(args.observed).absolute()
            verify_run(declared)
            verify_run(observed)
            mapping = None
            if args.mapping:
                path = Path(args.mapping).absolute()
                mapping = load(path.parent, path.name)
            snap = correlate(read_snapshot(declared), read_snapshot(observed), mapping)
            result = write_run(
                snap, Path(args.out).absolute(), ["p004", "correlate", "reviewed source snapshots"]
            )
        elif args.command == "verify-artifacts":
            result = verify_run(Path(args.input).absolute())
        else:
            result = reset_owned(Path(args.input).absolute(), args.confirm, args.delete_evidence)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, ImportError) as exc:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "code": str(exc) if isinstance(exc, Invalid) else "INVALID-OR-UNAVAILABLE-OPERATION",
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
