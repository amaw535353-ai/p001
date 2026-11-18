"""Small local operator CLI. Local Unix archive owner is the custodian trust boundary."""

import argparse
import json
from collections import Counter
from pathlib import Path
from uuid import uuid4

from p009.adapters import import_p007, import_p008
from p009.archive import Archive
from p009.config import config
from p009.correlate import KEYS, timeline
from p009.demo import demo
from p009.exports import export
from p009.models import Event, Principal
from p009.safety import ROOT, Invalid, digest


def main():
    parser = argparse.ArgumentParser(description="P009 synthetic telemetry; local Unix-owner operator")
    parser.add_argument("--archive", type=Path, default=ROOT / ".runtime/archive")
    parser.add_argument("--tenant", choices=["tenant-a", "tenant-b"], default="tenant-a")
    parser.add_argument(
        "command",
        choices=[
            "doctor",
            "validate",
            "up",
            "down",
            "status",
            "cleanup",
            "demo",
            "import-p007",
            "import-p008",
            "timeline",
            "evidence-verify",
            "export",
            "retention-audit",
            "retention-apply",
            "test-live",
        ],
    )
    parser.add_argument("--file", type=Path)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--profile", default="core", choices=["core", "langfuse", "wazuh", "full"])
    parser.add_argument("--confirm", default="")
    parser.add_argument("--key", choices=KEYS, default="trace_id")
    parser.add_argument("--value")
    args = parser.parse_args()
    try:
        cfg = config()
        principal = Principal(actor="local-unix-owner", tenant=args.tenant, role="custodian")
        if args.command == "doctor":
            from p009.operate import resources

            result = resources()
        elif args.command == "validate":
            from p009.validation import validate

            result = validate()
        elif args.command in {"up", "down", "cleanup"}:
            from p009.operate import cleanup, down, up

            result = (
                up(args.profile)
                if args.command == "up"
                else down()
                if args.command == "down"
                else cleanup(args.confirm)
            )
        elif args.command == "test-live":
            from p009.live import live

            result = live(args.profile)
        elif args.command == "demo":
            result = demo(ROOT / ".runtime/demos" / uuid4().hex)
        else:
            archive = Archive(args.archive, digest(cfg))
            if args.command == "evidence-verify":
                result = archive.verify()
            elif args.command == "status":
                from p009.operate import runtime_status

                rows = archive.records(principal)
                result = {
                    "events": len(rows),
                    "by_source": dict(Counter(e["source_id"] for e in rows)),
                    "by_type": dict(Counter(e["event_type"] for e in rows)),
                    "integrity": archive.verify(),
                    "privacy": "p009-metadata-v1",
                    "p006": "PARTIAL; missing request ID on authorization",
                    "runtime": runtime_status(args.tenant),
                }
            elif args.command == "timeline":
                event_rows = [Event.model_validate(e) for e in archive.records(principal)]
                result = timeline(
                    event_rows, principal, query={args.key: args.value} if args.value else None
                ).model_dump(mode="json")
            elif args.command == "export":
                result = export(archive, principal)
            elif args.command in {"import-p007", "import-p008"}:
                if args.file is None:
                    raise Invalid("EXPLICIT-FILE-REQUIRED")
                value = (
                    import_p007(args.file, args.run_root)
                    if args.command == "import-p007"
                    else import_p008(args.file)
                )
                result = archive.put_import(
                    value, "p007-export" if args.command == "import-p007" else "p008-export", principal
                )
            else:
                if args.command == "retention-apply" and args.confirm != "p009-owned-resources":
                    raise Invalid("DELETION-CONFIRMATION")
                result = archive.retention(principal, cfg.retention, args.command == "retention-apply")
        print(json.dumps(result, sort_keys=True, indent=2))
        if args.command == "test-live" and (result["counts"]["FAIL"] or result["counts"]["BLOCKED"]):
            return 2
        return 0
    except (ValueError, OSError, KeyError) as error:
        # Fixed error codes only. Validation errors can embed untrusted input; never print them.
        print(
            json.dumps(
                {
                    "status": "BLOCKED" if type(error).__name__ == "Blocked" else "FAIL",
                    "error": str(error) if isinstance(error, Invalid) else "OPERATION-REFUSED",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
