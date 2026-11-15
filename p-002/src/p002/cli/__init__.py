"""No network or platform dependencies for generation/scenario commands."""

import argparse
from typing import Any
import json
import sys
from pathlib import Path
from p002.models import Dataset
from p002.generators import generate
from p002.scenarios import (
    GENERATED,
    write_dataset,
    load_dataset,
    verify_files,
    catalog,
    select,
    seed,
    reset,
    validate_overlay,
)
from p002.exporters import canonical


def parser():
    p = argparse.ArgumentParser(prog="p002")
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--seed", type=int, default=2026)
    g.add_argument("--profile", choices=["tiny", "standard", "stress-local"], default="standard")
    g.add_argument("--mode", choices=["fixtures", "sdv"], default="fixtures")
    g.add_argument("--allow-stress", action="store_true")
    g.add_argument("--output", type=Path, default=GENERATED / "standard")
    for op in ["validate", "export"]:
        s = sub.add_parser(op)
        s.add_argument("--dataset", type=Path, default=GENERATED / "standard")
    s = sub.add_parser("scenarios")
    s.add_argument("operation", choices=["list", "show", "seed", "diff", "reset", "validate", "export"])
    s.add_argument("id", nargs="?")
    s.add_argument("--dataset", type=Path, default=GENERATED / "standard")
    s.add_argument("--unsafe-scenario", action="store_true")
    a = sub.add_parser("adapters")
    a.add_argument("operation", choices=["status", "dry-run", "seed", "verify", "cleanup"])
    a.add_argument("--name", choices=["nextcloud", "redmine", "label-studio", "p001"])
    a.add_argument("--target", choices=["lab"])
    a.add_argument("--dataset", type=Path, default=GENERATED / "standard")
    a.add_argument("--transport", choices=["http", "docker"], default="docker")
    a.add_argument("--confirm")
    sub.add_parser("doctor")
    sub.add_parser("evidence")
    d = sub.add_parser("down")
    d.add_argument("--confirm", required=True)
    sub.add_parser("schema")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    result: Any
    try:
        if args.command == "generate":
            d = generate(args.seed, args.profile, args.mode, args.allow_stress)
            path = write_dataset(d, args.output)
            result = {
                "dataset": str(path),
                "manifest": verify_files(path),
                "counts": {k: len(v) for k, v in d.tables().items()},
            }
        elif args.command in ["validate", "export"]:
            d = load_dataset(args.dataset)
            result = {
                "status": "PASS",
                "mode": d.mode,
                "hash": verify_files(args.dataset)["dataset_sha256"],
                "notice": d.notice,
            }
        elif args.command == "schema":
            result = Dataset.model_json_schema()
        elif args.command == "scenarios":
            op = args.operation
            if op == "list":
                result = [
                    {"id": s.id, "title": s.title, "status": s.status, "unsafe": s.unsafe} for s in catalog()
                ]
            elif op == "show":
                result = select(args.id).model_dump()
            elif op == "seed":
                result = seed(args.id, args.dataset, args.unsafe_scenario)
            elif op == "reset":
                result = reset(args.id)
            elif op in ["diff", "validate"]:
                result = validate_overlay(args.id)
            else:
                result = {
                    "notice": "SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT",
                    "scenarios": [s.model_dump() for s in catalog()],
                }
        elif args.command == "adapters":
            from p002.adapters import command

            result = command(args)
        else:
            from p002.operations import command

            result = command(args)
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (ValueError, OSError, KeyError, RuntimeError) as e:
        # Exception strings from external clients must not contain credentials.
        print(json.dumps({"status": "FAIL", "error": str(e)[:700]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
