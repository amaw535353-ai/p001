"""Operator CLI with safe defaults and explicit success/failure/incomplete exit codes."""

import argparse
from pathlib import Path
import sys
import uuid

from pydantic import ValidationError

from p008.adapters import TOOLS, capability
from p008.comparison import compare
from p008.exports import export, report
from p008.generation import generate
from p008.integrations import import_p007, siblings
from p008.laboratory import laboratory
from p008.models import Bundle
from p008.pipeline import execute, make_plan, reproduce, verified_run
from p008.quality import audit
from p008.registry import Registry
from p008.safety import Blocked, Invalid, canonical, load, write_new


def output(value) -> None:
    print(canonical(value).decode(), end="")


def parser():
    root = argparse.ArgumentParser(prog="p008", description="P-008 local synthetic evaluation pipeline")
    root.add_argument("--root", type=Path, help="Owned local registry root; default p-008/.runtime")
    commands = root.add_subparsers(dest="command", required=True)
    for name in (
        "doctor",
        "datasets",
        "dataset-build",
        "validate",
        "dataset-audit",
        "dataset-freeze",
        "plan",
        "eval",
        "report",
        "compare",
        "reproduce",
        "integrity-check",
        "benchmark-integrity",
        "import-p007",
        "export",
        "demo",
        "integrations",
        "cleanup",
    ):
        cmd = commands.add_parser(name)
        cmd.add_argument("--dataset", default="synthetic-core", choices=["synthetic-core"])
        cmd.add_argument("--version", default="1.0.0")
        cmd.add_argument("--seed", type=int, default=20261116)
        cmd.add_argument("--run")
        cmd.add_argument("--file", type=Path)
        if name in ("plan", "eval"):
            cmd.add_argument("--tool", choices=["offline", *TOOLS], default="offline")
            cmd.add_argument(
                "--split",
                choices=[
                    "all",
                    "development",
                    "validation",
                    "public_benchmark",
                    "sealed_holdout",
                    "regression",
                ],
                default="all",
            )
            cmd.add_argument(
                "--family",
                choices=["integrity", "injection", "authorization", "disclosure", "boundary", "context"],
            )
            cmd.add_argument("--repetitions", type=int, default=1)
            cmd.add_argument(
                "--policy",
                choices=["baseline", "corrected", "alternating", "timeout", "provider_error"],
                default="baseline",
            )
            cmd.add_argument("--plan")
            cmd.add_argument("--baseline", action="store_true")
            cmd.add_argument("--dry-run", action="store_true")
        if name == "compare":
            cmd.add_argument("--baseline", required=True)
            cmd.add_argument("--current", required=True)
        if name == "reproduce":
            cmd.add_argument("--sample")
        if name == "cleanup":
            cmd.add_argument("--confirm", required=True)
    return root


def required(value, name):
    if value is None:
        raise Invalid("MISSING-" + name.upper())
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    registry = Registry(args.root)
    try:
        cmd = args.command
        if cmd == "doctor":
            output(
                {
                    "schema_version": "1.0",
                    "python": sys.version.split()[0],
                    "network": "disabled",
                    "tools": [capability(t) for t in ("offline", *TOOLS)],
                    "p006": "BLOCKED: no verified runtime",
                    "registry": str(registry.root),
                }
            )
        elif cmd == "datasets":
            output(
                {
                    "dataset_ids": ["synthetic-core"],
                    "frozen": sorted(
                        str(p.relative_to(registry.root))
                        for p in registry.path("datasets").glob("*/*/manifest.json")
                    ),
                    "generated_sample_count": 48,
                }
            )
        elif cmd == "dataset-build":
            bundle = generate(args.seed, args.version)
            output({"status": "PASS", "draft": str(registry.save_draft(bundle)), "audit": audit(bundle)})
        elif cmd in ("validate", "dataset-audit"):
            if args.file:
                bundle = Bundle.model_validate(load(args.file))
            else:
                bundle, _ = registry.dataset(args.dataset, args.version)
            result = audit(bundle)
            output(result)
            return int(result["status"] != "PASS")
        elif cmd == "dataset-freeze":
            path = args.file or registry.path("drafts", args.dataset + "-" + args.version + ".json")
            output(registry.freeze(Bundle.model_validate(load(path))))
        elif cmd in ("plan", "eval"):
            plan = (
                registry.plan(args.plan)
                if args.plan
                else make_plan(
                    registry,
                    args.dataset,
                    args.version,
                    args.tool,
                    args.split,
                    args.repetitions,
                    args.policy,
                    args.family,
                )
            )
            output(
                {
                    "preflight": {
                        "dataset": plan.dataset_id,
                        "version": plan.dataset_version,
                        "sample_count": len(plan.sample_ids),
                        "split": plan.split,
                        "model": plan.evaluator.model,
                        "provider": plan.evaluator.provider,
                        "evaluator": plan.evaluator.version,
                        "scorer_hash": plan.scorer_hash,
                        "network": plan.network,
                        "limits": plan.limits.model_dump(mode="json"),
                        "repetitions": plan.repetitions,
                        "plan_id": plan.plan_id,
                    }
                }
            )
            if cmd == "eval" and not args.dry_run:
                run = execute(registry, plan.plan_id, args.baseline)
                output(
                    {
                        "run_id": run.run_id,
                        "status": run.status,
                        "metrics": run.metrics.model_dump(mode="json"),
                    }
                )
                return 0 if run.status == "PASS" else 1 if run.status == "FAIL" else 2
        elif cmd == "report":
            print(report(verified_run(registry, required(args.run, "run"))), end="")
        elif cmd == "compare":
            comparison = compare(verified_run(registry, args.baseline), verified_run(registry, args.current))
            output(comparison)
            return 0 if comparison.comparable else 2
        elif cmd == "reproduce":
            result = reproduce(registry, required(args.run, "run"), args.sample)
            output(result)
            return 0 if result["status"] == "PASS" else 2
        elif cmd == "integrity-check":
            if args.run:
                verified_run(registry, args.run)
            else:
                registry.dataset(args.dataset, args.version)
            output({"status": "PASS", "run": args.run, "dataset": args.dataset, "version": args.version})
        elif cmd == "benchmark-integrity":
            output(laboratory(registry, verified_run(registry, required(args.run, "run"))))
        elif cmd == "import-p007":
            value = import_p007(required(args.file, "file"))
            path = registry.path("imports", "p007-" + uuid.uuid4().hex + ".json")
            write_new(path, canonical(value))
            output(
                {
                    "status": "PASS",
                    "source_run_id": value.original_run_id,
                    "import": str(path),
                    "limit": value.limitation,
                }
            )
        elif cmd == "integrations":
            output(siblings())
        elif cmd == "export":
            output(
                {
                    "status": "PASS",
                    "local_export": str(export(registry, args.dataset, args.version, args.run)),
                    "publication": "NOT_PERFORMED",
                }
            )
        elif cmd == "cleanup":
            registry.cleanup(required(args.run, "run"), args.confirm)
            output({"status": "PASS", "removed_owned_run": args.run})
        elif cmd == "demo":
            from p008.demo import demo

            output(demo(registry, args.seed))
        return 0
    except (Invalid, ValidationError, ValueError, OSError, KeyError) as exc:
        # Never echo untrusted input or Pydantic's raw input_value into operator logs.
        kind = type(exc).__name__
        code = str(exc).splitlines()[0] if isinstance(exc, Invalid) else kind.upper()
        output(
            {"status": "BLOCKED" if isinstance(exc, Blocked) else "FAIL", "error_class": kind, "code": code}
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
