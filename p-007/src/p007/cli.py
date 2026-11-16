"""Operator CLI. Default mode never creates a listener or network-capable runner."""

import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import tempfile

from p007.catalog import catalog, plan
from p007.evidence import baseline, reproduce, run, verify
from p007.exports import export
from p007.models import ReproductionRequest
from p007.regression import compare
from p007.runners import discover
from p007.safety import PROJECT, Blocked, Invalid, digest, load, read_bytes, safe_path


def parser():
    p = argparse.ArgumentParser(prog="p007", description="Synthetic local AI security control regression")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("doctor", "validate", "catalog"):
        sub.add_parser(name)
    for name in ("plan", "run"):
        q = sub.add_parser(name)
        q.add_argument("--target", default="offline-demo")
        q.add_argument(
            "--profile",
            choices=("offline", "promptfoo", "inspect_ai", "zap", "playwright", "p006"),
            default="offline",
        )
        q.add_argument("--variant", choices=("baseline", "remediated", "regressed"), default="baseline")
        q.add_argument("--test")
        if name == "run":
            q.add_argument(
                "--local-demo",
                action="store_true",
                help="Explicit synthetic local scope/review exercise, no human approval claim",
            )
            q.add_argument(
                "--active-zap",
                action="store_true",
                help="Requests opt-in gate; current active implementation still refuses",
            )
            q.add_argument("--actor", default="operator")
            q.add_argument("--remediation-ref")
            q.add_argument("--retest-of")
    q = sub.add_parser("compare")
    q.add_argument("--baseline", required=True)
    q.add_argument("--current", required=True)
    q.add_argument("--rule")
    q = sub.add_parser("baseline")
    q.add_argument("--run", required=True)
    q.add_argument("--name", required=True)
    q = sub.add_parser("reproduce")
    q.add_argument("--run", required=True)
    q.add_argument("--test", required=True)
    q.add_argument("--repetitions", type=int, default=1)
    for name in ("verify-evidence", "report"):
        q = sub.add_parser(name)
        q.add_argument("--run", required=True)
    q = sub.add_parser("evidence")
    q.add_argument("operation", choices=["verify"])
    q.add_argument("--run", required=True)
    q = sub.add_parser("cleanup")
    q.add_argument("--run", required=True)
    q.add_argument("--confirm", default="")
    return p


def run_path(run_id):
    # Both schema and containment checks apply to user-supplied identifiers.
    if not isinstance(run_id, str) or not run_id.startswith("run-") or "/" in run_id or "\\" in run_id:
        raise Invalid("INVALID-RUN-ID")
    return safe_path(PROJECT / "evidence", run_id)


def baseline_manifest(value):
    if value.endswith(".baseline.json"):
        from p007.models import BaselineReference

        ref = BaselineReference.model_validate(load(safe_path(PROJECT / "evidence", value)))
        folder = run_path(ref.run_id)
        if digest(read_bytes(folder / "manifest.json")) != ref.manifest_sha256:
            raise Invalid("BASELINE-MANIFEST-MODIFIED")
        return verify(folder)
    return verify(run_path(value))


def do_run(args):
    if args.active_zap:
        from p007.authorization import active_zap_gate

        active_zap_gate(opt_in=True)
    if args.profile in ("zap", "playwright") and args.local_demo:
        if args.target != "local-fixture":
            raise Blocked("LOCAL-DEMO-REQUIRES-EXACT-LOCAL-FIXTURE-TARGET")
        from p007.authorization import Guard, P003Reader
        from p007.fixture import owned_fixture
        from p007.governance_demo import simulated_ledger

        runtime = PROJECT / ".runtime"
        runtime.mkdir(mode=0o700, exist_ok=True)
        with owned_fixture() as lease, tempfile.TemporaryDirectory(prefix="scope-", dir=runtime) as directory:
            _, ref = simulated_ledger(lease.target, Path(directory) / "p003-store")
            selected = plan(
                args.target, args.profile, variant=args.variant, test_id=args.test, target=lease.target
            )
            guard = Guard(lease.target, P003Reader(ref), lease, selected.tests[0])
            guard.check(lease.target.origin + selected.tests[0].operation.path)
            print(
                json.dumps(
                    {
                        "preflight": "ALLOW",
                        "target": args.target,
                        "origin": lease.target.origin,
                        "test_count": len(selected.tests),
                        "scan_type": "passive" if args.profile == "zap" else "browser",
                        "authorization": ref.engagement_id,
                        "policy_digest": ref.policy_digest,
                        "review": "SIMULATED CODEX EXERCISE, no independent human approval",
                    }
                ),
                flush=True,
            )
            return run(
                selected,
                actor=args.actor,
                guard=guard,
                remediation_ref=args.remediation_ref,
                retest_of=args.retest_of,
            )
    return run(
        plan(args.target, args.profile, variant=args.variant, test_id=args.test),
        actor=args.actor,
        remediation_ref=args.remediation_ref,
        retest_of=args.retest_of,
    )


def execute(args):
    if args.command == "doctor":
        return {
            "python": "3.12",
            "default": "offline",
            "tools": [
                asdict(discover(x))
                for x in ("offline", "promptfoo", "inspect_ai", "zap", "playwright", "p006")
            ],
            "p006": "BLOCKED: no committed implementation",
            "scope": "Fresh P003 ledger plus in-process owned fixture lease required",
        }
    if args.command in ("validate", "catalog"):
        catalog_data = catalog()
        return (
            {"status": "PASS", "tests": len(catalog_data.tests), "controls": len(catalog_data.controls)}
            if args.command == "validate"
            else catalog_data.model_dump(mode="json")
        )
    if args.command == "plan":
        return plan(args.target, args.profile, variant=args.variant, test_id=args.test).model_dump(
            mode="json"
        )
    if args.command == "run":
        folder = do_run(args)
        value = verify(folder)
        return {
            "run_id": folder.name,
            "evidence": str(folder),
            "statuses": dict(Counter(r.status for r in value.results)),
        }
    if args.command == "compare":
        return compare(
            baseline_manifest(args.baseline), verify(run_path(args.current)), args.rule
        ).model_dump(mode="json")
    if args.command == "baseline":
        return {"baseline": str(baseline(run_path(args.run), args.name))}
    if args.command == "reproduce":
        return reproduce(
            run_path(args.run),
            ReproductionRequest(run_id=args.run, test_id=args.test, repetitions=args.repetitions),
        )
    if args.command in ("verify-evidence", "evidence"):
        value = verify(run_path(args.run))
        return {
            "status": "PASS",
            "run_id": value.run_id,
            "artifacts_verified": len(value.artifacts),
            "limit": "Consistency only; no oracle correctness or author authenticity proof",
        }
    if args.command == "report":
        folder = run_path(args.run)
        return {"report": str(export(verify(folder), folder, safe_path(PROJECT / "reports", folder.name)))}
    if args.command == "cleanup":
        folder = run_path(args.run)
        if args.confirm != "p007-owned-evidence":
            raise Invalid("CLEANUP-REQUIRES---confirm-p007-owned-evidence")
        value = verify(folder)
        # Baselines remain immutable, even with generic cleanup confirmation.
        for ref in (PROJECT / "evidence").glob("*.baseline.json"):
            if load(ref).get("run_id") == value.run_id:
                raise Invalid("BASELINE-RUN-PROTECTED-FROM-CLEANUP")
        if load(folder / "owner.json") != {"owner": "p007", "run_id": value.run_id}:
            raise Invalid("CLEANUP-OWNERSHIP-MISMATCH")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise Invalid("HOST-LACKS-SYMLINK-SAFE-CLEANUP")
        shutil.rmtree(folder)
        return {"removed_owned_run": value.run_id}
    raise Invalid("UNSUPPORTED-COMMAND")


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        value = execute(args)
        print(json.dumps(value, indent=2, sort_keys=True))
        if args.command == "run":
            statuses = value["statuses"]
            return (
                1
                if statuses.get("FAIL")
                else 2
                if any(statuses.get(x) for x in ("BLOCKED", "NOT_TESTED", "FLAKY", "INCONCLUSIVE"))
                else 0
            )
        return 0
    except (Invalid, ValueError, OSError, ImportError) as exc:
        message = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        print(json.dumps({"status": "BLOCKED" if isinstance(exc, Blocked) else "ERROR", "reason": message}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
