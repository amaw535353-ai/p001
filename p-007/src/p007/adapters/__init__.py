"""Fixed, reviewed adapter registry. No runtime plugin loading."""

from pathlib import Path
import tempfile

from p007.models import ExecutionPlan, TestCase
from p007.runners import PINS, blocked, discover
from p007.safety import PROJECT, Blocked


def execute_test(test: TestCase, plan: ExecutionPlan, guard=None):
    if test.tool_version != PINS[test.adapter]:
        return blocked(test.adapter, "TOOL-PIN-MISMATCH", error="unsupported")
    if test.adapter in ("zap", "playwright"):
        if guard is None:
            return blocked(test.adapter, "FRESH-P003-AND-OWNED-LEASE-REQUIRED", error="scope")
        if guard.target != plan.target or guard.test != test:
            return blocked(test.adapter, "PLAN-GUARD-TEST-BINDING-MISMATCH", error="scope")
        try:
            guard.check(plan.target.origin + test.operation.path, test.operation.method)
        except Blocked as exc:
            return blocked(test.adapter, str(exc), error="scope")
    capability = discover(test.adapter)
    if not capability.available:
        return blocked(test.adapter, capability.reason, capability.version)
    runtime = PROJECT / ".runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=test.adapter + "-", dir=runtime) as directory:
        folder = Path(directory)
        try:
            if test.adapter == "promptfoo":
                from p007.adapters.promptfoo import run
            elif test.adapter == "inspect_ai":
                from p007.adapters.inspect_ai import run
            elif test.adapter == "playwright":
                from p007.adapters.playwright import run
            elif test.adapter == "zap":
                from p007.adapters.zap import run
            else:
                return blocked(test.adapter, "UNSUPPORTED-ADAPTER", error="unsupported")
            return run(test, plan, capability, folder, guard)
        except Blocked as exc:
            return blocked(test.adapter, str(exc), capability.version, error="scope")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            from p007.models import RunnerResult

            return RunnerResult(
                adapter=test.adapter,
                executed=True,
                original_status="ADAPTER-ERROR:" + type(exc).__name__,
                exit_code=None,
                error_class="provider",
                tool_version=capability.version,
            )
