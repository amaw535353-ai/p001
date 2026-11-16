"""Actual Inspect eval/task/solver/scorer pipeline, isolated in a bounded worker."""

from p007.models import RunnerResult
from p007.runners import bounded_result, execute
from p007.safety import canonical, digest, write_new


def run(test, plan, capability, folder, guard=None):
    payload = {
        "case": plan.fixtures["cases"][test.fixture_ref],
        "policy": plan.fixtures["policy"],
        "expected": test.oracle.equals,
        "repetitions": test.repetitions,
    }
    input_file, output = folder / "input.json", folder / "summary.json"
    write_new(input_file, canonical(payload))
    command = [capability.executable, "-m", "p007.adapters.inspect_ai.worker", str(input_file), str(output)]
    code, stdout, error = execute(command, folder, test.limits)
    if error != "none" or not output.exists():
        return RunnerResult(
            adapter="inspect_ai",
            executed=True,
            original_status="INSPECT-" + (error.upper() if error != "none" else "NO-OUTPUT"),
            exit_code=code,
            error_class=error if error != "none" else "provider",
            tool_version=capability.version,
            commands=[command],
            metadata={"diagnostic": stdout.decode(errors="replace")[-6000:]},
        )
    data = bounded_result(output, test.limits)
    if data["eval_status"] != "success" or not data["samples"]:
        return RunnerResult(
            adapter="inspect_ai",
            executed=True,
            original_status="INSPECT-EVALUATION-ERROR",
            exit_code=code,
            error_class="provider",
            tool_version=capability.version,
            metadata=data,
            commands=[command],
        )
    return RunnerResult(
        adapter="inspect_ai",
        executed=True,
        original_status="EVALUATED",
        exit_code=code,
        observed=data["samples"][0]["observed"],
        samples=[x["observed"] for x in data["samples"]],
        tool_version=capability.version,
        commands=[command],
        metadata={
            **data,
            "model": "mockllm/p007-local-policy-v1",
            "task": "p007-control-task-v1",
            "scorer": "p007-exact-behavior-v1",
            "settings": {"seed": 7, "temperature": 0, "sample_count": test.repetitions},
            "config_hash": digest(payload),
            "raw_output_retention": "sanitized per-sample and aggregate fields retained; ephemeral eval log removed",
        },
    )
