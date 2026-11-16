"""Real Promptfoo CLI with a fixed local provider and independent behavior oracle."""

import json

from p007.models import RunnerResult
from p007.runners import bounded_result, execute
from p007.safety import PROJECT, canonical, digest, write_new


def parse_results(value: dict) -> tuple[dict, list[dict]]:
    rows = value.get("results", {}).get("results", [])
    if not rows or any(r.get("error") for r in rows):
        raise ValueError("PROMPTFOO-PROVIDER-ERROR-OR-MISSING-SAMPLES")
    observations = [json.loads(r["response"]["output"]) for r in rows]
    return observations[0], [
        {
            "observed": obs,
            "tool_success": row.get("success"),
            "score": row.get("score"),
            "grading": row.get("gradingResult"),
        }
        for row, obs in zip(rows, observations, strict=True)
    ]


def run(test, plan, capability, folder, guard=None):
    provider = PROJECT / "src/p007/adapters/promptfoo/provider.cjs"
    prompt = json.dumps(
        {"case": plan.fixtures["cases"][test.fixture_ref], "policy": plan.fixtures["policy"]}, sort_keys=True
    )
    configuration = {
        "prompts": ["{{input}}"],
        "providers": [str(provider)],
        "tests": [{"vars": {"input": prompt}, "assert": [{"type": "is-json"}]}],
        "evaluateOptions": {"maxConcurrency": 1, "repeat": test.repetitions},
    }
    config = folder / "config.json"
    write_new(config, canonical(configuration))
    output = folder / "output.json"
    command = [
        capability.executable,
        "eval",
        "--config",
        str(config),
        "--output",
        str(output),
        "--no-cache",
        "--no-progress-bar",
        "--no-table",
        "--no-write",
        "--max-concurrency",
        "1",
    ]
    code, stdout, error = execute(command, folder, test.limits)
    if error != "none" or not output.exists():
        return RunnerResult(
            adapter="promptfoo",
            executed=True,
            original_status="PROMPTFOO-" + (error.upper() if error != "none" else "NO-OUTPUT"),
            exit_code=code,
            error_class=error if error != "none" else "provider",
            tool_version=capability.version,
            commands=[command],
        )
    observed, per_sample = parse_results(bounded_result(output, test.limits))
    return RunnerResult(
        adapter="promptfoo",
        executed=True,
        original_status="EVALUATED",
        exit_code=code,
        observed=observed,
        samples=[x["observed"] for x in per_sample],
        tool_version=capability.version,
        commands=[command],
        metadata={
            "model": "p007-local-policy-v1",
            "provider": "fixed-local-cjs-v1",
            "settings": {"seed": 7, "temperature": 0, "sample_count": test.repetitions},
            "config_hash": digest(configuration),
            "raw_output_hash": digest(output.read_bytes()),
            "samples": per_sample,
            "raw_output_retention": "sanitized per-sample fields retained; ephemeral raw file removed",
        },
    )
