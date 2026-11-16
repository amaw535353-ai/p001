"""Fixed worker: model responses are computed from inputs, independently of targets."""

import json
import sys

from inspect_ai import Task, eval
from inspect_ai.dataset import Sample
from inspect_ai.model import ModelOutput, ModelUsage, get_model
from inspect_ai.scorer import Score, accuracy, scorer
from inspect_ai.solver import generate

from p007.safety import canonical, load, write_new
from p007.synthetic import respond
from pathlib import Path


@scorer(metrics=[accuracy()])
def exact_behavior():
    async def score(state, target):
        observed, expected = json.loads(state.output.completion), json.loads(target.text)
        passed = all(
            k in observed and type(observed[k]) is type(v) and observed[k] == v for k, v in expected.items()
        )
        return Score(
            value="C" if passed else "I",
            answer="structured synthetic observation",
            explanation="Exact application-side behavior oracle v1",
        )

    return score


def main():
    data = load(Path(sys.argv[1]))
    outputs = [
        ModelOutput.from_content(
            "p007-local-policy-v1", json.dumps(respond(data["case"], data["policy"], n), sort_keys=True)
        )
        for n in range(data["repetitions"])
    ]
    # The built-in mock otherwise calls the default tokenizer and may download
    # an encoding. Synthetic usage avoids that unintended remote dependency.
    for output in outputs:
        output.usage = ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0)
    model = get_model("mockllm/p007-local-policy-v1", custom_outputs=outputs)
    dataset = [
        Sample(id="sample-" + str(n), input=json.dumps(data["case"]), target=json.dumps(data["expected"]))
        for n in range(data["repetitions"])
    ]
    task = Task(
        name="p007-control-task-v1", version=1, dataset=dataset, solver=generate(), scorer=exact_behavior()
    )
    logs = eval(
        task,
        model=model,
        temperature=0,
        seed=7,
        max_connections=1,
        max_samples=1,
        log_dir="inspect-logs",
        display="none",
    )
    log = logs[0]
    result = {
        "eval_status": log.status,
        "samples": [
            {
                "sample_id": str(s.id),
                "observed": json.loads(s.output.completion) if s.output.completion else {},
                "scores": {name: value.value for name, value in (s.scores or {}).items()},
                "error": s.error.message if s.error else None,
            }
            for s in (log.samples or [])
        ],
        "aggregate": log.results.model_dump(mode="json") if log.results else None,
        "error": log.error.message if log.error else None,
    }
    write_new(Path(sys.argv[2]), canonical(result))


if __name__ == "__main__":
    main()
