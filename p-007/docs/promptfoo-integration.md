# Promptfoo integration (#3)

The real CLI is installed under `.tools/node`, pinned at 0.125.1. The adapter writes
a small JSON configuration, fixes provider resolution to the reviewed local CJS
module, and executes `promptfoo eval --config <file> --output <file> --no-cache
--no-progress-bar --no-table --no-write --max-concurrency 1`. Telemetry/update
flags are disabled and provider credentials are excluded from the child environment.

The provider computes tenant/model/prompt behavior from synthetic inputs and policy;
it does not return the test's expected value. Promptfoo checks structured output;
the Python oracle separately checks exact security behavior. Six allowed/denied and
injection/disclosure cases are available. Record version, provider/model identity,
configuration digest, sample settings, original score/status/exit and observations.

This executes Promptfoo, not a hosted LLM or P006. A finite pattern-matching
simulator is not jailbreak-resistance evidence. Sources inspected 2026-11-16:
[custom provider](https://www.promptfoo.dev/docs/providers/custom-api/),
[CLI](https://www.promptfoo.dev/docs/usage/command-line/),
[license](https://github.com/promptfoo/promptfoo/blob/main/LICENSE).
