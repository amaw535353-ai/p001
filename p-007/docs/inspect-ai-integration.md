# Inspect AI integration (#41)

The actual Inspect Task, Sample, generate solver, registered scorer and eval APIs
run in the isolated `.tools/inspect` Python environment at 0.3.290. The adapter
uses built-in mockllm with outputs computed independently from synthetic policy.
The exact-behavior scorer evaluates structured fields per sample; aggregate scores
never replace sample evidence. Task/scorer/model versions, settings, configuration
hash, score map, aggregate and original errors are retained.

Current eval accepts temperature/seed as keyword arguments, not a nested `config`
field. Its mock provider otherwise requests a tokenizer encoding; explicit zero
synthetic ModelUsage prevents that unintended external dependency. No model API or
paid provider is configured. A failed sample, missing provider or timeout cannot
become a passing test. Mock responses establish framework behavior only.

Sources inspected 2026-11-16: [models](https://inspect.aisi.org.uk/models.html),
[scorers](https://inspect.aisi.org.uk/scorers.html), actual installed
`inspect_ai/model/_providers/mockllm.py`, and
[MIT license](https://github.com/UKGovernmentBEIS/inspect_ai/blob/main/LICENSE).
