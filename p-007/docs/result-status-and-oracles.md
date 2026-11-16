# Statuses and oracles

| Status | Meaning |
|---|---|
| PASS | executed expected security behavior and exact assertion passed |
| FAIL | executed behavior violated the defined expectation |
| BLOCKED | missing dependency/scope/environment/unsupported capability |
| NOT_TESTED | no execution attempted, including an unmapped skip |
| INCONCLUSIVE | execution error, timeout, missing required observation or sample mismatch |
| NOT_APPLICABLE | explicitly retired/nonapplicable case, never a passed control |
| FLAKY | complete repeated observations disagree under the recorded policy |

Oracles check exact values/types and forbidden marker presence in the actual
observation. Exit zero and aggregate evaluation scores are insufficient. Raw runner
status and exit code are retained even when the normalized status differs.

The repeated-model fixture alternates deterministically to demonstrate how inconsistent
samples are recorded. It is not a measurement of a real nondeterministic model.
Repetition count and minimum-pass threshold are recorded before execution; mixed
samples always remain FLAKY, even if a numerical threshold could otherwise pass.
Authorization, identity, HTTP response, invocation count and secret-presence checks
use application-side oracles. No judge model or generated explanation is ground truth.
