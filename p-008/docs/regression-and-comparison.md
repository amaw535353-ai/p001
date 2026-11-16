# Comparison and reproduction

The strict-identity-v1 rule requires matching dataset/manifest/sample set/split,
task/scorer/rubric/evaluator/adapter/tool/model/provider identities, relevant
configuration, source/dependency hashes, runtime, seed, repetitions and budgets.
Different configurations are never silently equivalent. Noncomparable results
retain a cause classification and reasons but no regression pass-rate delta.

Comparable runs retain sample-level transitions and classify improved, regressed,
mixed, unchanged, blocked, inconclusive or flaky. Dataset/scorer/evaluator/model
changes and new/removed samples have explicit noncomparable classifications.
Raw compare is a pure function; CLI comparisons first verify anchored runs and
reconcile stored metrics/results.

Reproduction validates original plan/anchors, frozen inputs, sample hashes,
current implementation, tool version and lock identities. Drift raises an error;
it never substitutes a newer dataset or current configuration. It executes the
whole original plan to preserve order/state and then compares the requested sample
or all samples. Output match and evaluation status are separate: a reproduced FAIL
is still a FAIL. Runtime/tool-native text may vary; normalized sample observations
and scores are the reproducibility target. All original native artifacts remain
hash-verifiable.
