# Baselines and regression comparison

Every run has a new collision-resistant ID. Baseline references contain the original
manifest hash and are exclusively created; they cannot overwrite a prior baseline.
Cleanup also protects baseline runs. Comparison accepts a run ID or an anchored
`.baseline.json` reference. Both manifests and artifact hashes verify first.

Join on stable test IDs. Exact definition, target, fixture, controls, source/config,
policy, model/settings/browser and tool identities determine comparability. Changed
identities yield BLOCKED_OR_NOT_COMPARABLE. Named synthetic compatibility rules
permit only exact target-version and policy-hash transitions; other fields still
must match. A rule cannot waive a changed model, tool, fixture or test.

PASS→FAIL is REGRESSION; FAIL→PASS is IMPROVED; stable outcomes remain
UNCHANGED_PASS/UNCHANGED_FAIL. New/removed/not-applicable cases are distinguished.
Blocked/untested controls never count as passed. Flaky/inconclusive outcomes remain
visible. Remediation and retest links are preserved and never erase prior failures.

The demo uses an offline-only output-validation fix and a separate denied-action
regression sentinel. It never changes P006 or a live target. These are deliberate
simulation variants with explicit compatibility rules, not a reviewed real fix.
