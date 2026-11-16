"""Behavior oracles operate before redaction; status is never inferred from exit zero."""

import json

from p007.models import NormalizedResult, RunnerResult, Status, TestCase
from p007.safety import digest, redact


def assertion(test: TestCase, observed: dict) -> tuple[bool, str]:
    for key, expected in test.oracle.equals.items():
        if key not in observed:
            return False, "MISSING-OBSERVATION:" + key
        if type(observed[key]) is not type(expected) or observed[key] != expected:
            return False, "EXPECTED-BEHAVIOR-VIOLATED:" + key
    text = json.dumps(observed, sort_keys=True)
    if any(marker in text for marker in test.oracle.absent_markers):
        return False, "FORBIDDEN-MARKER-PRESENT"
    return True, "EXPECTED-BEHAVIOR-OBSERVED"


def normalize(test: TestCase, raw: RunnerResult, *, compatibility: dict) -> NormalizedResult:
    status: Status = "INCONCLUSIVE"
    detail = "RUNNER-DID-NOT-PROVIDE-RELIABLE-EVIDENCE"
    if not raw.executed and raw.original_status == "NOT_APPLICABLE" and test.lifecycle == "retired":
        status, detail = "NOT_APPLICABLE", "RETIRED-TEST"
    elif raw.error_class in ("dependency", "scope", "unsupported"):
        status, detail = "BLOCKED", raw.original_status
    elif not raw.executed:
        status, detail = "NOT_TESTED", raw.original_status
    elif raw.error_class != "none" or raw.original_status not in ("COMPLETE", "EVALUATED"):
        detail = raw.original_status
    elif raw.exit_code not in (0, 1, None):
        detail = "NONZERO-RUNNER-ERROR"
    else:
        checks = [assertion(test, row) for row in (raw.samples or [raw.observed])]
        outcomes = [check[0] for check in checks]
        passed, detail = assertion(test, raw.observed)
        if detail.startswith("MISSING-OBSERVATION") or any(
            check[1].startswith("MISSING-OBSERVATION") for check in checks
        ):
            status, detail = "INCONCLUSIVE", "REQUIRED-OBSERVATION-MISSING"
        elif raw.samples and len(raw.samples) != test.repetitions:
            status, detail = "INCONCLUSIVE", "SAMPLE-COUNT-MISMATCH"
        elif len(set(outcomes)) > 1:
            status, detail = "FLAKY", "INCONSISTENT-REPETITIONS"
        else:
            status = "PASS" if passed and all(outcomes) else "FAIL"
    clean = RunnerResult.model_validate(redact(raw.model_dump(mode="json")))
    return NormalizedResult(
        test_id=test.test_id,
        test_version=test.version,
        control_ids=test.control_ids,
        status=status,
        assertion=detail,
        expected=redact(test.oracle.equals),
        observed=redact(raw.observed),
        runner=clean,
        definition_hash=digest(test.model_dump(mode="json")),
        compatibility_hash=digest({**compatibility, "tool_version": raw.tool_version}),
        compatibility={**compatibility, "tool_version": raw.tool_version},
    )
