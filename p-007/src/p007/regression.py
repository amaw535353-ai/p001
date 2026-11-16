"""Strict comparability; explicit, narrow target-version compatibility rules."""

from p007.models import DiffEntry, DiffKind, EvidenceManifest, RegressionDiff, Status
from p007.safety import PROJECT, Invalid, load


def compare(before: EvidenceManifest, after: EvidenceManifest, rule: str | None = None) -> RegressionDiff:
    allowed = False
    if rule:
        rules = load(PROJECT / "config/compatibility-rules.json")
        candidate = rules.get(rule)
        if candidate is None:
            raise Invalid("UNKNOWN-COMPATIBILITY-RULE")
        allowed = (
            before.target.target_id == after.target.target_id == candidate["target_id"]
            and [before.target.version, after.target.version] == candidate["versions"]
        )
        if not allowed:
            raise Invalid("COMPATIBILITY-RULE-NOT-APPLICABLE")
    left = {r.test_id: r for r in before.results}
    right = {r.test_id: r for r in after.results}
    entries = []
    for key in sorted(left.keys() | right.keys()):
        kind: DiffKind
        a, b = left.get(key), right.get(key)
        reason = "Comparable test, target, fixture, provider, policy and runner identities"
        if a is None:
            kind = "NEW_TEST"
        elif b is None or b.status == "NOT_APPLICABLE":
            kind = "REMOVED_OR_NOT_APPLICABLE"
        elif (
            a.definition_hash != b.definition_hash
            or a.compatibility_hash != b.compatibility_hash
            or before.target.version != after.target.version
        ):
            # Rules permit only the documented synthetic policy/target transition;
            # every other identity must remain exactly equal.
            def stable(r):
                return (
                    r.definition_hash,
                    {
                        k: v
                        for k, v in r.compatibility.items()
                        if k not in ("target_version", "policy_version", "policy_hash")
                    },
                )

            permitted_policy = bool(
                rule
                and [a.compatibility.get("policy_hash"), b.compatibility.get("policy_hash")]
                == candidate["policy_hashes"]
            )
            if (
                allowed
                and permitted_policy
                and stable(a) == stable(b)
                and before.source_hash == after.source_hash
            ):
                reason = "Explicit synthetic remediation rule: " + str(rule)
                kind = transition(a.status, b.status)
            else:
                kind, reason = (
                    "BLOCKED_OR_NOT_COMPARABLE",
                    "Test/config/target/fixture/model/tool identity changed",
                )
        else:
            kind = transition(a.status, b.status)
        entries.append(
            DiffEntry(
                test_id=key,
                classification=kind,
                before=a.status if a else None,
                after=b.status if b else None,
                reason=reason,
            )
        )
    return RegressionDiff(
        baseline=before.run_id,
        current=after.run_id,
        entries=entries,
        compatibility_rule=rule,
        remediation_ref=after.remediation_ref,
        retest_evidence=after.run_id + "/manifest.json",
    )


def transition(a: Status, b: Status) -> DiffKind:
    if a in ("FLAKY", "INCONCLUSIVE") or b in ("FLAKY", "INCONCLUSIVE"):
        return "FLAKY_OR_INCONCLUSIVE"
    if a not in ("PASS", "FAIL") or b not in ("PASS", "FAIL"):
        return "BLOCKED_OR_NOT_COMPARABLE"
    transitions: dict[tuple[str, str], DiffKind] = {
        ("PASS", "FAIL"): "REGRESSION",
        ("FAIL", "PASS"): "IMPROVED",
        ("PASS", "PASS"): "UNCHANGED_PASS",
        ("FAIL", "FAIL"): "UNCHANGED_FAIL",
    }
    return transitions[(a, b)]
