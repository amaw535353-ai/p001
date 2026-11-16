"""Independent dataset gates; no weighted score can hide a failed gate."""

from collections import Counter, defaultdict
from difflib import SequenceMatcher

from p008.generation import bundle_digest, sample_digest
from p008.models import Bundle, VisibleInput
from p008.respond import DUMMY_MARKER
from p008.safety import Invalid, canonical, digest


def model_visible(sample) -> dict:
    # An explicit projection avoids forwarding labels, scorer keys or metadata.
    value = sample.input.model_dump(mode="json")
    VisibleInput.model_validate(value)
    text = canonical(value).decode()
    if (
        DUMMY_MARKER in text
        or "P008_HOLDOUT_" in text
        or any(
            x in text.lower()
            for x in ('"expected_outcome"', '"hidden_labels"', '"scorer_key"', '"outcome_id"')
        )
    ):
        raise Invalid("HIDDEN-LABEL-OR-DUMMY-SECRET-LEAKAGE")
    return value


def audit(bundle: Bundle) -> dict:
    Bundle.model_validate(bundle.model_dump(mode="json"))
    errors, review = [], []
    if bundle.card.manifest_digest != bundle_digest(bundle):
        errors.append("BUNDLE-DIGEST-MISMATCH")
    hashes: dict[str, str] = {}
    groups: dict[str, set[str]] = defaultdict(set)
    scenarios = {s.scenario_id: s for s in bundle.scenarios}
    outcomes = {o.outcome_id: o for o in bundle.outcomes}
    exact, near = [], []
    for n, sample in enumerate(bundle.samples):
        if sample.content_digest != sample_digest(sample):
            errors.append("SAMPLE-DIGEST:" + sample.sample_id)
        fingerprint = digest(sample.input)
        if fingerprint in hashes:
            exact.append([hashes[fingerprint], sample.sample_id])
        hashes[fingerprint] = sample.sample_id
        scenario = scenarios[sample.scenario_id]
        for namespace, value in (
            ("group", sample.group_key),
            ("scenario", sample.scenario_id),
            ("template", scenario.source_template),
            ("construction", scenario.construction_method),
        ):
            groups[namespace + ":" + value].add(sample.split)
        expected = outcomes[sample.expected_outcome_ref]
        if expected.adjudication in ("ambiguous", "disputed"):
            errors.append("LABEL-REVIEW-REQUIRED:" + sample.sample_id)
        if expected.decision == "DENY" and expected.allowed_actions:
            errors.append("INCONSISTENT-EXPECTED-ACTIONS:" + sample.sample_id)
        try:
            model_visible(sample)
        except Invalid as exc:
            errors.append(str(exc) + ":" + sample.sample_id)
        if sample.provenance != bundle.card.provenance:
            errors.append("SAMPLE-PROVENANCE-MISMATCH:" + sample.sample_id)
        for other in bundle.samples[:n]:
            similarity = SequenceMatcher(
                None, sample.input.prompt.casefold(), other.input.prompt.casefold()
            ).ratio()
            if similarity >= 0.80:
                near.append(
                    {
                        "samples": [other.sample_id, sample.sample_id],
                        "similarity": round(similarity, 3),
                        "review_only": True,
                    }
                )
    leakage = [key for key, names in sorted(groups.items()) if len(names) > 1]
    if exact:
        errors.append("EXACT-DUPLICATES")
    if leakage:
        errors.append("SPLIT-LINEAGE-LEAKAGE")
    if near:
        review.append("NEAR-DUPLICATES-REQUIRE-REVIEW-NOT-PROVEN-LEAKAGE")
    counts = {
        "family": dict(Counter(scenarios[s.scenario_id].family for s in bundle.samples)),
        "split": dict(Counter(s.split for s in bundle.samples)),
        "modality": dict(Counter(s.modality for s in bundle.samples)),
        "difficulty": dict(Counter(s.difficulty for s in bundle.samples)),
        "outcome": dict(Counter(outcomes[s.expected_outcome_ref].decision for s in bundle.samples)),
        "risk": {"21": sum(21 in scenarios[s.scenario_id].risk_ids for s in bundle.samples)},
    }
    return {
        "schema_version": "1.0",
        "status": "FAIL" if errors else "PASS",
        "sample_count": len(bundle.samples),
        "errors": errors,
        "review_signals": review,
        "exact_duplicates": exact,
        "near_duplicate_candidates": near,
        "leakage_groups": leakage,
        "invalid_labels": sum("LABEL" in x or "EXPECTED" in x for x in errors),
        "missing_provenance_or_licenses": 0,
        "coverage": counts,
        "limitation": "Counts are descriptive. Near similarity is a review signal, not a leakage verdict.",
    }


def require_quality(bundle: Bundle) -> None:
    result = audit(bundle)
    if result["errors"]:
        raise Invalid("QUALITY-GATES:" + ",".join(result["errors"]))
