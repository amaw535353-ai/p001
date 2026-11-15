"""Semantic model changes invalidate decisions; no automatic reapproval."""

from p005.domain.schemas import Model
from p005.evidence.safety import Invalid, digest
from p005.modeling.rule_engine import analyze


def compare(before: Model, after: Model) -> dict:
    if before.model_id != after.model_id:
        raise Invalid("DIFF-MODEL-IDENTITY-MISMATCH")
    if after.model_version <= before.model_version:
        raise Invalid("DIFF-REQUIRES-INCREASING-MODEL-VERSION")
    tables = {}
    affected = set()
    for table in ("nodes", "flows", "boundaries", "zones"):

        def semantic(row):
            return {k: v for k, v in row.model_dump().items() if k not in ("source_snapshot",)}

        left = {x.id: semantic(x) for x in getattr(before, table)}
        right = {x.id: semantic(x) for x in getattr(after, table)}
        changed = sorted(i for i in left.keys() & right.keys() if left[i] != right[i])
        tables[table] = dict(
            added=sorted(right.keys() - left.keys()),
            removed=sorted(left.keys() - right.keys()),
            changed=changed,
        )
        affected.update(tables[table]["added"] + tables[table]["removed"] + changed)
    old, new = analyze(before), analyze(after)
    old_ids, new_ids = {t["threat_id"] for t in old["threats"]}, {t["threat_id"] for t in new["threats"]}
    return dict(
        schema_version="p005-diff-1.0",
        before_digest=digest(before.model_dump()),
        after_digest=digest(after.model_dump()),
        graph=tables,
        hypotheses=dict(
            added=sorted(new_ids - old_ids),
            removed=sorted(old_ids - new_ids),
            retained_require_review=sorted(old_ids & new_ids),
        ),
        impacted_ids=sorted(affected),
        review_state="NEEDS_REVIEW",
        previous_decisions="INVALIDATED",
        previous_tests="STALE_NOT_EXECUTED",
        atlas_mappings="REQUIRES_REASSESSMENT",
        newly_out_of_scope=sorted(
            set(after.model_scope.out_of_scope_node_ids) - set(before.model_scope.out_of_scope_node_ids)
        ),
        scope_changed=before.model_scope != after.model_scope,
        rationale="Architecture/source version changed; retained IDs are not approval continuity",
    )
