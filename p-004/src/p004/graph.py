"""Tenant-aware claim correlation, deterministic graph and semantic differences."""

from typing import Any

from p004.models import Asset, Boundary, Context, Coverage, Endpoint, Flow, Observation, Snapshot, Source
from p004.safety import address, digest, route


def stable(kind: str, *parts: Any) -> str:
    return kind + "_" + digest(list(parts))[:24]


def semantic(value: Any) -> Any:
    """Ignore acquisition clocks in architecture hashes and diffs; retain provenance."""
    if isinstance(value, dict):
        return {k: semantic(v) for k, v in value.items() if k not in ("first_seen_utc", "last_seen_utc")}
    if isinstance(value, list):
        return [semantic(x) for x in value]
    return value


def architecture(snapshot: Snapshot) -> dict:
    return {
        k: semantic([x.model_dump(mode="json") for x in getattr(snapshot, k)])
        for k in ("assets", "endpoints", "flows", "trust_boundaries")
    }


class Graph:
    def __init__(self, context: Context):
        self.context = context
        self.assets: dict[str, Asset] = {}
        self.endpoints: dict[str, Endpoint] = {}
        self.flows: dict[str, Flow] = {}
        self.boundaries: dict[str, Boundary] = {}
        self.observations: dict[str, Observation] = {}
        self.coverage: list[Coverage] = []

    def common(self, id, tenant, ref: Source, method, status="DECLARED", **kw):
        return dict(
            id=id,
            tenant_id=tenant,
            environment_id=self.context.environment_id,
            source_refs=[ref],
            evidence_claims=[
                dict(
                    source_ref=ref,
                    discovery_method=method,
                    status=status,
                    measured_scope="HTTP route/status metadata only; other properties remain declared"
                    if status == "OBSERVED"
                    else "source declaration or explicitly marked inference; no control effectiveness",
                )
            ],
            discovery_method=method,
            status=status,
            confidence=0.9 if status == "OBSERVED" else 0.6 if status == "DECLARED" else 0.3,
            first_seen_utc=self.context.timestamp_utc,
            last_seen_utc=self.context.timestamp_utc,
            **kw,
        )

    def note(self, status, category, summary, refs=None, entities=None, details=None):
        item = Observation(
            id=stable("obs", status, category, summary, entities, details),
            status=status,
            category=category,
            summary=summary,
            source_refs=refs or [],
            entity_ids=entities or [],
            details=details or {},
        )
        self.observations[item.id] = item
        return item.id

    def merge(self, table: dict, incoming):
        previous = table.get(incoming.id)
        if previous is None:
            table[incoming.id] = incoming
            return incoming.id
        left = previous.model_dump(mode="json")
        right = incoming.model_dump(mode="json")
        ignored = {
            "source_refs",
            "evidence_claims",
            "status",
            "confidence",
            "discovery_method",
            "first_seen_utc",
            "last_seen_utc",
        }
        differences = {
            k: {"existing": left[k], "incoming": right[k]}
            for k in left
            if k not in ignored and left[k] != right[k]
        }
        if differences:
            self.note(
                "UNVERIFIED",
                "discrepancy",
                "Conflicting claims retained; manual review required",
                incoming.source_refs,
                [incoming.id],
                differences,
            )
        # Original declaration plus each later observation is retained in provenance/observations.
        refs = {digest(r.model_dump()): r for r in [*previous.source_refs, *incoming.source_refs]}
        updates = {"source_refs": [refs[k] for k in sorted(refs)], "last_seen_utc": incoming.last_seen_utc}
        evidence = {digest(e.model_dump()): e for e in [*previous.evidence_claims, *incoming.evidence_claims]}
        updates["evidence_claims"] = [evidence[k] for k in sorted(evidence)]
        if isinstance(incoming, Endpoint):
            updates["response_codes"] = sorted(set(previous.response_codes + incoming.response_codes))
        if incoming.status == "OBSERVED":
            updates.update(status="OBSERVED", confidence=0.9)
        table[incoming.id] = type(incoming).model_validate({**left, **updates})
        return incoming.id

    def asset(self, key, kind, tenant, ref, method="static", label=None, **kw):
        id = stable("asset", self.context.environment_id, tenant, key)
        item = Asset(**self.common(id, tenant, ref, method, **kw), asset_id=id, kind=kind, label=label or key)
        return self.merge(self.assets, item)

    def endpoint(self, asset_id, path, verb, ref, method="openapi", origin=None, **kw):
        path = route(path)
        origin = address(origin).removesuffix("/") if origin else None
        tenant = self.assets[asset_id].tenant_id
        item = Endpoint(
            **self.common(stable("endpoint", asset_id, origin, verb, path), tenant, ref, method, **kw),
            asset_id=asset_id,
            origin=origin,
            path=path,
            method=verb,
        )
        return self.merge(self.endpoints, item)

    def flow(self, source, target, kind, ref, method="static", boundary=None, **kw):
        tenant = self.assets[source].tenant_id
        id = stable("flow", source, target, kind)
        item = Flow(
            **self.common(id, tenant, ref, method, **kw), source_id=source, target_id=target, kind=kind
        )
        self.merge(self.flows, item)
        if boundary:
            bid = stable("boundary", id)
            # A candidate crossing is inferred even when the underlying relation is observed.
            self.boundaries[bid] = Boundary(
                **self.common(bid, tenant, ref, method, status="INFERRED"),
                flow_id=id,
                source_id=source,
                target_id=target,
                label=boundary,
            )
        return id

    def snapshot(self):
        data = dict(
            context=self.context.model_copy(deep=True),
            assets=[self.assets[k] for k in sorted(self.assets)],
            endpoints=[self.endpoints[k] for k in sorted(self.endpoints)],
            flows=[self.flows[k] for k in sorted(self.flows)],
            trust_boundaries=[self.boundaries[k] for k in sorted(self.boundaries)],
            observations=[self.observations[k] for k in sorted(self.observations)],
            coverage=sorted(self.coverage, key=lambda c: (c.source, c.target, c.status)),
        )
        snapshot = Snapshot.model_validate({**data, "snapshot_digest": "0" * 64})
        snapshot.snapshot_digest = digest(architecture(snapshot))
        return snapshot


def diff(before: Snapshot, after: Snapshot) -> dict:
    results = {}
    for name in ("assets", "endpoints", "flows", "trust_boundaries"):
        old = {x.id: semantic(x.model_dump(mode="json")) for x in getattr(before, name)}
        new = {x.id: semantic(x.model_dump(mode="json")) for x in getattr(after, name)}
        results[name] = dict(
            added=[new[k] for k in sorted(new.keys() - old.keys())],
            removed=[old[k] for k in sorted(old.keys() - new.keys())],
            changed=[
                dict(
                    id=k,
                    before=old[k],
                    after=new[k],
                    changed_fields=sorted(field for field in old[k] if old[k][field] != new[k][field]),
                    change_type="provenance-only"
                    if all(
                        old[k][field] == new[k][field]
                        for field in old[k]
                        if field not in ("source_refs", "evidence_claims")
                    )
                    else "inventory",
                )
                for k in sorted(new.keys() & old.keys())
                if old[k] != new[k]
            ],
        )
    return dict(
        schema_version="1.0",
        before=before.snapshot_digest,
        after=after.snapshot_digest,
        classification="inventory change; not a vulnerability",
        changes=results,
        policy_changed=before.context.policy_digest != after.context.policy_digest,
    )
