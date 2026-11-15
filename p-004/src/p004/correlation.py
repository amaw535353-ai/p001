"""Explicit cross-run correlation. A shared label never proves a shared principal."""

from p004.graph import Graph, stable
from p004.models import Boundary, Endpoint, Flow, Snapshot
from p004.safety import Invalid


def correlate(declared: Snapshot, observed: Snapshot, mapping: dict[str, str] | None = None) -> Snapshot:
    """Mapping is observed asset ID -> declared asset ID, manually reviewed.

    Remapping is allowed only for identical explicit tenant/environment/kind/address.
    Missing mappings preserve separate identities; no origin alias/DNS inference.
    """
    mapping = mapping or {}
    source = {a.id: a for a in observed.assets}
    target = {a.id: a for a in declared.assets}
    if len(set(mapping.values())) != len(mapping):
        raise Invalid("CORRELATION-MAPPING-NOT-ONE-TO-ONE")
    for old, new in mapping.items():
        if old not in source or new not in target:
            raise Invalid("CORRELATION-UNKNOWN-ASSET")
        original_asset, declared_asset = source[old], target[new]
        if (
            original_asset.tenant_id,
            original_asset.environment_id,
            original_asset.kind,
            original_asset.address,
        ) != (
            declared_asset.tenant_id,
            declared_asset.environment_id,
            declared_asset.kind,
            declared_asset.address,
        ) or not original_asset.address:
            raise Invalid("CORRELATION-CONTEXT-MISMATCH")
    ctx = observed.context.model_copy(deep=True)
    if declared.context.outcome != "COMPLETE" or observed.context.outcome != "COMPLETE":
        ctx.outcome = "PARTIAL"
    ctx.run_id = "correlated-" + stable("run", declared.snapshot_digest, observed.snapshot_digest)[4:]
    g = Graph(ctx)
    for snapshot in (declared, observed):
        remap = mapping if snapshot is observed else {}
        entity_remap = dict(remap)
        for a in snapshot.assets:
            id = remap.get(a.id, a.id)
            asset_record = type(a).model_validate({**a.model_dump(mode="json"), "id": id, "asset_id": id})
            g.merge(g.assets, asset_record)
        for e in snapshot.endpoints:
            asset = remap.get(e.asset_id, e.asset_id)
            id = stable("endpoint", asset, e.origin, e.method, e.path)
            entity_remap[e.id] = id
            g.merge(
                g.endpoints,
                Endpoint.model_validate({**e.model_dump(mode="json"), "id": id, "asset_id": asset}),
            )
        flow_remap = {}
        for f in snapshot.flows:
            source_id, target_id = remap.get(f.source_id, f.source_id), remap.get(f.target_id, f.target_id)
            id = stable("flow", source_id, target_id, f.kind)
            flow_remap[f.id] = id
            entity_remap[f.id] = id
            g.merge(
                g.flows,
                Flow.model_validate(
                    {**f.model_dump(mode="json"), "id": id, "source_id": source_id, "target_id": target_id}
                ),
            )
        for b in snapshot.trust_boundaries:
            id = stable("boundary", flow_remap[b.flow_id])
            entity_remap[b.id] = id
            g.boundaries[id] = Boundary.model_validate(
                {
                    **b.model_dump(mode="json"),
                    "id": id,
                    "flow_id": flow_remap[b.flow_id],
                    "source_id": remap.get(b.source_id, b.source_id),
                    "target_id": remap.get(b.target_id, b.target_id),
                }
            )
        for o in snapshot.observations:
            g.observations[o.id] = o.model_copy(
                update={"entity_ids": [entity_remap.get(x, x) for x in o.entity_ids]}
            )
        g.coverage.extend(snapshot.coverage)
    g.note(
        "UNVERIFIED",
        "coverage",
        "Correlation retains explicit mapping and provenance; reachability is not authorization",
        details={
            "asset_mapping": mapping,
            "before_digest": declared.snapshot_digest,
            "observed_digest": observed.snapshot_digest,
        },
    )
    return g.snapshot()
