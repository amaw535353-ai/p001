"""Explicit crossings, real directed hops and bounded simple paths."""

from p005.domain.schemas import Boundary, BoundaryReason, Model, ThreatPath
from p005.evidence.safety import Invalid, stable


def boundaries(model: Model) -> list[Boundary]:
    nodes = {n.id: n for n in model.nodes}
    zones = {z.id: z for z in model.zones}
    found = []
    for edge in model.flows:
        left, right = nodes[edge.source], nodes[edge.target]
        reasons: list[BoundaryReason] = []
        if left.zone_id != right.zone_id:
            reasons.append("ZONE")
        if left.tenant_id != right.tenant_id:
            reasons.append("TENANT")
        if left.owner_role != right.owner_role:
            reasons.append("OWNER")
        if (
            edge.kind in ("authenticates", "delegates", "authorizes")
            or left.principal_id != right.principal_id
        ):
            reasons.append("IDENTITY")
        if left.kind == "Agent" and right.kind in ("Tool", "MCPServer"):
            reasons.append("AGENT_TOOL")
        if left.kind == "ApprovalGate" or right.kind == "ApprovalGate":
            reasons.append("APPROVAL")
        if left.features.untrusted_content:
            reasons.append("CONTENT")
        if right.kind in ("ExternalDependency", "ModelEndpoint", "LLMGateway"):
            reasons.append("PROVIDER")
        if edge.kind == "deploys":
            reasons.append("CONTROL_PLANE")
        if "UNKNOWN" in (zones[left.zone_id].trust_level, zones[right.zone_id].trust_level):
            reasons.append("UNKNOWN_TRUST")
        if not reasons:
            continue
        found.append(
            Boundary(
                id=stable("boundary", edge.id, sorted(reasons)),
                zone_pair=[left.zone_id, right.zone_id],
                edge_ids=[edge.id],
                reasons=reasons,
                actor_ids=[edge.principal_id] if edge.principal_id else [],
                epistemic_status="INFERRED",
                evidence_refs=edge.evidence_refs,
                confidence="INFERENCE",
                assumptions=["Candidate boundary derived from declared graph; human confirmation required"],
            )
        )
    return sorted(found, key=lambda b: b.id)


def validate_path(model: Model, path: ThreatPath) -> None:
    edges = {e.id: e for e in model.flows}
    boundary_map = {b.id: b for b in model.boundaries}
    self_loop = len(path.edge_ids) == 1 and len(path.node_ids) == 2 and path.node_ids[0] == path.node_ids[1]
    if len(path.node_ids) != len(path.edge_ids) + 1 or (
        len(set(path.node_ids)) != len(path.node_ids) and not self_loop
    ):
        raise Invalid("INVALID-SIMPLE-PATH")
    for index, eid in enumerate(path.edge_ids):
        if eid not in edges or [edges[eid].source, edges[eid].target] != path.node_ids[index : index + 2]:
            raise Invalid("FABRICATED-OR-REVERSED-HOP")
    if any(
        b not in boundary_map or not set(boundary_map[b].edge_ids) & set(path.edge_ids)
        for b in path.boundary_ids
    ):
        raise Invalid("PATH-BOUNDARY-REFERENCE")


def path_for(model: Model, edge_id: str) -> ThreatPath:
    edge = next(e for e in model.flows if e.id == edge_id)
    # A single actual edge is the minimal candidate. Extend only through modeled
    # directed edges with the same tenant and explicitly equal principal; never
    # infer onward privilege from connectivity alone.
    ids = [edge.source, edge.target]
    hops = [edge.id]
    while len(hops) < 4 and edge.principal_id and len(set(ids)) == len(ids):
        candidates = sorted(
            (
                e
                for e in model.flows
                if e.source == ids[-1]
                and e.target not in ids
                and e.tenant_id == edge.tenant_id
                and e.principal_id == edge.principal_id
            ),
            key=lambda e: e.id,
        )
        if not candidates:
            break
        nxt = candidates[0]
        hops.append(nxt.id)
        ids.append(nxt.target)
    path = ThreatPath(
        id=stable("path", hops),
        node_ids=ids,
        edge_ids=hops,
        boundary_ids=sorted(b.id for b in model.boundaries if set(b.edge_ids) & set(hops)),
        uncertainty="Modeled connectivity only; reachability, authorization and preconditions NOT_TESTED",
    )
    validate_path(model, path)
    return path
