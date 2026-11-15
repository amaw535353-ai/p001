"""Actual local contracts only. No network, state files or target-side claims."""

from pathlib import Path

from p005 import __version__
from p005.domain.schemas import Model
from p005.evidence.safety import Invalid, digest, load, redact, stable
from p005.modeling.graph import boundaries


def base(source: str, source_hash: str, tenants: list[str]) -> dict:
    return dict(
        schema_version="p005-model-1.0",
        model_id=stable("model", source),
        engagement_id="synthetic-import",
        engagement_version=1,
        system_id="synthetic-import",
        model_version=1,
        created_utc="2026-11-15T00:00:00Z",
        snapshot_source=source,
        source_snapshot_hash=source_hash,
        git_commit="UNKNOWN",
        dataset_seed=2026,
        tool_versions={"p005": __version__},
        environment_id="synthetic-lab",
        assumptions=["Imported metadata is not proof of authorization, reachability or enforcement"],
        exclusions=["All live execution"],
        model_scope=dict(source=source, in_scope_node_ids=[]),
        tenants=sorted(set(tenants)),
        zones=[],
        nodes=[],
        flows=[],
        evidence=[],
        integrations=[],
    )


def zone(data: dict, tenant: str, ev: str) -> str:
    zid = stable("zone", tenant, "UNKNOWN-imported-zone")
    if not any(z["id"] == zid for z in data["zones"]):
        data["zones"].append(
            dict(
                id=zid,
                label="Unverified zone for imported tenant",
                tenant_id=tenant,
                owner_role="source-owner-unknown",
                trust_level="UNKNOWN",
                evidence_refs=[ev],
            )
        )
    return zid


def evidence(
    data: dict, source: str, pointer: str, status="DECLARED", measured="Source declaration only"
) -> str:
    eid = stable("evidence", source, pointer, status)
    if not any(e["id"] == eid for e in data["evidence"]):
        data["evidence"].append(
            dict(
                id=eid,
                source=source,
                pointer=pointer,
                sanitized_sha256=data["source_snapshot_hash"],
                status=status,
                measured_scope=measured,
            )
        )
    return eid


def finish(data: dict, project: str, path: Path) -> Model:
    data["integrations"] = [
        dict(
            project=project,
            status="VERIFIED",
            evidence_refs=[path.name],
            reason="Validated actual local source contract; metadata import only, no target validation",
        )
    ]
    model = Model.model_validate(redact(data))
    data = model.model_dump()
    data["boundaries"] = [b.model_dump() for b in boundaries(model)]
    return Model.model_validate(data)


KINDS = {
    "human-identity": "HumanIdentity",
    "workload-identity": "WorkloadIdentity",
    "service-account": "WorkloadIdentity",
    "identity-provider": "IdentityProvider",
    "agent": "Agent",
    "mcp-tool": "MCPServer",
    "a2a-peer": "A2APeer",
    "model-endpoint": "ModelEndpoint",
    "connector": "Connector",
    "retrieval-pipeline": "Retriever",
    "vector-db": "VectorDatabase",
    "api-service": "API",
    "object-store": "DataStore",
    "database": "DataStore",
    "document": "DocumentCollection",
    "namespace": "KubernetesNamespace",
    "telemetry": "TelemetrySink",
    "ci-cd": "CIPipeline",
    "secret-manager": "SecretStore",
    "ui": "Browser",
}


def p004(path: Path) -> Model:
    try:
        from p004.models import Snapshot
        from p004.graph import architecture
        from p004.safety import digest as p004_digest
    except ImportError as exc:
        raise Invalid("P004-CONTRACT-NOT-INSTALLED: install the local sibling for this adapter") from exc
    raw = load(path)
    if raw.get("schema_version") != "1.0":
        raise Invalid("P004-INCOMPATIBLE-SCHEMA")
    snapshot = Snapshot.model_validate(raw)
    if p004_digest(architecture(snapshot)) != snapshot.snapshot_digest:
        raise Invalid("P004-SNAPSHOT-DIGEST-MISMATCH")
    data = base(path.name, digest(redact(raw)), [a.tenant_id for a in snapshot.assets])
    data.update(
        engagement_id=snapshot.context.engagement_id or "unassigned-engagement",
        engagement_version=snapshot.context.approved_engagement_version or 1,
        git_commit=snapshot.context.git_commit,
        dataset_seed=snapshot.context.dataset_seed or 0,
    )
    ids = {a.id: stable("node", "P004", a.tenant_id, a.id) for a in snapshot.assets}
    evidence_map = {}
    for asset in [*snapshot.assets, *snapshot.flows]:
        status = "UNKNOWN" if asset.status == "NOT_APPLICABLE" else asset.status
        refs = []
        for index, claim in enumerate(asset.evidence_claims):
            refs.append(
                evidence(
                    data,
                    path.name,
                    f"/{asset.id}/evidence_claims/{index}",
                    "UNKNOWN" if claim.status == "NOT_APPLICABLE" else claim.status,
                    claim.measured_scope
                    + "; source="
                    + claim.source_ref.path
                    + "; pointer="
                    + claim.source_ref.pointer
                    + "; sha256="
                    + claim.source_ref.sha256,
                )
            )
        if status == "OBSERVED" and not any(
            e["status"] == "OBSERVED" and e["id"] in refs for e in data["evidence"]
        ):
            raise Invalid("P004-OBSERVED-WITHOUT-OBSERVATION-EVIDENCE")
        evidence_map[asset.id] = (refs, status)
    for asset in snapshot.assets:
        refs, status = evidence_map[asset.id]
        data["nodes"].append(
            dict(
                id=ids[asset.id],
                source_id=asset.id,
                kind=KINDS.get(asset.kind, "Asset"),
                label=asset.label,
                address=asset.address,
                owner_role="source-owner-unknown",
                zone_id=zone(data, asset.tenant_id, refs[0]),
                tenant_id=asset.tenant_id,
                evidence_refs=refs,
                epistemic_status=status,
                confidence="DIRECT_METADATA"
                if status == "OBSERVED"
                else "DECLARATION"
                if status == "DECLARED"
                else "INFERENCE",
                assumptions=["P004 measured scope is limited; labels do not establish runtime controls"],
                source_snapshot=data["source_snapshot_hash"],
                surface=[
                    f"{e.method} {e.path} ({e.status})" for e in snapshot.endpoints if e.asset_id == asset.id
                ][:32],
            )
        )
    for flow in snapshot.flows:
        refs, status = evidence_map[flow.id]
        if flow.source_id not in ids or flow.target_id not in ids:
            raise Invalid("P004-ORPHAN-FLOW")
        # A P004 actor label is not always an asset ID. Never invent a principal.
        principal = ids.get(flow.actor_id)
        if principal and next(n for n in data["nodes"] if n["id"] == principal)["kind"] not in (
            "Actor",
            "HumanIdentity",
            "WorkloadIdentity",
        ):
            principal = None
        kind = (
            flow.kind
            if flow.kind
            in (
                "invokes",
                "retrieves",
                "delegates",
                "authenticates",
                "authorizes",
                "reads",
                "writes",
                "stores",
                "hosts",
                "transmits",
            )
            else "transmits"
        )
        source_node = next(n for n in data["nodes"] if n["id"] == ids[flow.source_id])
        data["flows"].append(
            dict(
                id=stable("flow", "P004", flow.id),
                source_id=flow.id,
                source=ids[flow.source_id],
                target=ids[flow.target_id],
                kind=kind,
                tenant_id=source_node["tenant_id"],
                principal_id=principal,
                data_type="UNKNOWN (P004 relation: " + flow.kind + ")",
                evidence_refs=refs,
                epistemic_status=status,
                confidence="INFERENCE"
                if status == "INFERRED"
                else "DIRECT_METADATA"
                if status == "OBSERVED"
                else "DECLARATION",
                assumptions=[
                    flow.permission_assumption,
                    "Unknown authorization; no enforcement result inferred",
                ],
            )
        )
    data["assumptions"].append(
        "P004 candidate boundaries recomputed from unknown zones; original snapshot remains source"
    )
    data["exclusions"].append(
        "Missing observed flows do not prove absence; passive alerts remain unverified signals"
    )
    data["source_context"] = [
        dict(
            project="P-004",
            original_boundary_ids=[b.id + ":" + b.status for b in snapshot.trust_boundaries],
            coverage=[c.source + ":" + c.status + ":" + str(c.processed) for c in snapshot.coverage],
            observation_statuses=[o.id + ":" + o.status + ":" + o.category for o in snapshot.observations],
            passive_alerts=[
                o.id + ":UNVERIFIED_SIGNAL" for o in snapshot.observations if o.category == "passive-alert"
            ],
            source_status="Imported observations are source claims, never findings",
        )
    ]
    return finish(data, "P-004", path)


def p002(path: Path) -> Model:
    try:
        from p002.models import Dataset
    except ImportError as exc:
        raise Invalid("P002-CONTRACT-NOT-INSTALLED") from exc
    raw = load(path)
    if not isinstance(raw, dict) or raw.get("schema_version") != "1.0":
        raise Invalid("P002-INCOMPATIBLE-SCHEMA")
    dataset = Dataset.model_validate(raw)
    if dataset.mode != "fixtures":
        raise Invalid("P002-SYNTHETIC-FIXTURES-REQUIRED")
    data = base(path.name, digest(redact(dataset.model_dump(mode="json"))), [t.id for t in dataset.tenants])
    data["dataset_seed"] = dataset.seed
    ev = evidence(
        data,
        path.name,
        "/",
        measured="Synthetic application permissions are oracle expectations, not enforcement",
    )
    tables = [
        (dataset.humans, "HumanIdentity"),
        (dataset.workloads, "WorkloadIdentity"),
        (dataset.groups, "Actor"),
        (dataset.resources, "Asset"),
    ]
    ids = {}
    for rows, kind in tables:
        for row in rows:
            actual_kind = kind
            features: dict[str, str | bool] = {}
            if kind == "Asset":
                actual_kind = {
                    "document": "DocumentCollection",
                    "kb-page": "DocumentCollection",
                    "cloud-object": "DataStore",
                    "tool-config": "Tool",
                }.get(row.kind, "Asset")
                features["untrusted_content"] = any(
                    d.resource_id == row.id and d.trust == "untrusted-text" for d in dataset.documents
                )
                features["retention"] = "DECLARED"
            nid = stable("node", "P002", row.tenant_id, kind, row.id)
            ids[row.id] = nid
            data["nodes"].append(
                dict(
                    id=nid,
                    source_id=row.id,
                    kind=actual_kind,
                    features=features,
                    label=row.id,
                    owner_role="synthetic-data-owner",
                    tenant_id=row.tenant_id,
                    zone_id=zone(data, row.tenant_id, ev),
                    evidence_refs=[ev],
                    sensitivity=str(getattr(row, "classification", "UNKNOWN")),
                    source_snapshot=data["source_snapshot_hash"],
                    assumptions=[
                        "Source type: " + type(row).__name__,
                        "Declared record status: " + row.status,
                        "Grant effects, scenario outcomes and oracle decisions do not establish enforcement",
                    ],
                )
            )
    for grant in dataset.grants:
        if grant.principal_id not in ids or grant.resource_id not in ids:
            raise Invalid("P002-UNMAPPED-GRANT")
        source = next(n for n in data["nodes"] if n["id"] == ids[grant.principal_id])
        data["flows"].append(
            dict(
                id=stable("flow", "P002", grant.id),
                source_id=grant.id,
                source=ids[grant.principal_id],
                target=ids[grant.resource_id],
                kind="authorizes",
                tenant_id=source["tenant_id"],
                principal_id=ids[grant.principal_id],
                data_type="Synthetic declared grant",
                evidence_refs=[ev],
                declared_grant_effect=grant.effect,
                authorization="CONTROL_DECLARED",
                assumptions=[
                    "Grant declaration only, not a full temporal authorization decision; actual enforcement NOT_TESTED",
                    "Declared actions: " + ",".join(grant.actions),
                ],
            )
        )
    for decision in dataset.decisions:
        if decision.actor_id not in ids or decision.resource_id not in ids:
            raise Invalid("P002-UNMAPPED-ORACLE")
        actor = next(n for n in data["nodes"] if n["id"] == ids[decision.actor_id])
        data["flows"].append(
            dict(
                id=stable("flow", "P002-ORACLE", decision.id),
                source_id=decision.id,
                source=ids[decision.actor_id],
                target=ids[decision.resource_id],
                kind="authorizes",
                tenant_id=actor["tenant_id"],
                principal_id=ids[decision.actor_id],
                data_type="Synthetic expected " + decision.action + " authorization",
                evidence_refs=[ev],
                expected_decision=decision.expected,
                assumptions=[
                    "Generated oracle, never measured enforcement",
                    decision.reason,
                    "Context time: " + decision.context.time,
                ],
            )
        )
    data["source_context"] = [
        dict(
            project="P-002",
            logical_time=dataset.logical_time,
            scenario_ids=[s.id for s in dataset.scenarios],
            scenario_statuses=[s.id + ":" + s.status for s in dataset.scenarios],
            scenario_expectations=[s.id + ":" + s.test_oracle for s in dataset.scenarios],
            decision_origin="Generated oracle; no observed enforcement imported",
            document_content="Omitted; document trust and resource classifications retained",
        )
    ]
    return finish(data, "P-002", path)


def p003_context(model: Model, path: Path) -> Model:
    try:
        from p003.models import Engagement, verified
    except ImportError as exc:
        raise Invalid("P003-CONTRACT-NOT-INSTALLED") from exc
    data = load(path)
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise Invalid("P003-INCOMPATIBLE-SCHEMA")
    engagement = Engagement.model_validate(data)
    verified(engagement)
    result = model.model_dump()
    included = set(engagement.scope.included_asset_ids)
    source_ids = {a.asset_id for a in engagement.assets}
    excluded_urls = {e.selector.value for e in engagement.scope.exclusions if e.selector.kind == "url"}
    matched = {
        n.id: {
            a.asset_id
            for a in engagement.assets
            if n.tenant_id == a.tenant
            and (n.source_id == a.asset_id or (a.selector.kind == "url" and n.address == a.selector.value))
        }
        for n in model.nodes
    }
    result["engagement_id"] = engagement.engagement_id
    result["engagement_version"] = engagement.version
    result["model_scope"] = dict(
        source=path.name,
        source_digest=digest(redact(data)),
        in_scope_node_ids=[
            n.id for n in model.nodes if matched[n.id] & included and n.address not in excluded_urls
        ],
        out_of_scope_node_ids=[
            n.id for n in model.nodes if matched[n.id] & (source_ids - included) or n.address in excluded_urls
        ],
        prohibited_activities=["live-testing", "scanning", "cloud-changes"],
    )
    result["exclusions"] += ["P003 exclusion: " + e.reason for e in engagement.scope.exclusions]
    result["assumptions"] += [
        "P003 context only; no ledger replay, fresh ROE or real legal authority established",
        "Assessment window: " + engagement.window.start + " to " + engagement.window.end,
    ]
    result["source_context"] = [c for c in result["source_context"] if c.get("project") != "P-003"] + [
        dict(
            project="P-003",
            engagement_version=str(engagement.version),
            allowed_activity_classes=engagement.scope.activities,
            exclusions=[
                e.selector.kind + ":" + e.selector.value + ":" + e.reason for e in engagement.scope.exclusions
            ],
            window_start=engagement.window.start,
            window_end=engagement.window.end,
            ledger_and_revocation="NOT_TESTED; fresh executor-side authorization required",
        )
    ]
    result["integrations"] = [i for i in result["integrations"] if i["project"] != "P-003"] + [
        dict(
            project="P-003",
            status="VERIFIED",
            evidence_refs=[path.name],
            reason="Actual sealed Engagement contract validated; static scope only, no authority to execute",
        )
    ]
    result["review_state"] = "NEEDS_REVIEW"
    return Model.model_validate(result)


def p001(path: Path) -> Model:
    # Only the reviewed synthetic resources.json/bootstrap.json paths are accepted.
    from p005.evidence.safety import REPO

    if path.absolute() not in (
        REPO / "infra/kubernetes/resources.json",
        REPO / "infra/kubernetes/bootstrap.json",
    ):
        raise Invalid("P001-APPROVED-INVENTORY-PATH-REQUIRED: full state is never an input")
    raw = load(path)
    if not isinstance(raw, list) or not raw:
        raise Invalid("P001-INVENTORY-CONTRACT")
    # Do not retain bodies, ConfigMaps, env, Secrets, containers or state values.
    rows = []
    for row in raw:
        if row.get("kind") not in (
            "Namespace",
            "Service",
            "ServiceAccount",
            "NetworkPolicy",
            "Deployment",
            "Role",
            "RoleBinding",
        ):
            continue
        meta = row.get("metadata", {})
        if not meta.get("name"):
            raise Invalid("P001-MISSING-RESOURCE-NAME")
        rows.append(
            dict(
                kind=row["kind"],
                name=meta["name"],
                namespace=meta.get("namespace", meta["name"] if row["kind"] == "Namespace" else "shared"),
            )
        )
    data = base(path.name, digest(redact(rows)), [r["namespace"] for r in rows])
    ev = evidence(
        data, path.name, "/metadata-allowlist", measured="P001 declarations only; IAM/CNI runtime NOT_TESTED"
    )
    for row in rows:
        kind = {
            "Namespace": "KubernetesNamespace",
            "Service": "API",
            "ServiceAccount": "WorkloadIdentity",
        }.get(row["kind"], "CloudResource")
        data["nodes"].append(
            dict(
                id=stable("node", "P001", row),
                source_id="p001:" + row["namespace"] + ":" + row["name"],
                kind=kind,
                label=row["name"] + " " + row["kind"],
                owner_role="lab-platform-owner",
                zone_id=zone(data, row["namespace"], ev),
                tenant_id=row["namespace"],
                evidence_refs=[ev],
                source_snapshot=data["source_snapshot_hash"],
            )
        )
    return finish(data, "P-001", path)
