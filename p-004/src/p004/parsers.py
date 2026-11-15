"""Local declarative adapters only. Never evaluate, import or dereference source text."""

import ast
import copy
from pathlib import Path
import re
import tomllib

from p004.graph import Graph, stable
from p004.models import ArchitectureDeclaration, Coverage, EvidenceClaim, InputConfig, Source
from p004.safety import Invalid, address, digest, load, read_bytes, route


def reference(root: Path, path: str, pointer="/", line=None) -> Source:
    return Source(path=path, sha256=digest(read_bytes(root, path)), pointer=pointer, line=line)


def manifest(g: Graph, data: dict, ref: Source, method="static"):
    data = ArchitectureDeclaration.model_validate(data).model_dump(mode="json", exclude_none=True)
    if data.get("schema_version") != "p004-architecture-v1" or set(data) - {
        "schema_version",
        "assets",
        "flows",
    }:
        raise Invalid("ARCHITECTURE-CONTRACT")
    ids = {}
    for row in data["assets"]:
        if set(row) - {"key", "kind", "tenant_id", "label", "address", "attributes", "endpoints"}:
            raise Invalid("UNKNOWN-ASSET-FIELD")
        tenant = row["tenant_id"]
        key = (tenant, row["key"])
        if key in ids:
            raise Invalid("DUPLICATE-ASSET-KEY")
        ids[key] = g.asset(
            row["key"],
            row["kind"],
            tenant,
            ref,
            method,
            label=row.get("label"),
            address=row.get("address"),
            attributes=row.get("attributes", {}),
        )
        for endpoint in row.get("endpoints", []):
            g.endpoint(
                ids[key],
                endpoint["path"],
                endpoint["method"],
                ref,
                method,
                origin=row.get("address"),
                auth=endpoint.get("auth", "unknown"),
            )
    for flow in data.get("flows", []):
        source = ids[(flow["tenant_id"], flow["source"])]
        target = ids[(flow.get("target_tenant", flow["tenant_id"]), flow["target"])]
        g.flow(
            source,
            target,
            flow["kind"],
            ref,
            method,
            status="DECLARED",
            boundary=flow.get("boundary"),
            attributes={"identity_assumption": "not verified"},
        )
    return len(data["assets"])


def openapi(g: Graph, data: dict, ref: Source, tenant="tenant-a", key="openapi-service", origin=None):
    if not isinstance(data.get("openapi"), str) or not data["openapi"].startswith("3."):
        raise Invalid("OPENAPI-3-REQUIRED")
    if not isinstance(data.get("paths"), dict) or not isinstance(data.get("info"), dict):
        raise Invalid("OPENAPI-CONTRACT")
    service = g.asset(
        key,
        "api-service",
        tenant,
        ref,
        "openapi",
        label=data["info"].get("title", key),
        address=origin,
        attributes={"api_version": data["info"].get("version", "unknown")},
    )
    count = 0
    for path, methods in sorted(data["paths"].items()):
        route(path)
        if not isinstance(methods, dict):
            raise Invalid("OPENAPI-PATH-OBJECT")
        for method, operation in sorted(methods.items()):
            if method not in ("get", "head", "options", "post", "put", "patch", "delete"):
                if method == "$ref":
                    g.note("UNVERIFIED", "coverage", "OpenAPI reference not dereferenced", [ref])
                continue
            if not isinstance(operation, dict):
                raise Invalid("OPENAPI-OPERATION-OBJECT")
            g.endpoint(
                service,
                path,
                method.upper(),
                ref,
                "openapi",
                origin=origin,
                api_version=str(data["info"].get("version", "unknown")),
                auth="declared" if operation.get("security", data.get("security")) else "unknown",
                attributes={
                    "request_class": "schema-declared" if "requestBody" in operation else "unknown",
                    "response_class": "schema-declared" if "responses" in operation else "unknown",
                },
            )
            count += 1
    return count


KUBE_KINDS = {
    "Namespace": "namespace",
    "Service": "api-service",
    "Deployment": "container",
    "Pod": "container",
    "StatefulSet": "container",
    "ServiceAccount": "service-account",
    "Role": "other",
    "RoleBinding": "other",
    "NetworkPolicy": "other",
    "Ingress": "other",
}


def kubernetes(g: Graph, data, ref: Source, method="static"):
    rows = data.get("items", [data]) if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise Invalid("KUBERNETES-CONTRACT")
    index = {}
    for i, row in enumerate(rows):
        kind = row.get("kind")
        if kind not in KUBE_KINDS:
            continue  # Secrets, ConfigMap bodies and unknown resources are never exported.
        meta = row["metadata"]
        ns = meta.get("namespace", meta["name"] if kind == "Namespace" else "default")
        key = f"kube:{ns}:{kind}:{meta['name']}"
        attrs = {"kubernetes_kind": kind, "namespace": ns, "runtime_enforcement": "NOT TESTED"}
        spec = row.get("spec", {})
        if kind == "Service":
            attrs.update(
                service_type=spec.get("type", "ClusterIP"),
                ports=spec.get("ports", []),
                exposure="declared-only; runtime not verified",
            )
        if kind == "NetworkPolicy":
            attrs["policy_types"] = spec.get("policyTypes", [])
            attrs["policy_digest"] = digest(spec)
        if kind in ("Role", "RoleBinding"):
            attrs["grant_digest"] = digest(
                {"rules": row.get("rules", []), "subjects": row.get("subjects", [])}
            )
        pointer = ("/items/" if isinstance(data, dict) and "items" in data else "/") + str(i)
        row_ref = ref.model_copy(update={"pointer": pointer})
        id = g.asset(
            key, KUBE_KINDS[kind], ns, row_ref, method, label=f"{ns}/{meta['name']} {kind}", attributes=attrs
        )
        index[(ns, kind, meta["name"])] = (id, row)
    for (ns, kind, _name), (id, row) in index.items():
        namespace = index.get((ns, "Namespace", ns))
        if namespace and kind != "Namespace":
            g.flow(namespace[0], id, "hosts", ref, method)
        spec = row.get("spec", {})
        if kind == "Service":
            selectors = spec.get("selector", {})
            for (other_ns, other_kind, _), (target, workload) in index.items():
                labels = workload.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {})
                if (
                    ns == other_ns
                    and other_kind in ("Deployment", "StatefulSet")
                    and selectors
                    and all(labels.get(k) == v for k, v in selectors.items())
                ):
                    g.flow(id, target, "exposed-via", ref, method, boundary="service to workload")
        template = spec.get("template", {}).get("spec", spec if kind == "Pod" else {})
        account = template.get("serviceAccountName")
        if account and (ns, "ServiceAccount", account) in index:
            g.flow(
                id,
                index[(ns, "ServiceAccount", account)][0],
                "authenticates",
                ref,
                method,
                boundary="workload to declared service identity",
            )
    return len(rows)


def compose(g: Graph, data, ref: Source):
    if not isinstance(data.get("services"), dict) or any(k in data for k in ("include", "extends")):
        raise Invalid("COMPOSE-CONTRACT")
    for name, service in sorted(data["services"].items()):
        if "extends" in service:
            raise Invalid("COMPOSE-REMOTE-INCLUDES-FORBIDDEN")
        g.asset(
            "compose:" + name,
            "container",
            "unassigned",
            ref,
            label=name,
            attributes={
                "ports": service.get("ports", []),
                "image": service.get("image", "unknown"),
                "runtime_enforcement": "NOT TESTED",
            },
        )
    return len(data["services"])


def python_routes(g: Graph, raw: bytes, ref: Source, key="source-service", tenant="tenant-a"):
    try:
        tree = ast.parse(raw)
    except (SyntaxError, RecursionError) as exc:
        raise Invalid("PYTHON-SOURCE-PARSE") from exc
    service = g.asset(key, "api-service", tenant, ref, label=key)
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute) or not dec.args:
                    continue
                method = dec.func.attr.upper()
                if method in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH") and isinstance(
                    dec.args[0], ast.Constant
                ):
                    p = dec.args[0].value
                    if isinstance(p, str):
                        loc = Source(**{**ref.model_dump(), "line": node.lineno})
                        g.endpoint(
                            service,
                            route(p),
                            method,
                            loc,
                            "static",
                            status="UNVERIFIED",
                            constraints=["Source route candidate; reachability not tested"],
                        )
                        count += 1
    return count


def dependency_manifest(g: Graph, raw: bytes, ref: Source, path: str):
    if path.endswith(".toml"):
        data = tomllib.loads(raw.decode())
        dependencies = data.get("project", {}).get("dependencies", [])
    else:
        dependencies = raw.decode().splitlines()
    names = []
    for dep in dependencies:
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]{0,99})(?:\[[^]]+\])?(==[A-Za-z0-9.+_-]+)?(?:\s|$|[<>=;])",
            dep.strip(),
        )
        if match:
            names.append(match[1] + (match[2] or ""))
    g.asset(
        "dependencies:" + path,
        "ci-cd",
        "unassigned",
        ref,
        label="Dependency declaration",
        attributes={"packages": sorted(set(names)), "supply_chain_verification": "NOT TESTED"},
    )
    return len(names)


def env_example(g: Graph, raw: bytes, ref: Source, path: str):
    if not path.endswith(".example"):
        raise Invalid("ONLY-ENV-EXAMPLE-ALLOWED")
    names = sorted(set(re.findall(r"^([A-Z][A-Z0-9_]{0,99})=", raw.decode(), re.M)))
    # Only variable names, never their values or shell expansions, are retained.
    g.asset(
        "env-example:" + path,
        "other",
        "unassigned",
        ref,
        label="Environment requirement names only",
        attributes={"variable_names": names},
    )
    return len(names)


def dockerfile(g: Graph, raw: bytes, ref: Source):
    # RUN, COPY and all shell expansions remain unexecuted source data.
    bases = re.findall(r"^FROM\s+([A-Za-z0-9/_.:@-]+)(?:\s|$)", raw.decode(), re.M | re.I)
    g.asset(
        "dockerfile:" + ref.path,
        "container",
        "unassigned",
        ref,
        label="Dockerfile declared image",
        attributes={"base_images": bases, "runtime": "NOT TESTED"},
    )
    return len(bases)


def p001(g: Graph, root: Path):
    paths = ["infra/kubernetes/bootstrap.json", "infra/kubernetes/resources.json"]
    count = 0
    for path in paths:
        ref = reference(root, path)
        count += kubernetes(g, load(root, path), ref, "p001")
    cluster_path = "infra/kind/cluster.yaml"
    cluster_ref = reference(root, cluster_path)
    cluster_data = load(root, cluster_path)
    if (
        cluster_data.get("kind") != "Cluster"
        or cluster_data.get("networking", {}).get("apiServerAddress") != "127.0.0.1"
    ):
        raise Invalid("P001-CLUSTER-SOURCE-CONTRACT-CHANGED")
    cluster = g.asset(
        "p001:kind:cluster",
        "cluster",
        "unassigned",
        cluster_ref,
        "p001",
        label="P001 declared kind cluster",
        attributes={"networking": cluster_data["networking"], "runtime": "NOT TESTED"},
    )
    count += 1
    for namespace in [a for a in g.assets.values() if a.kind == "namespace" and a.discovery_method == "p001"]:
        g.flow(cluster, namespace.id, "hosts", cluster_ref, "p001", boundary="cluster to declared namespace")
    path = "services/common/app.py"
    ref = reference(root, path)
    tree = ast.parse(read_bytes(root, path))
    strings = {x.value for x in ast.walk(tree) if isinstance(x, ast.Constant) and isinstance(x.value, str)}
    expected = {
        "/healthz",
        "/readyz",
        "/infer",
        "/objects/",
        "http://mock:8080/infer",
        "http://localstack.emulator.svc.cluster.local:4566",
    }
    if not expected <= strings:
        raise Invalid("P001-SOURCE-CONTRACT-CHANGED")
    script = read_bytes(root, "scripts/lab-up").decode()
    forward_ref = reference(root, "scripts/lab-up")
    for tenant, port in re.findall(r"^forward (tenant-[ab]) api (\d+) 8080$", script, re.M):
        origin = f"http://127.0.0.1:{port}"
        api = g.asset(
            f"p001:{tenant}:api",
            "api-service",
            tenant,
            ref,
            "p001",
            label=f"P001 {tenant} API",
            address=origin,
            attributes={"runtime_enforcement": "NOT TESTED", "authentication": "declared fixture bearer"},
        )
        original = g.assets[api]
        g.assets[api] = original.model_copy(
            update={
                "source_refs": [ref, forward_ref],
                "evidence_claims": [
                    *original.evidence_claims,
                    EvidenceClaim(
                        source_ref=forward_ref,
                        discovery_method="p001",
                        status="DECLARED",
                        measured_scope="exact loopback port-forward declaration; runtime not tested",
                    ),
                ],
            }
        )
        service_id = stable("asset", g.context.environment_id, tenant, f"kube:{tenant}:Service:api")
        if service_id in g.assets:
            g.flow(
                api,
                service_id,
                "exposed-via",
                forward_ref,
                "p001",
                boundary="declared loopback forward to cluster service",
            )
        mock = g.asset(
            f"p001:{tenant}:mock",
            "model-endpoint",
            tenant,
            ref,
            "p001",
            label="deterministic mock; not an LLM",
        )
        workload = g.asset(
            f"p001:{tenant}:sdk", "workload-identity", tenant, ref, "p001", label="synthetic SDK identity"
        )
        store = g.asset(f"p001:{tenant}:bucket", "object-store", tenant, ref, "p001", label=f"p001-{tenant}")
        user = g.asset(
            f"p001:{tenant}:caller", "human-identity", tenant, ref, "p001", label="synthetic caller"
        )
        telemetry = g.asset(
            f"p001:{tenant}:logs", "telemetry", tenant, ref, "p001", label="allowlisted local stdout"
        )
        for verb, p in [
            ("GET", "/healthz"),
            ("GET", "/readyz"),
            ("POST", "/infer"),
            ("GET", "/objects/{key}"),
            ("PUT", "/objects/{key}"),
        ]:
            g.endpoint(
                api,
                p,
                verb,
                ref,
                "p001",
                origin=address(origin).removesuffix("/"),
                auth="declared",
                constraints=["Reviewed source contract, not a reachability observation"],
            )
        for a, b, kind, boundary in [
            (user, api, "invokes", "caller to API"),
            (api, mock, "invokes", "API to model simulator"),
            (api, workload, "authenticates", "API to workload credential"),
            (workload, store, "reads", "workload to emulator store"),
            (api, telemetry, "emits-telemetry", "application to log sink"),
        ]:
            g.flow(a, b, kind, ref, "p001", boundary=boundary)
    g.note("NOT_TESTED", "coverage", "P001 runtime, IAM and CNI enforcement not inferred from source", [ref])
    return count


def p002(g: Graph, data: dict, ref: Source):
    # Real sibling typed validator is deliberately required; no permissive structural fallback.
    from p002.models import Dataset

    dataset = Dataset.model_validate(data)
    if dataset.mode != "fixtures":
        raise Invalid("P002-FIXTURES-ONLY")
    g.context.dataset_seed = dataset.seed
    ids = {}
    for table, kind in [
        (dataset.tenants, "tenant"),
        (dataset.departments, "other"),
        (dataset.groups, "other"),
        (dataset.humans, "human-identity"),
        (dataset.workloads, "workload-identity"),
        (dataset.resources, "document"),
    ]:
        for row in table:
            resource_kind = getattr(row, "kind", None)
            actual_kind = kind
            if resource_kind:
                actual_kind = {
                    "cloud-object": "object-store",
                    "folder": "other",
                    "tool-config": "other",
                    "mock-dataset": "other",
                    "project": "other",
                }.get(resource_kind, "document")
            ids[row.id] = g.asset(
                row.id,
                actual_kind,
                row.tenant_id,
                ref,
                "p002",
                label=row.id,
                attributes={
                    "classification": str(getattr(row, "classification", "synthetic")),
                    "declared_status": row.status,
                    "permission_enforcement": "NOT TESTED",
                    "source_record_type": type(row).__name__,
                    "source_resource_kind": resource_kind,
                    "department_id": getattr(row, "department_id", None),
                    "owner_id": row.owner_id,
                    "synthetic_role": getattr(row, "role", None),
                },
            )
    for grant in dataset.grants:
        if grant.principal_id in ids and grant.resource_id in ids:
            g.flow(
                ids[grant.principal_id],
                ids[grant.resource_id],
                "authorizes",
                ref,
                "p002",
                attributes={"effect": grant.effect, "actions": grant.actions, "grant_id": grant.id},
                boundary="declared application permission, not assessment authorization",
            )
    g.note(
        "DECLARED",
        "coverage",
        "P002 application oracle never grants P004 test authorization",
        [ref],
        details={
            "scenario_labels": [{"id": s.id, "status": s.status} for s in dataset.scenarios],
            "logical_time": dataset.logical_time,
            "permission_staleness": "NOT TESTED; no target contacted",
        },
    )
    return len(ids)


def policy_context(g: Graph, data: dict, ref: Source):
    from p003.models import Engagement, verified

    spec = Engagement.model_validate(data)
    verified(spec)
    for row in spec.assets:
        g.asset(
            row.asset_id,
            "api-service",
            row.tenant,
            ref,
            "p003",
            label=row.service,
            address=row.selector.value if row.selector.kind == "url" else None,
            attributes={
                "included_proposal": row.included,
                "included_in_scope": row.asset_id in spec.scope.included_asset_ids,
                "methods": row.methods,
                "ownership_declaration": row.ownership,
                "engagement_id": spec.engagement_id,
                "version": spec.version,
                "policy_digest": spec.content_digest,
                "live_authority": "NOT VERIFIED",
                "permitted_activity_classes": spec.scope.activities,
                "utc_window": spec.window.model_dump(),
                "excluded_resources": [e.selector.model_dump() for e in spec.scope.exclusions],
                "evidence_rules": {
                    "data_class": spec.evidence_policy.data_class,
                    "storage_ids": spec.evidence_policy.storage_ids,
                    "retention_days": spec.evidence_policy.retention_days,
                    "redact_before_export": spec.evidence_policy.redact_before_export,
                },
            },
        )
    g.note(
        "UNVERIFIED",
        "coverage",
        "Imported P003 document is context only; approval requires live ledger replay",
        [ref],
    )
    return len(spec.assets)


def inventory(root: Path, config_path: str, g: Graph):
    config = InputConfig.model_validate(load(root, config_path)).model_dump(mode="json", exclude_none=True)
    if config.get("schema_version") != "p004-input-v1" or set(config) != {"schema_version", "inputs"}:
        raise Invalid("INPUT-CONFIG-CONTRACT")
    if not 1 <= len(config["inputs"]) <= 100:
        raise Invalid("INPUT-COUNT-LIMIT")
    total = 0
    for entry in config["inputs"]:
        if not isinstance(entry, dict) or set(entry) - {"kind", "path", "key", "tenant_id", "origin"}:
            raise Invalid("INPUT-ENTRY-CONTRACT")
        kind = entry["kind"]
        path = entry.get("path", "P001-source-contract")
        checkpoint = copy.deepcopy(g.__dict__)
        try:
            if kind == "p001":
                count = p001(g, root)
            else:
                raw = read_bytes(root, path)
                total += len(raw)
                if total > 10_000_000:
                    raise Invalid("TOTAL-INPUT-LIMIT")
                ref = reference(root, path)
                if kind == "dependencies":
                    count = dependency_manifest(g, raw, ref, path)
                elif kind == "env-example":
                    count = env_example(g, raw, ref, path)
                elif kind == "dockerfile":
                    count = dockerfile(g, raw, ref)
                elif kind == "python":
                    count = python_routes(g, raw, ref, key=entry.get("key", "source-service"))
                else:
                    data = load(root, path)
                    if kind in ("architecture", "onyx", "openhands"):
                        count = manifest(g, data, ref)
                        if kind != "architecture":
                            g.note(
                                "NOT_TESTED",
                                "coverage",
                                f"{kind} local manifest only; vendor API not tested",
                                [ref],
                            )
                    elif kind == "openapi":
                        count = openapi(
                            g,
                            data,
                            ref,
                            entry.get("tenant_id", "tenant-a"),
                            entry.get("key", "openapi-service"),
                            entry.get("origin"),
                        )
                    elif kind == "kubernetes":
                        count = kubernetes(g, data, ref)
                    elif kind == "compose":
                        count = compose(g, data, ref)
                    elif kind == "p002":
                        count = p002(g, data, ref)
                    elif kind == "p003":
                        count = policy_context(g, data, ref)
                    elif kind == "iac-reviewed":
                        if (
                            set(data) != {"schema_version", "reviewed", "inventory"}
                            or data["schema_version"] != "p004-reviewed-iac-v1"
                            or data["reviewed"] is not True
                        ):
                            raise Invalid("REVIEWED-IAC-PROJECTION-REQUIRED")
                        count = manifest(g, data["inventory"], ref)
                    else:
                        raise Invalid("UNSUPPORTED-INPUT-KIND")
            g.coverage.append(
                Coverage(
                    source=kind,
                    target=path,
                    status="discovered",
                    known_denominator=count,
                    processed=count,
                    reason="Known input entries only; unknown attack surface has no denominator",
                )
            )
        except (ValueError, TypeError, KeyError, OSError, ImportError, RecursionError) as exc:
            g.__dict__ = checkpoint
            g.context.outcome = "PARTIAL"
            g.coverage.append(
                Coverage(
                    source=kind,
                    target=path,
                    status="error",
                    processed=0,
                    reason="Input failed validation; no raw data retained",
                )
            )
            g.note(
                "ERROR",
                "error",
                "Input rejected; inspect local source with a human",
                details={"source_kind": kind, "error_class": type(exc).__name__},
            )
    return g.snapshot()
