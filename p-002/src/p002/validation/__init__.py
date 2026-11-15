"""Cross-table constraints supplement the published Pydantic JSON Schema."""

import hashlib
from typing import Any
import json
from datetime import datetime
from p002 import NOTICE


def digest(value):
    raw = (
        value
        if isinstance(value, bytes)
        else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )
    return hashlib.sha256(raw).hexdigest()


def validate_graph(d):
    datetime.strptime(d.logical_time, "%Y-%m-%dT%H:%M:%SZ")
    tables = d.tables()
    flat = [r for rows in tables.values() for r in rows]
    by = {r.id: r for r in flat}
    if len(by) != len(flat):
        raise ValueError("duplicate canonical ID")
    tenants = {r.id for r in d.tenants}
    humans = {r.id: r for r in d.humans}
    identities = set(humans) | {r.id for r in d.workloads}
    principals = identities | {r.id for r in d.groups}
    resources = {r.id: r for r in d.resources}

    def require(ref, allowed, label):
        if ref not in allowed:
            raise ValueError(f"dangling {label}: {ref}")

    relations = {
        "tenants": {"enterprise_id": "enterprises"},
        "departments": {"manager_id": "humans"},
        "humans": {"department_id": "departments", "manager_id": "humans"},
        "groups": {"department_id": "departments"},
        "memberships": {"group_id": "groups", "user_id": "humans"},
        "workloads": {"department_id": "departments"},
        "resources": {"department_id": "departments", "parent_id": "resources"},
        "folders": {"resource_id": "resources"},
        "documents": {"resource_id": "resources"},
        "versions": {"document_id": "documents"},
        "owners": {"resource_id": "resources", "user_id": "humans"},
        "projects": {"resource_id": "resources"},
        "issues": {
            "resource_id": "resources",
            "project_id": "projects",
            "reporter_id": "humans",
            "assignee_id": "humans",
        },
        "comments": {"issue_id": "issues", "author_id": "humans"},
        "tasks": {"document_id": "documents"},
        "annotations": {"task_id": "tasks", "annotator_id": "humans", "label_id": "labels"},
        "grants": {"resource_id": "resources"},
        "delegations": {"caller_id": "humans", "service_id": "workloads", "resource_id": "resources"},
        "requests": {"requester_id": "humans", "resource_id": "resources"},
        "approvals": {"request_id": "requests", "approver_id": "humans"},
        "business_events": {"resource_id": "resources"},
        "decisions": {"resource_id": "resources"},
    }
    sets = {k: {r.id for r in rows} for k, rows in tables.items()}
    for table, rows in tables.items():
        for r in rows:
            require(r.tenant_id, tenants, "tenant")
            require(r.owner_id, humans, "owner")
            require(r.provenance_id, sets["provenance"], "provenance")
            if by[r.owner_id].tenant_id != r.tenant_id:
                raise ValueError("owner tenant mismatch")
            for ref in r.lineage:
                require(ref, by, "lineage")
            for field, target in relations.get(table, {}).items():
                ref = getattr(r, field)
                if ref is None:
                    continue
                require(ref, sets[target], field)
                if table not in ["tenants"] and by[ref].tenant_id != r.tenant_id:
                    raise ValueError(f"tenant mismatch {table}.{field}")
            for field in [
                "created_at",
                "valid_from",
                "valid_until",
                "revoked_at",
                "deleted_at",
                "hired_at",
                "terminated_at",
                "effective_at",
            ]:
                val = getattr(r, field, None)
                if val:
                    datetime.strptime(val, "%Y-%m-%dT%H:%M:%SZ")
                    if field != "created_at" and val < r.created_at:
                        raise ValueError("time before creation")
            if hasattr(r, "valid_until") and r.valid_until <= r.valid_from:
                raise ValueError("invalid validity interval")
            if getattr(r, "revoked_at", None) and r.revoked_at < r.valid_from:
                raise ValueError("revocation before grant")
    for r in d.humans:
        if r.manager_id:
            m = humans[r.manager_id]
            if m.department_id != r.department_id or m.id == r.id or m.role != "manager":
                raise ValueError("invalid manager relationship")
        if r.terminated_at and r.terminated_at < r.hired_at:
            raise ValueError("termination before hire")
    for r in d.departments:
        if humans[r.manager_id].department_id != r.id or humans[r.manager_id].role != "manager":
            raise ValueError("department manager mismatch")
    groups = {r.id: r for r in d.groups}
    for r in d.memberships:
        if groups[r.group_id].department_id != humans[r.user_id].department_id:
            raise ValueError("membership department mismatch")
    for r in d.resources:
        if humans[r.owner_id].department_id != r.department_id:
            raise ValueError("resource owner department mismatch")
        if r.parent_id and resources[r.parent_id].department_id != r.department_id:
            raise ValueError("resource parent department mismatch")
        if bool(r.deleted_at) != (r.retention == "deleted") or (r.status == "deleted") != bool(r.deleted_at):
            raise ValueError("illegal deletion transition")
        seen = {r.id}
        p = r.parent_id
        while p:
            if p in seen:
                raise ValueError("resource parent cycle")
            seen.add(p)
            p = resources[p].parent_id
    unique: list[list[Any]] = [
        [(x.group_id, x.user_id, x.valid_from) for x in d.memberships],
        [(x.document_id, x.version) for x in d.versions],
        [x.resource_id for x in d.documents],
        [x.resource_id for x in d.owners],
    ]
    if any(len(x) != len(set(x)) for x in unique):
        raise ValueError("relationship cardinality violation")
    owners = {r.resource_id: r.user_id for r in d.owners}
    if set(owners) != set(resources) or any(owners[r.id] != r.owner_id for r in d.resources):
        raise ValueError("resource ownership incomplete")
    for doc in d.documents:
        if NOTICE not in doc.body or doc.content_sha256 != digest(doc.body.encode()):
            raise ValueError("document notice/hash mismatch")
        vs = [v for v in d.versions if v.document_id == doc.id]
        if not vs or max(v.version for v in vs) != resources[doc.resource_id].version:
            raise ValueError("document version mismatch")
        if max(vs, key=lambda v: v.version).body_sha256 != doc.content_sha256:
            raise ValueError("current version hash mismatch")
    labels = {r.id: r for r in d.labels}
    tasks = {r.id: r for r in d.tasks}
    for task in d.tasks:
        for label in task.label_ids:
            require(label, sets["labels"], "label")
            if labels[label].tenant_id != task.tenant_id:
                raise ValueError("task label tenant mismatch")
        if len(set(task.label_ids)) != 4 or {labels[x].name.value for x in task.label_ids} != {
            "PUBLIC",
            "INTERNAL",
            "CONFIDENTIAL",
            "RESTRICTED",
        }:
            raise ValueError("invalid task labels")
    for a in d.annotations:
        if a.label_id not in tasks[a.task_id].label_ids:
            raise ValueError("annotation outside task label set")
        if labels[a.label_id].tenant_id != a.tenant_id:
            raise ValueError("annotation label tenant mismatch")
    projects = {p.id: resources[p.resource_id] for p in d.projects}
    for issue in d.issues:
        department = projects[issue.project_id].department_id
        if resources[issue.resource_id].department_id != department or any(
            humans[u].department_id != department for u in [issue.reporter_id, issue.assignee_id]
        ):
            raise ValueError("issue project/identity department mismatch")
    for table, expected_kind in [("folders", "folder"), ("projects", "project"), ("issues", "issue")]:
        if any(resources[x.resource_id].kind != expected_kind for x in getattr(d, table)):
            raise ValueError("typed resource kind mismatch")
    for g in d.grants:
        require(g.principal_id, principals, "principal")
        if (by[g.principal_id].tenant_id != g.tenant_id) != g.cross_tenant:
            raise ValueError("undeclared or spurious cross-tenant grant")
    for x in d.requests:
        if resources[x.resource_id].kind != "invoice" or x.parameters.get("amount_cents") != resources[
            x.resource_id
        ].attributes.get("amount_cents"):
            raise ValueError("invoice request amount mismatch")
        if x.parameters_sha256 != digest(x.parameters):
            raise ValueError("request parameter binding mismatch")
    requests = {r.id: r for r in d.requests}
    for a in d.approvals:
        req = requests[a.request_id]
        if a.approver_id == req.requester_id or a.parameters_sha256 != req.parameters_sha256:
            raise ValueError("invalid separation/approval binding")
        if a.status != "approved":
            raise ValueError("approval must be approved")
    for event in d.lifecycle_events:
        require(event.target_id, by, "lifecycle target")
        if by[event.target_id].tenant_id != event.tenant_id:
            raise ValueError("lifecycle tenant mismatch")
        legal = {
            "hire": ("pending", "active"),
            "terminate": ("active", "disabled"),
            "membership-revoke": ("active", "revoked"),
            "delete": ("active", "deleted"),
            "reclassify": ("INTERNAL", "RESTRICTED"),
        }
        if (event.before, event.after) != legal[event.event_type]:
            raise ValueError("illegal lifecycle transition")
    for r in [*d.business_events, *d.decisions]:
        require(r.actor_id, identities, "actor")
    for row in d.decisions:
        if row.context.caller_id:
            require(row.context.caller_id, humans, "caller")
        if row.context.request_id:
            require(row.context.request_id, requests, "context request")
    if d.decisions:
        from p002.policies import evaluate

        for row in d.decisions:
            verdict, reason, rules = evaluate(d, row.actor_id, row.action, row.resource_id, row.context)
            if (verdict, reason, rules) != (row.expected, row.reason, row.rule_ids):
                raise ValueError("oracle differs from reference evaluator")
    if len({s.id for s in d.scenarios}) != len(d.scenarios):
        raise ValueError("duplicate scenario")
    return {"orphan_references": 0, "duplicate_ids": 0, "records": len(flat)}
