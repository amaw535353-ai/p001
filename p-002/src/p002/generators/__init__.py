"""Dependency-ordered self-created fixture generation, with no network calls."""

import random
from typing import Any
from pathlib import Path
import json
from p002 import NOTICE
from p002.models import Dataset, NOW, T0, Context, Classification
from p002.policies import evaluate
from p002.validation import digest

ROOT = Path(__file__).resolve().parents[3]
PROFILES = {"tiny": (3, 4), "standard": (6, 10), "stress-local": (24, 80)}


def generate(seed=2026, profile="standard", mode="fixtures", allow_stress=False):
    if profile not in PROFILES:
        raise ValueError("unknown profile")
    if profile == "stress-local" and not allow_stress:
        raise ValueError("stress-local requires --allow-stress")
    if not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed out of range")
    rng = random.Random(seed)
    people, doc_count = PROFILES[profile]
    data: dict[str, Any] = {
        k: []
        for k in [
            "enterprises",
            "tenants",
            "departments",
            "humans",
            "groups",
            "memberships",
            "workloads",
            "resources",
            "folders",
            "documents",
            "versions",
            "owners",
            "provenance",
            "projects",
            "issues",
            "comments",
            "labels",
            "tasks",
            "annotations",
            "grants",
            "delegations",
            "requests",
            "approvals",
            "business_events",
            "lifecycle_events",
            "decisions",
            "scenarios",
        ]
    }
    data.update(seed=seed, profile=profile, logical_time=NOW, mode=mode)

    def add(table, id, t, **fields):
        row = {
            "id": id,
            "tenant_id": f"p002:{t}",
            "owner_id": f"p002:{t}:hr:u0",
            "provenance_id": f"p002:{t}:source",
            **fields,
        }
        data[table].append(row)
        return row

    def resource(id, t, dept, kind, title, classification="INTERNAL", parent=None, **kwargs):
        own = f"p002:{t}:{dept}:u0"
        r = add(
            "resources",
            id,
            t,
            department_id=f"p002:{t}:{dept}",
            kind=kind,
            title=title,
            classification=classification,
            parent_id=parent,
            owner_id=own,
            **kwargs,
        )
        add("owners", id + ":owner", t, resource_id=id, user_id=own, owner_id=own)
        return r

    for t in ["tenant-a", "tenant-b"]:
        add("provenance", f"p002:{t}:source", t)
        add(
            "tenants",
            f"p002:{t}",
            t,
            enterprise_id="p002:enterprise",
            name="Fictional " + t,
            domain=t + ".example.test",
        )
        for c in Classification:
            add("labels", f"p002:{t}:label:{c.value.lower()}", t, name=c.value)
        for dept, name in [("hr", "Human Resources"), ("finance", "Finance"), ("engineering", "Engineering")]:
            prefix = f"p002:{t}:{dept}"
            manager = prefix + ":u0"
            folder = prefix + ":folder"
            add("departments", prefix, t, name=name, manager_id=manager, owner_id=manager)
            add("groups", prefix + ":group", t, department_id=prefix, name="P002 " + name, owner_id=manager)
            for i in range(people):
                uid = prefix + f":u{i}"
                add(
                    "humans",
                    uid,
                    t,
                    department_id=prefix,
                    display_name=f"Fictional {t[-1].upper()} {dept.title()} Person {i:02}",
                    email=f"{dept}.person{i}@{t}.example.test",
                    role="manager" if i == 0 else ("reviewer" if i % 2 == 0 else "analyst"),
                    manager_id=None if i == 0 else manager,
                    owner_id=manager,
                    status="disabled" if i == people - 1 else "active",
                    terminated_at="2026-01-10T00:00:00Z" if i == people - 1 else None,
                )
                add(
                    "memberships",
                    uid + ":member",
                    t,
                    group_id=prefix + ":group",
                    user_id=uid,
                    owner_id=manager,
                )
                add(
                    "lifecycle_events",
                    uid + ":hire",
                    t,
                    target_id=uid,
                    event_type="hire",
                    effective_at=T0,
                    before="pending",
                    after="active",
                )
                if i == people - 1:
                    add(
                        "lifecycle_events",
                        uid + ":termination",
                        t,
                        target_id=uid,
                        event_type="terminate",
                        effective_at="2026-01-10T00:00:00Z",
                        before="active",
                        after="disabled",
                    )
            add(
                "workloads",
                prefix + ":service",
                t,
                department_id=prefix,
                name="Fictional departmental reader",
                owner_id=manager,
            )
            resource(folder, t, dept, "folder", name + " synthetic folder")
            add("folders", folder + ":entry", t, resource_id=folder, owner_id=manager)
            add(
                "grants",
                prefix + ":grant-group",
                t,
                principal_id=prefix + ":group",
                resource_id=folder,
                actions=["read", "update"],
                inherited=True,
                owner_id=manager,
            )
            for i in range(doc_count):
                rid = prefix + f":doc{i}"
                kind = ["document", "kb-page", "invoice"][i % 3]
                classification = list(Classification)[i % 4].value
                attrs = (
                    {
                        "amount_cents": rng.randrange(1000, 100000),
                        "fake_account": "NONFUNCTIONAL-ACCOUNT-" + str(i),
                    }
                    if kind == "invoice"
                    else {}
                )
                resource(
                    rid,
                    t,
                    dept,
                    kind,
                    f"Fictional {name} record {i:03}",
                    classification,
                    folder,
                    attributes=attrs,
                )
                body = f"{NOTICE}\n\n# Fictional {name} record {i:03}\n\nTenant {t}; classification {classification}.\n"
                body += [
                    "Synthetic onboarding checklist. No invitation is sent.",
                    "Synthetic knowledge page. All claims require source review.",
                    "Fictional invoice review. Amounts and account references cannot be used for payment.",
                ][i % 3]
                body += f"\nDeterministic reference: {rng.randrange(10**9):09}.\n"
                if i == 3:
                    body += "SYNTHETIC-CANARY-" + t.upper() + "-" + dept.upper() + "-NO-REAL-DATA\n"
                doc = add(
                    "documents",
                    rid + ":body",
                    t,
                    resource_id=rid,
                    body=body,
                    content_sha256=digest(body.encode()),
                    owner_id=manager,
                )
                add(
                    "versions",
                    rid + ":v1",
                    t,
                    document_id=doc["id"],
                    version=1,
                    body_sha256=doc["content_sha256"],
                    owner_id=manager,
                )
                task = add(
                    "tasks",
                    rid + ":task",
                    t,
                    document_id=doc["id"],
                    label_ids=[f"p002:{t}:label:{c.value.lower()}" for c in Classification],
                    owner_id=manager,
                )
                add(
                    "annotations",
                    rid + ":annotation",
                    t,
                    task_id=task["id"],
                    annotator_id=manager,
                    label_id=f"p002:{t}:label:{classification.lower()}",
                    owner_id=manager,
                )
            for kind in ["tool-config", "mock-dataset", "cloud-object"]:
                attrs = (
                    {"object_uri": f"s3://p001-{t}/fixture-p002-{dept}"}
                    if kind == "cloud-object"
                    else {"mode": "NONFUNCTIONAL-PLACEHOLDER"}
                )
                resource(
                    prefix + ":" + kind,
                    t,
                    dept,
                    kind,
                    "Synthetic " + kind,
                    "CONFIDENTIAL",
                    folder,
                    attributes=attrs,
                )
            project = prefix + ":project"
            resource(project, t, dept, "project", f"P002 {name} project", parent=folder)
            add(
                "projects",
                project + ":entry",
                t,
                resource_id=project,
                name=f"Fictional {name} work",
                owner_id=manager,
            )
            for i in range(2):
                rid = prefix + f":issue{i}"
                resource(rid, t, dept, "issue", f"Synthetic change {i}", "CONFIDENTIAL", project)
                add(
                    "issues",
                    rid + ":entry",
                    t,
                    resource_id=rid,
                    project_id=project + ":entry",
                    reporter_id=prefix + ":u1",
                    assignee_id=manager,
                    subject=f"{NOTICE}: Fictional {name} work item {i}",
                    owner_id=manager,
                )
                add(
                    "comments",
                    rid + ":comment",
                    t,
                    issue_id=rid + ":entry",
                    author_id=manager,
                    body=NOTICE + "; review pending.",
                    owner_id=manager,
                )
            # Explicit deny beats inherited group access; temporal service delegation is separate.
            add(
                "grants",
                prefix + ":deny-u1-doc3",
                t,
                principal_id=prefix + ":u1",
                resource_id=prefix + ":doc3",
                actions=["read"],
                effect="DENY",
                owner_id=manager,
            )
            add(
                "grants",
                prefix + ":grant-service",
                t,
                principal_id=prefix + ":service",
                resource_id=prefix + ":doc0",
                actions=["read"],
                owner_id=manager,
            )
            add(
                "delegations",
                prefix + ":delegation",
                t,
                caller_id=manager,
                service_id=prefix + ":service",
                resource_id=prefix + ":doc0",
                actions=["read"],
                valid_until="2026-02-01T00:00:00Z",
                owner_id=manager,
            )
            for i, event in enumerate(
                [
                    "onboarding",
                    "offboarding",
                    "hr-case",
                    "invoice-review",
                    "engineering-change",
                    "procurement",
                    "knowledge-retrieval",
                ]
            ):
                add(
                    "business_events",
                    prefix + f":business{i}",
                    t,
                    event_type=event,
                    actor_id=manager,
                    resource_id=prefix + f":doc{i % doc_count}",
                    effective_at=NOW,
                    owner_id=manager,
                )
            if dept == "finance":
                rid = prefix + ":doc2"
                params = {
                    "amount_cents": next(
                        x["attributes"]["amount_cents"] for x in data["resources"] if x["id"] == rid
                    ),
                    "fake_account": next(
                        x["attributes"]["fake_account"] for x in data["resources"] if x["id"] == rid
                    ),
                    "currency": "SYNTHETIC",
                }
                req = add(
                    "requests",
                    prefix + ":request",
                    t,
                    requester_id=prefix + ":u1",
                    resource_id=rid,
                    parameters=params,
                    parameters_sha256=digest(params),
                    owner_id=manager,
                )
                add(
                    "grants",
                    prefix + ":execute",
                    t,
                    principal_id=prefix + ":u1",
                    resource_id=rid,
                    actions=["execute"],
                    owner_id=manager,
                )
                add(
                    "grants",
                    prefix + ":approve",
                    t,
                    principal_id=manager,
                    resource_id=rid,
                    actions=["approve"],
                    owner_id=manager,
                )
                add(
                    "approvals",
                    prefix + ":approval",
                    t,
                    request_id=req["id"],
                    approver_id=manager,
                    parameters_sha256=req["parameters_sha256"],
                    status="approved",
                    owner_id=manager,
                )
    for t in ["tenant-a", "tenant-b"]:
        p = f"p002:{t}:hr"
        for kind, target, before, after in [
            ("membership-revoke", p + ":u1:member", "active", "revoked"),
            ("delete", p + ":doc0", "active", "deleted"),
            ("reclassify", p + ":doc1", "INTERNAL", "RESTRICTED"),
        ]:
            add(
                "lifecycle_events",
                p + ":scheduled-" + kind,
                t,
                target_id=target,
                event_type=kind,
                effective_at="2026-02-01T00:00:00Z",
                before=before,
                after=after,
            )
    add("enterprises", "p002:enterprise", "tenant-a", name="Fictional Meridian Training Works")
    data["scenarios"] = [
        json.loads(p.read_text()) for p in sorted((ROOT / "config/scenarios").glob("S*.json"))
    ]
    if mode == "sdv":
        from p002.generators.sdv_mode import synthesize

        data = synthesize(data)
    d = Dataset.model_validate(data)
    cases = []
    for t in ["tenant-a", "tenant-b"]:
        other = "tenant-b" if t == "tenant-a" else "tenant-a"
        for dept in ["hr", "finance", "engineering"]:
            p = f"p002:{t}:{dept}"
            for action in ["read", "update"]:
                for actor, target_id in [
                    (p + ":u0", p + ":doc0"),
                    (p + ":u1", p + ":doc0"),
                    (f"p002:{other}:{dept}:u0", p + ":doc0"),
                    (f"p002:{t}:hr:u0" if dept != "hr" else f"p002:{t}:finance:u0", p + ":doc0"),
                    (p + f":u{people - 1}", p + ":doc0"),
                ]:
                    cases.append((actor, action, target_id, Context()))
            cases.extend(
                [
                    (p + ":u1", "read", p + ":doc3", Context()),
                    (p + ":service", "read", p + ":doc0", Context(caller_id=p + ":u0")),
                    (
                        p + ":service",
                        "read",
                        p + ":doc0",
                        Context(caller_id=p + ":u0", time="2026-03-01T00:00:00Z"),
                    ),
                    (p + ":service", "read", p + ":doc0", Context()),
                    (p + ":u0", "read", p + ":issue0", Context()),
                    (f"p002:{other}:{dept}:u0", "read", p + ":issue0", Context()),
                ]
            )
            if dept == "finance":
                req = next(x for x in d.requests if x.id == p + ":request")
                cases.extend(
                    [
                        (
                            p + ":u1",
                            "execute",
                            p + ":doc2",
                            Context(request_id=req.id, parameters_sha256=req.parameters_sha256),
                        ),
                        (
                            p + ":u1",
                            "execute",
                            p + ":doc2",
                            Context(request_id=req.id, parameters_sha256="0" * 64),
                        ),
                    ]
                )
    for i, (actor, action, rid, ctx) in enumerate(cases):
        res = next(r for r in d.resources if r.id == rid)
        verdict, reason, rules = evaluate(d, actor, action, rid, ctx)
        d.decisions.append(
            __import__("p002.models", fromlist=["ExpectedDecision"]).ExpectedDecision(
                id=f"p002:decision:{i:04}",
                tenant_id=res.tenant_id,
                owner_id=res.owner_id,
                provenance_id=res.provenance_id,
                actor_id=actor,
                action=action,
                resource_id=rid,
                context=ctx,
                expected=verdict,
                reason=reason,
                rule_ids=rules,
            )
        )
    return Dataset.model_validate(d.model_dump())
