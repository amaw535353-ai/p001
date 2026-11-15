"""Reference intended policy. Not proof of backend authorization enforcement."""

from p002.models import Context


def active(record, time):
    return (
        record.status not in ["revoked", "disabled", "deleted"]
        and record.valid_from <= time < record.valid_until
        and (record.revoked_at is None or time < record.revoked_at)
    )


def evaluate(d, actor_id, action, resource_id, context=None):
    c = context or Context()
    actors = {x.id: x for x in [*d.humans, *d.workloads]}
    resources = {x.id: x for x in d.resources}

    def deny(rule):
        return "DENY", rule, [rule]

    a = actors.get(actor_id)
    r = resources.get(resource_id)
    if not a or not r:
        return deny("unknown-actor-or-resource")
    if (
        (
            a.status != "active"
            and not (
                a.status == "disabled" and getattr(a, "terminated_at", None) and c.time < a.terminated_at
            )
        )
        or c.time < a.created_at
        or c.time < getattr(a, "hired_at", a.created_at)
        or (getattr(a, "terminated_at", None) and c.time >= a.terminated_at)
    ):
        return deny("inactive-identity")
    if c.time < r.created_at or (r.deleted_at and c.time >= r.deleted_at):
        return deny("resource-not-live")
    principals = {actor_id}
    principals.update(m.group_id for m in d.memberships if m.user_id == actor_id and active(m, c.time))
    targets = {r.id}
    p = r.parent_id
    while p:
        targets.add(p)
        p = resources[p].parent_id
    grants = [
        g
        for g in d.grants
        if g.principal_id in principals
        and g.resource_id in targets
        and (g.resource_id == r.id or g.inherited)
        and action in g.actions
        and active(g, c.time)
    ]
    if a.tenant_id != r.tenant_id and not any(g.cross_tenant and g.effect == "ALLOW" for g in grants):
        return deny("tenant-boundary")
    if any(g.effect == "DENY" for g in grants):
        return deny("explicit-deny-precedence")
    if not any(g.effect == "ALLOW" for g in grants):
        return deny("default-deny-no-effective-grant")
    if actor_id in {x.id for x in d.workloads}:
        if not c.caller_id or c.caller_id not in actors or actors[c.caller_id].status != "active":
            return deny("caller-required")
        delegations = [
            x
            for x in d.delegations
            if x.service_id == actor_id
            and x.caller_id == c.caller_id
            and x.resource_id == r.id
            and action in x.actions
            and active(x, c.time)
        ]
        if not delegations:
            return deny("delegation-scope-or-time")
        result = evaluate(
            d,
            c.caller_id,
            action,
            r.id,
            Context(time=c.time, request_id=c.request_id, parameters_sha256=c.parameters_sha256),
        )
        if result[0] != "ALLOW":
            return deny("caller-not-entitled")
    if action == "execute":
        req = next((x for x in d.requests if x.id == c.request_id), None)
        caller = c.caller_id or actor_id
        if (
            not req
            or req.requester_id != caller
            or req.resource_id != r.id
            or req.parameters_sha256 != c.parameters_sha256
        ):
            return deny("exact-action-binding")
        approvals = [
            x
            for x in d.approvals
            if x.request_id == req.id
            and x.status == "approved"
            and x.approver_id != caller
            and x.parameters_sha256 == req.parameters_sha256
            and x.valid_from <= c.time < x.valid_until
        ]
        if not any(
            evaluate(d, x.approver_id, "approve", r.id, Context(time=c.time))[0] == "ALLOW" for x in approvals
        ):
            return deny("distinct-effective-approval-required")
    return "ALLOW", "effective-grant", ["effective-grant"]
