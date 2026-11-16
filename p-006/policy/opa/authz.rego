package p006.authz

import rego.v1

default allow := false

trusted if {
    input.schema_version == "p006-authz-input-v1"
    input.policy_version == "p006-authz-v1"
    input.active == true
    input.within_quota == true
    input.client == "open-webui"
    input.classification == "SYNTHETIC"
    input.provider == "local-mock"
    principal := data.p006.principals[input.subject]
    principal.enabled == true
    input.tenant == principal.tenant
    input.resource_tenant == principal.tenant
    count(input.roles) == count(principal.roles)
    every role in input.roles { role in principal.roles }
}

allow if {
    trusted
    input.action in {"chat", "models"}
    model := data.p006.models[input.model]
    model.required_role in input.roles
}

allow if {
    trusted
    input.action == "tenant-admin"
    "tenant-admin" in input.roles
}

allow if {
    trusted
    input.action == "platform-admin"
    input.tenant == "platform"
    "platform-admin" in input.roles
}

reason := "ALLOW" if allow else := "DEFAULT_DENY"
decision := {"allow": allow, "policy_version": "p006-authz-v1", "reason": reason}
