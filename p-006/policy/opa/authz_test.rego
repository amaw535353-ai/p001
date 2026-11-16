package p006.authz_test

import rego.v1

test_default_deny if {
    data.p006.authz.decision.allow == false with input as {}
}

test_known_user_allowed if {
    p := data.p006.principals["00000000-0000-4000-8000-000000000001"]
    i := {"schema_version": "p006-authz-input-v1", "policy_version": "p006-authz-v1",
          "subject": "00000000-0000-4000-8000-000000000001", "tenant": p.tenant,
          "resource_tenant": p.tenant, "roles": p.roles, "action": "chat", "model": "local-basic",
          "provider": "local-mock", "active": true, "within_quota": true,
          "classification": "SYNTHETIC", "client": "open-webui"}
    data.p006.authz.decision.allow == true with input as i
}

test_cross_tenant_denied if {
    i := {"schema_version": "p006-authz-input-v1", "policy_version": "p006-authz-v1",
          "subject": "00000000-0000-4000-8000-000000000001", "tenant": "tenant-a",
          "resource_tenant": "tenant-b", "roles": ["user"], "action": "chat", "model": "local-basic",
          "provider": "local-mock", "active": true, "within_quota": true,
          "classification": "SYNTHETIC", "client": "open-webui"}
    data.p006.authz.decision.allow == false with input as i
}
