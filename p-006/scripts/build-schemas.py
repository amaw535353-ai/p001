#!/usr/bin/env python3
"""Regenerate published JSON schemas from the strict Python contracts."""

import json
from pathlib import Path

from p006 import models

root = Path(__file__).resolve().parents[1]
mapping = {"Profile": "architecture-profile", "ServiceInventory": "service-inventory",
           "Endpoint": "service-endpoint", "IdentityProvider": "identity-provider",
           "OIDCClient": "oidc-client", "Principal": "principal", "Tenant": "tenant",
           "RoleBinding": "role-binding", "AuthzRequest": "authorization-request",
           "AuthzDecision": "authorization-decision", "PolicyBundle": "opa-policy-bundle",
           "VaultPolicy": "vault-policy", "VaultReference": "vault-secret-reference",
           "GatewayModel": "gateway-model", "GatewayRoute": "gateway-route",
           "EgressPolicy": "egress-policy", "Deployment": "deployment-config", "TestCase": "test-case",
           "TestResult": "test-result", "Chat": "chat-request"}
for name, filename in mapping.items():
    schema = getattr(models, name).model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"urn:p006:{filename}:v1"
    (root / "schemas" / f"{filename}.schema.json").write_text(json.dumps(schema, indent=2) + "\n")
print(f"Generated {len(mapping)} strict schemas")
