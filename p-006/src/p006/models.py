"""Strict contracts. Committed settings contain references, never credentials."""

import hashlib
import json
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Id = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
Role = Literal["user", "tenant-admin", "platform-admin"]
Action = Literal["chat", "models", "tenant-admin", "platform-admin"]
Status = Literal["PASS", "FAIL", "BLOCKED", "NOT_TESTED", "INCONCLUSIVE", "NOT_APPLICABLE"]


def digest(data: object) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Endpoint(Strict):
    schema_version: Literal["p006-endpoint-v1"] = "p006-endpoint-v1"
    service_id: Id
    method: Literal["GET", "POST"]
    path: Annotated[str, Field(pattern=r"^/[a-zA-Z0-9_/{}/.-]*$")]
    response_schema_ref: str


class Service(Strict):
    id: Id
    image: str
    networks: list[Id]
    port: Annotated[int, Field(ge=1, le=65535)]
    build_recipe_sha256: str | None = None

    @model_validator(mode="after")
    def pinned(self):
        if self.image == "p006-runtime:1.0.0":
            if self.build_recipe_sha256 is None or not re.fullmatch(r"[a-f0-9]{64}", self.build_recipe_sha256):
                raise ValueError("local runtime requires its reproducible build recipe hash")
            return self
        if not re.fullmatch(r"[a-z0-9./:_-]+:[a-zA-Z0-9._-]+@sha256:[a-f0-9]{64}", self.image):
            raise ValueError("image version AND digest required")
        if ":latest@" in self.image:
            raise ValueError("latest forbidden")
        return self


class ServiceInventory(Strict):
    schema_version: Literal["p006-inventory-v1"] = "p006-inventory-v1"
    services: list[Service]
    endpoints: list[Endpoint]

    @model_validator(mode="after")
    def references(self):
        ids = [service.id for service in self.services]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate service")
        if any(endpoint.service_id not in ids for endpoint in self.endpoints):
            raise ValueError("unknown endpoint service")
        return self


class OIDCClient(Strict):
    id: Literal["open-webui", "p006-pep"]
    redirect_uris: list[str]
    origins: list[str]
    pkce: Literal["S256"] = "S256"

    @model_validator(mode="after")
    def exact_local(self):
        for url in self.redirect_uris + self.origins:
            if not url.startswith("http://127.0.0.1:8086") or "*" in url:
                raise ValueError("only exact local redirect/origin supported")
            if url not in {"http://127.0.0.1:8086", "http://127.0.0.1:8086/oauth/oidc/callback"}:
                raise ValueError("unapproved redirect/origin")
        return self


class IdentityProvider(Strict):
    schema_version: Literal["p006-idp-v1"] = "p006-idp-v1"
    issuer: Literal["http://127.0.0.1:8087/realms/p006"]
    audience: Literal["p006-pep"]
    jwks_url: Literal["http://keycloak:8080/realms/p006/protocol/openid-connect/certs"]
    introspection_url: Literal["http://keycloak:8080/realms/p006/protocol/openid-connect/token/introspect"]
    algorithms: list[Literal["RS256"]]
    clients: list[OIDCClient]


class Tenant(Strict):
    id: Literal["tenant-a", "tenant-b", "platform"]
    classification: Literal["SYNTHETIC"] = "SYNTHETIC"


class Principal(Strict):
    subject: Annotated[str, Field(pattern=r"^[a-f0-9-]{36}$")]
    username: Id
    tenant: Literal["tenant-a", "tenant-b", "platform"]
    roles: list[Role]
    enabled: bool = True


class RoleBinding(Strict):
    principal: str
    tenant: str
    roles: list[Role]


class GatewayModel(Strict):
    id: Literal["local-basic", "local-admin"]
    provider: Literal["local-mock"] = "local-mock"
    required_role: Role
    max_tokens: Annotated[int, Field(ge=1, le=128)] = 64


class GatewayRoute(Strict):
    schema_version: Literal["p006-route-v1"] = "p006-route-v1"
    id: Literal["local-mock"] = "local-mock"
    url: Literal["http://litellm:4000/v1/chat/completions"]
    backend: Literal["http://model:8000/v1"]
    model_ids: list[Literal["local-basic", "local-admin"]]
    external_enabled: Literal[False] = False


class VaultReference(Strict):
    schema_version: Literal["p006-secret-ref-v1"] = "p006-secret-ref-v1"
    path: Literal["p006/data/gateway"]
    field: Literal["gateway_key", "provider_key"]
    auth: Literal["approle"] = "approle"


class VaultPolicy(Strict):
    name: Literal["p006-pep", "p006-gateway", "p006-rotator", "p006-unrelated"]
    path: str
    capabilities: list[Literal["read", "create", "update"]]
    token_ttl_seconds: Annotated[int, Field(ge=10, le=300)] = 60


class EgressPolicy(Strict):
    schema_version: Literal["p006-egress-v1"] = "p006-egress-v1"
    networks: dict[Id, list[Id]]
    internal: Literal[True] = True
    external_destinations: list[str] = Field(default_factory=list, max_length=0)


class Deployment(Strict):
    schema_version: Literal["p006-deployment-v1"] = "p006-deployment-v1"
    host: Literal["127.0.0.1"] = "127.0.0.1"
    ui_port: Literal[8086] = 8086
    idp_port: Literal[8087] = 8087
    owner: Literal["p006"] = "p006"


class PolicyBundle(Strict):
    schema_version: Literal["p006-policy-v1"] = "p006-policy-v1"
    version: Literal["p006-authz-v1"] = "p006-authz-v1"
    default_allow: Literal[False] = False


class Profile(Strict):
    schema_version: Literal["p006-profile-v1"]
    name: Literal["hardened", "vulnerable-lab"]
    model_mode: Literal["deterministic-local"]
    identity: IdentityProvider
    principals: list[Principal]
    tenants: list[Tenant]
    models: list[GatewayModel]
    route: GatewayRoute
    policy: PolicyBundle
    egress: EgressPolicy
    deployment: Deployment
    max_request_bytes: Annotated[int, Field(ge=1024, le=16384)] = 16384
    max_response_bytes: Annotated[int, Field(ge=1024, le=65536)] = 65536
    requests_per_minute: Annotated[int, Field(ge=1, le=60)] = 20
    tenant_tokens_per_minute: Annotated[int, Field(ge=128, le=8192)] = 1024

    @model_validator(mode="after")
    def references(self):
        groups: list[list[str]] = [[p.subject for p in self.principals], [p.username for p in self.principals],
                                  [m.id for m in self.models], [t.id for t in self.tenants],
                                  [c.id for c in self.identity.clients]]
        for ids in groups:
            if len(ids) != len(set(ids)):
                raise ValueError("duplicate identifier")
        if any(p.tenant not in {t.id for t in self.tenants} for p in self.principals):
            raise ValueError("unknown tenant")
        if set(self.route.model_ids) != {m.id for m in self.models}:
            raise ValueError("model route mismatch")
        if self.identity.algorithms != ["RS256"]:
            raise ValueError("exact algorithm required")
        return self


class AuthzRequest(Strict):
    schema_version: Literal["p006-authz-input-v1"] = "p006-authz-input-v1"
    policy_version: Literal["p006-authz-v1"] = "p006-authz-v1"
    subject: str
    tenant: str
    resource_tenant: str
    roles: list[Role]
    model: str
    action: Action
    provider: Literal["local-mock"] = "local-mock"
    classification: Literal["SYNTHETIC"] = "SYNTHETIC"
    client: Literal["open-webui"] = "open-webui"
    active: Literal[True] = True
    within_quota: bool


class AuthzDecision(Strict):
    allow: bool
    policy_version: Literal["p006-authz-v1"]
    reason: Literal["ALLOW", "DEFAULT_DENY"]

    @model_validator(mode="after")
    def consistent(self):
        if self.allow != (self.reason == "ALLOW"):
            raise ValueError("inconsistent policy decision")
        return self


class Message(Strict):
    role: Literal["user", "assistant", "system"]
    content: Annotated[str, Field(min_length=1, max_length=4096)]


class Chat(Strict):
    model: Annotated[str, Field(min_length=1, max_length=64)]
    messages: list[Message] = Field(min_length=1, max_length=16)
    max_tokens: Annotated[int, Field(ge=1, le=128)] = 64
    stream: bool = False
    temperature: Annotated[float, Field(ge=0, le=0)] = 0.0


class TestCase(Strict):
    schema_version: Literal["p006-test-case-v1"] = "p006-test-case-v1"
    id: str
    objective: str
    requirement: str
    component: str
    boundary: str
    profile: Literal["hardened", "vulnerable-lab"]
    preconditions: str
    action: str
    expected: str
    reproduction: str


class TestResult(Strict):
    schema_version: Literal["p006-test-result-v1"] = "p006-test-result-v1"
    test_id: str
    status: Status
    observation: str
    config_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    evidence_ref: str
    limitations: str
