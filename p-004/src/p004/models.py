"""Versioned strict contracts; evidence supports claims, not security conclusions."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from p004.safety import Invalid, address, route, scrub, text

Status = Literal[
    "OBSERVED", "DECLARED", "INFERRED", "UNVERIFIED", "NOT_APPLICABLE", "NOT_TESTED", "BLOCKED", "ERROR"
]
Method = Literal["static", "openapi", "p001", "p002", "p003", "playwright", "zap", "manual", "guarded-http"]
SHA = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
ID = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{2,80}$")]
Ref = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9:_.-]{0,127}$")]
Kind = Literal[
    "client",
    "tenant",
    "human-identity",
    "workload-identity",
    "service-account",
    "identity-provider",
    "application",
    "ui",
    "api-service",
    "model-endpoint",
    "agent",
    "mcp-tool",
    "a2a-peer",
    "connector",
    "retrieval-pipeline",
    "vector-db",
    "database",
    "object-store",
    "document",
    "container",
    "cluster",
    "namespace",
    "cloud-emulator",
    "external-integration",
    "secret-manager",
    "telemetry",
    "ci-cd",
    "other",
]
EdgeKind = Literal[
    "invokes",
    "authenticates",
    "authorizes",
    "delegates",
    "retrieves",
    "reads",
    "writes",
    "stores",
    "indexes",
    "transmits",
    "emits-telemetry",
    "hosts",
    "exposed-via",
    "candidate-trust-boundary-crossing",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False, str_max_length=4096)


class Source(Strict):
    path: str
    sha256: SHA
    pointer: str
    line: int | None = Field(default=None, ge=1)

    @field_validator("path", "pointer")
    @classmethod
    def safe_text(cls, value):
        return text(value, 512)


class EvidenceClaim(Strict):
    source_ref: Source
    discovery_method: Method
    status: Status
    measured_scope: str


class Claim(Strict):
    id: ID
    tenant_id: Ref
    environment_id: Ref = "local-lab"
    source_refs: list[Source] = Field(min_length=1, max_length=100)
    evidence_claims: list[EvidenceClaim] = Field(min_length=1, max_length=100)
    discovery_method: Method
    status: Status = "DECLARED"
    confidence: float = Field(ge=0, le=1)
    requires_human_confirmation: bool = True
    first_seen_utc: str
    last_seen_utc: str
    constraints: list[str] = Field(default_factory=list, max_length=32)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen_utc", "last_seen_utc")
    @classmethod
    def valid_stamp(cls, value):
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return value

    @field_validator("attributes", "constraints")
    @classmethod
    def sanitize(cls, value):
        return scrub(value)


class Asset(Claim):
    asset_id: ID
    kind: Kind
    label: str
    address: str | None = None

    @field_validator("label")
    @classmethod
    def clean(cls, value):
        return text(value)

    @field_validator("address")
    @classmethod
    def normalized(cls, value):
        return address(value) if value else None

    @model_validator(mode="after")
    def same_id(self):
        if self.asset_id != self.id:
            raise Invalid("ASSET-ID-MISMATCH")
        return self


class Endpoint(Claim):
    asset_id: ID
    origin: str | None = None
    path: str
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    api_version: str | None = None
    auth: Literal["declared", "observed-rejection", "unknown", "not-applicable"] = "unknown"
    response_codes: list[int] = Field(default_factory=list, max_length=16)

    @field_validator("api_version")
    @classmethod
    def clean_version(cls, value):
        return text(value) if value else None

    @field_validator("path")
    @classmethod
    def path_template(cls, value):
        return route(value)

    @field_validator("origin")
    @classmethod
    def canonical_origin(cls, value):
        return address(value).removesuffix("/") if value else None


class Flow(Claim):
    source_id: ID
    target_id: ID
    kind: EdgeKind
    actor_id: str | None = None
    permission_assumption: str = "not verified"

    @field_validator("actor_id", "permission_assumption")
    @classmethod
    def clean_identity_assumption(cls, value):
        return text(value) if value else value


class Boundary(Claim):
    flow_id: ID
    source_id: ID
    target_id: ID
    label: str

    @field_validator("label")
    @classmethod
    def clean(cls, value):
        return text(value)


class Observation(Strict):
    id: ID
    status: Status
    category: Literal["coverage", "discrepancy", "policy-decision", "request", "passive-alert", "error"]
    summary: str
    source_refs: list[Source] = Field(default_factory=list, max_length=100)
    entity_ids: list[ID] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    requires_human_confirmation: Literal[True] = True

    @field_validator("summary")
    @classmethod
    def clean(cls, value):
        return text(value)

    @field_validator("details")
    @classmethod
    def clean_details(cls, value):
        return scrub(value)


class Coverage(Strict):
    source: str
    target: str
    status: Literal["discovered", "not_observed", "out_of_scope", "blocked", "skipped", "unverified", "error"]
    known_denominator: int | None = Field(default=None, ge=0)
    processed: int = Field(ge=0)
    reason: str

    @field_validator("source", "target", "reason")
    @classmethod
    def clean(cls, value):
        return text(value, 512)


class Context(Strict):
    schema_version: Literal["1.0"] = "1.0"
    run_id: Ref
    engagement_id: Ref | None = None
    approved_engagement_version: int | None = Field(default=None, ge=1)
    timestamp_utc: str
    tool_version: Literal["1.0.0"] = "1.0.0"
    git_commit: str
    environment_id: Ref = "local-lab"
    dataset_seed: int | None = None
    policy_digest: SHA | None = None
    sanitization_status: Literal["allowlist-projection-and-redaction"] = "allowlist-projection-and-redaction"
    mode: Literal["offline", "guarded-http"] = "offline"
    outcome: Literal["COMPLETE", "PARTIAL", "BLOCKED", "ERROR"] = "COMPLETE"

    @field_validator("timestamp_utc")
    @classmethod
    def valid_stamp(cls, value):
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return value


class Snapshot(Strict):
    schema_version: Literal["1.0"] = "1.0"
    context: Context
    assets: list[Asset] = Field(default_factory=list, max_length=5000)
    endpoints: list[Endpoint] = Field(default_factory=list, max_length=5000)
    flows: list[Flow] = Field(default_factory=list, max_length=10000)
    trust_boundaries: list[Boundary] = Field(default_factory=list, max_length=10000)
    observations: list[Observation] = Field(default_factory=list, max_length=5000)
    coverage: list[Coverage] = Field(default_factory=list, max_length=200)
    snapshot_digest: SHA

    @model_validator(mode="after")
    def references(self):
        assets = {x.id: x for x in self.assets}
        ids = [x.id for x in self.assets] + [x.id for x in self.endpoints] + [x.id for x in self.flows]
        ids += [x.id for x in self.trust_boundaries] + [x.id for x in self.observations]
        if len(ids) != len(set(ids)):
            raise Invalid("DUPLICATE-ENTITY-ID")
        if any(
            e.asset_id not in assets or e.tenant_id != assets[e.asset_id].tenant_id for e in self.endpoints
        ):
            raise Invalid("ENDPOINT-REFERENCE")
        for flow in self.flows:
            if flow.source_id not in assets or flow.target_id not in assets:
                raise Invalid("FLOW-REFERENCE")
        flow_ids = {x.id for x in self.flows}
        for boundary in self.trust_boundaries:
            if (
                boundary.flow_id not in flow_ids
                or boundary.source_id not in assets
                or boundary.target_id not in assets
            ):
                raise Invalid("BOUNDARY-REFERENCE")
        return self


class InputEntry(Strict):
    kind: Literal[
        "p001",
        "openapi",
        "architecture",
        "python",
        "kubernetes",
        "compose",
        "p002",
        "p003",
        "iac-reviewed",
        "onyx",
        "openhands",
        "dependencies",
        "env-example",
        "dockerfile",
    ]
    path: str | None = None
    key: str = "openapi-service"
    tenant_id: Ref = "tenant-a"
    origin: str | None = None

    @model_validator(mode="after")
    def path_required(self):
        if self.kind != "p001" and not self.path:
            raise Invalid("INPUT-PATH-REQUIRED")
        return self


class InputConfig(Strict):
    schema_version: Literal["p004-input-v1"]
    inputs: list[InputEntry] = Field(min_length=1, max_length=100)


class EndpointDeclaration(Strict):
    path: str
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    auth: Literal["declared", "unknown", "not-applicable"] = "unknown"


class AssetDeclaration(Strict):
    key: Ref
    kind: Kind
    tenant_id: Ref
    label: str | None = None
    address: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    endpoints: list[EndpointDeclaration] = Field(default_factory=list, max_length=100)


class FlowDeclaration(Strict):
    tenant_id: Ref
    source: Ref
    target: Ref
    target_tenant: Ref | None = None
    kind: EdgeKind
    boundary: str | None = None


class ArchitectureDeclaration(Strict):
    schema_version: Literal["p004-architecture-v1"]
    assets: list[AssetDeclaration] = Field(max_length=5000)
    flows: list[FlowDeclaration] = Field(default_factory=list, max_length=10000)
