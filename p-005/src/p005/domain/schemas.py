"""Vendor-independent v1 contracts. Validation is both structural and semantic."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

ID = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z][a-zA-Z0-9_.:-]{1,127}$")]
SHA = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Status = Literal[
    "OBSERVED", "DECLARED", "INFERRED", "UNKNOWN", "UNVERIFIED", "BLOCKED", "NOT_TESTED", "ERROR"
]
Classification = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "UNKNOWN"]
Decision = Literal[
    "PROPOSED", "ACCEPTED_FOR_TESTING", "REJECTED_WITH_REASON", "NOT_APPLICABLE", "NEEDS_INFORMATION"
]
ReviewState = Literal["DRAFT", "NEEDS_REVIEW", "REVIEWED", "APPROVED_FOR_TEST_DESIGN", "SUPERSEDED"]
ScopeState = Literal["IN_SCOPE_MODEL_ONLY", "OUT_OF_SCOPE", "REQUIRES_NEW_AUTHORIZATION"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False, str_max_length=4096)


class EvidenceRef(Strict):
    id: ID
    source: str
    pointer: str
    sanitized_sha256: SHA
    status: Status
    measured_scope: str
    human_reviewed: bool = False


class Claim(Strict):
    id: ID
    epistemic_status: Status = "DECLARED"
    evidence_refs: list[ID] = Field(min_length=1, max_length=32)
    confidence: Literal["DIRECT_METADATA", "DECLARATION", "INFERENCE", "UNKNOWN"] = "DECLARATION"
    assumptions: list[str] = Field(default_factory=list, max_length=32)
    requires_human_review: Literal[True] = True


class TrustZone(Claim):
    id: ID
    label: str
    tenant_id: ID
    owner_role: str
    trust_level: Literal["UNTRUSTED", "APPLICATION", "PRIVILEGED", "EXTERNAL", "UNKNOWN"]


class Features(Strict):
    untrusted_content: bool = False
    privileged_actions: bool = False
    autonomous: bool = False
    generates_content: bool = False
    persistent_memory: bool = False
    coding_workspace: bool = False
    egress: bool = False
    logging: Literal["DECLARED", "DISABLED", "UNKNOWN"] = "UNKNOWN"
    budget: Literal["DECLARED", "MISSING", "UNKNOWN"] = "UNKNOWN"
    retention: Literal["DECLARED", "UNKNOWN"] = "UNKNOWN"
    dependency_provenance: Literal["DECLARED", "UNKNOWN"] = "UNKNOWN"


class Node(Claim):
    id: ID
    source_id: str | None = None
    kind: Literal[
        "Asset",
        "Actor",
        "HumanIdentity",
        "WorkloadIdentity",
        "IdentityProvider",
        "Agent",
        "Tool",
        "MCPServer",
        "A2APeer",
        "LLMGateway",
        "ModelEndpoint",
        "Retriever",
        "Connector",
        "VectorDatabase",
        "ApplicationService",
        "API",
        "DataStore",
        "DocumentCollection",
        "KubernetesNamespace",
        "CloudResource",
        "SecretStore",
        "TelemetrySink",
        "ExternalDependency",
        "ApprovalGate",
        "CIPipeline",
        "Browser",
        "PolicyEnforcementPoint",
        "PolicyDecisionPoint",
        "Evaluator",
        "Guardrail",
        "Memory",
    ]
    label: str
    address: str | None = None
    owner_role: str
    zone_id: ID
    tenant_id: ID
    environment_id: ID = "synthetic-lab"
    sensitivity: Classification = "UNKNOWN"
    integrity: Literal["LOW", "HIGH", "UNKNOWN"] = "UNKNOWN"
    allowed_actor_ids: list[ID] = Field(default_factory=list, max_length=32)
    principal_id: ID | None = None
    surface: list[str] = Field(default_factory=list, max_length=32)
    privilege: Literal["NONE", "READ", "WRITE", "ADMIN", "UNKNOWN"] = "UNKNOWN"
    reachable: Status = "NOT_TESTED"
    source_snapshot: SHA
    features: Features = Field(default_factory=Features)


class Flow(Claim):
    id: ID
    source_id: ID | None = None
    source: ID
    target: ID
    kind: Literal[
        "invokes",
        "retrieves",
        "responds",
        "delegates",
        "executes",
        "approves",
        "authenticates",
        "authorizes",
        "logs",
        "stores",
        "deploys",
        "reads",
        "writes",
        "hosts",
        "transmits",
    ]
    tenant_id: ID
    principal_id: ID | None = None
    data_type: str
    classification: Classification = "UNKNOWN"
    channel: str = "UNKNOWN"
    entry_point: str | None = None
    authorization: Literal["CONTROL_DECLARED", "UNKNOWN", "DISABLED"] = "UNKNOWN"
    authorization_point_id: ID | None = None
    delegation: Literal["NONE", "SCOPED", "BROAD", "UNKNOWN"] = "UNKNOWN"
    token_audience: Literal["EXPECTED", "MISMATCH", "UNKNOWN"] = "UNKNOWN"
    approval_binding: Literal["DECLARED", "MISSING", "UNKNOWN"] = "UNKNOWN"
    encryption: Literal["DECLARED_TLS", "OBSERVED_TLS", "PLAINTEXT", "UNKNOWN"] = "UNKNOWN"
    transformation: str = "UNKNOWN"
    expected_decision: Literal["ALLOW", "DENY", "UNKNOWN"] = "UNKNOWN"
    declared_grant_effect: Literal["ALLOW", "DENY"] | None = None
    enforcement_result: Literal["NOT_TESTED"] = "NOT_TESTED"
    grants_freshness: Literal["DECLARED", "STALE", "UNKNOWN"] = "UNKNOWN"


BoundaryReason = Literal[
    "ZONE",
    "TENANT",
    "OWNER",
    "IDENTITY",
    "AGENT_TOOL",
    "APPROVAL",
    "CONTENT",
    "PROVIDER",
    "CONTROL_PLANE",
    "UNKNOWN_TRUST",
]


class Boundary(Claim):
    id: ID
    zone_pair: list[ID] = Field(min_length=2, max_length=2)
    edge_ids: list[ID] = Field(min_length=1, max_length=32)
    reasons: list[
        Literal[
            "ZONE",
            "TENANT",
            "OWNER",
            "IDENTITY",
            "AGENT_TOOL",
            "APPROVAL",
            "CONTENT",
            "PROVIDER",
            "CONTROL_PLANE",
            "UNKNOWN_TRUST",
        ]
    ] = Field(min_length=1)
    actor_ids: list[ID] = Field(default_factory=list, max_length=32)


class IntegrationResult(Strict):
    project: Literal["P-001", "P-002", "P-003", "P-004"]
    status: Literal["VERIFIED", "CONTRACT_ONLY", "NOT_TESTED", "BLOCKED", "INCOMPATIBLE"]
    evidence_refs: list[str]
    reason: str


class Scope(Strict):
    source: str
    source_digest: SHA | None = None
    in_scope_node_ids: list[ID] = Field(default_factory=list, max_length=512)
    out_of_scope_node_ids: list[ID] = Field(default_factory=list, max_length=512)
    allowed_activity: Literal["offline-modeling-only"] = "offline-modeling-only"
    prohibited_activities: list[str] = Field(
        default_factory=lambda: ["live-testing", "scanning", "cloud-changes"]
    )
    real_legal_authority: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"


class Model(Strict):
    schema_version: Literal["p005-model-1.0"]
    model_id: ID
    engagement_id: ID
    engagement_version: int = Field(ge=1)
    system_id: ID
    model_version: int = Field(ge=1)
    created_utc: str
    snapshot_source: str
    source_snapshot_hash: SHA
    git_commit: str
    dataset_seed: int
    tool_versions: dict[str, str]
    environment_id: ID
    author_role: Literal["builder"] = "builder"
    review_state: ReviewState = "DRAFT"
    assumptions: list[str]
    exclusions: list[str]
    model_scope: Scope
    sanitization_status: Literal["REDACTED_BEFORE_PUBLIC_HASH"] = "REDACTED_BEFORE_PUBLIC_HASH"
    tenants: list[ID] = Field(min_length=1, max_length=32)
    zones: list[TrustZone] = Field(min_length=1, max_length=128)
    nodes: list[Node] = Field(min_length=1, max_length=512)
    flows: list[Flow] = Field(max_length=1024)
    boundaries: list[Boundary] = Field(default_factory=list, max_length=1024)
    evidence: list[EvidenceRef] = Field(min_length=1, max_length=4096)
    integrations: list[IntegrationResult] = Field(default_factory=list, max_length=4)
    source_context: list[dict[str, str | list[str]]] = Field(default_factory=list, max_length=16)

    @field_validator("created_utc")
    @classmethod
    def utc(cls, value: str) -> str:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return value

    @model_validator(mode="after")
    def references(self):
        zones = {z.id: z for z in self.zones}
        nodes = {n.id: n for n in self.nodes}
        edges = {e.id: e for e in self.flows}
        evidence = {e.id: e for e in self.evidence}
        claims = [*self.zones, *self.nodes, *self.flows, *self.boundaries]
        ids = [x.id for x in claims] + list(evidence)
        if len(ids) != len(set(ids)) or len(evidence) != len(self.evidence):
            raise ValueError("DUPLICATE-GRAPH-ID")
        if len(self.tenants) != len(set(self.tenants)):
            raise ValueError("DUPLICATE-TENANT")
        for zone in self.zones:
            if zone.tenant_id not in self.tenants:
                raise ValueError("ZONE-TENANT-REFERENCE")
        for node in self.nodes:
            if node.zone_id not in zones or node.tenant_id != zones[node.zone_id].tenant_id:
                raise ValueError("NODE-ZONE-TENANT-REFERENCE")
            for principal in [*node.allowed_actor_ids, *([node.principal_id] if node.principal_id else [])]:
                if principal not in nodes or nodes[principal].kind not in (
                    "HumanIdentity",
                    "WorkloadIdentity",
                    "Actor",
                ):
                    raise ValueError("PRINCIPAL-REFERENCE")
                if nodes[principal].tenant_id not in (node.tenant_id, "shared"):
                    raise ValueError("CROSS-TENANT-PRINCIPAL")
        for edge in self.flows:
            if edge.source not in nodes or edge.target not in nodes:
                raise ValueError("ORPHAN-FLOW")
            if edge.tenant_id != nodes[edge.source].tenant_id:
                raise ValueError("FLOW-TENANT-REFERENCE")
            if edge.principal_id and (
                edge.principal_id not in nodes
                or nodes[edge.principal_id].kind not in ("HumanIdentity", "WorkloadIdentity", "Actor")
            ):
                raise ValueError("FLOW-PRINCIPAL-REFERENCE")
            if edge.principal_id and nodes[edge.principal_id].tenant_id not in (edge.tenant_id, "shared"):
                raise ValueError("FLOW-PRINCIPAL-TENANT-MISMATCH")
            if edge.authorization_point_id and (
                edge.authorization_point_id not in nodes
                or nodes[edge.authorization_point_id].kind
                not in ("PolicyEnforcementPoint", "PolicyDecisionPoint")
            ):
                raise ValueError("AUTHORIZATION-POINT-REFERENCE")
            if edge.encryption == "OBSERVED_TLS" and edge.epistemic_status != "OBSERVED":
                raise ValueError("UNSUPPORTED-ENCRYPTION-OBSERVATION")
        for claim in claims:
            if any(ref not in evidence for ref in claim.evidence_refs):
                raise ValueError("EVIDENCE-REFERENCE")
            if claim.epistemic_status == "OBSERVED" and not any(
                evidence[ref].status == "OBSERVED" and evidence[ref].measured_scope
                for ref in claim.evidence_refs
            ):
                raise ValueError("OBSERVATION-PROVENANCE-REQUIRED")
            if claim.confidence == "DIRECT_METADATA" and claim.epistemic_status != "OBSERVED":
                raise ValueError("DIRECT-CONFIDENCE-REQUIRES-OBSERVATION")
        for boundary in self.boundaries:
            if any(z not in zones for z in boundary.zone_pair) or any(
                e not in edges for e in boundary.edge_ids
            ):
                raise ValueError("BOUNDARY-REFERENCE")
            for eid in boundary.edge_ids:
                edge = edges[eid]
                if [nodes[edge.source].zone_id, nodes[edge.target].zone_id] != boundary.zone_pair:
                    raise ValueError("BOUNDARY-ZONE-PAIR")
            if any(p not in nodes for p in boundary.actor_ids):
                raise ValueError("BOUNDARY-ACTOR-REFERENCE")
        scope_ids = self.model_scope.in_scope_node_ids + self.model_scope.out_of_scope_node_ids
        if any(n not in nodes for n in scope_ids) or set(self.model_scope.in_scope_node_ids) & set(
            self.model_scope.out_of_scope_node_ids
        ):
            raise ValueError("SCOPE-REFERENCE")
        return self


class Triage(Strict):
    potential_impact: Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    exposure: Status
    attacker_preconditions: list[str]
    control_strength_unknown: Literal[True] = True
    evidence_quality: Literal["DIRECT_METADATA", "DECLARATION", "INFERENCE", "UNKNOWN"]
    uncertainty: str
    human_review_priority: Literal["HIGH", "MEDIUM", "LOW"]
    rationale: str


class ThreatScenario(Strict):
    schema_version: Literal["p005-threat-1.0"] = "p005-threat-1.0"
    threat_id: ID
    title: str
    status: Literal["MODELLED_THREAT"] = "MODELLED_THREAT"
    hypothesis_status: Literal["HYPOTHESIS"] = "HYPOTHESIS"
    node_ids: list[ID]
    edge_ids: list[ID]
    boundary_ids: list[ID]
    tenant_id: ID
    risk_ids: list[str]
    risk_source: str
    analysis_method: list[str]
    preconditions: list[str]
    attacker_capability: str
    target_behavior: str
    trust_assumption: str
    abuse_path_id: ID
    security_property: str
    business_impact_hypothesis: str
    plausibility_rationale: str
    confidence: str
    evidence_refs: list[ID]
    applicability: Decision = "PROPOSED"
    mitigation_ids: list[ID]
    control_ids: list[ID]
    test_ids: list[ID]
    owner_role: str
    review_status: ReviewState = "NEEDS_REVIEW"
    rule_trace: dict[str, str | list[str]]
    triage: Triage
    revision_history: list[str]


class ThreatPath(Strict):
    id: ID
    node_ids: list[ID] = Field(min_length=2, max_length=5)
    edge_ids: list[ID] = Field(min_length=1, max_length=4)
    boundary_ids: list[ID]
    status: Literal["HYPOTHESIS"] = "HYPOTHESIS"
    uncertainty: str


class ControlRequirement(Strict):
    id: ID
    threat_id: ID
    state: Literal["CONTROL_PROPOSED"] = "CONTROL_PROPOSED"
    requirement: str
    external_requirement_id: Literal[None] = None
    external_mapping_status: Literal["UNMAPPED_PENDING_P083"] = "UNMAPPED_PENDING_P083"
    owner_role: str
    objective: str
    acceptance_criteria: list[str]


class Mitigation(Strict):
    id: ID
    threat_id: ID
    control_id: ID
    state: Literal["CONTROL_PROPOSED"] = "CONTROL_PROPOSED"
    owner_role: str
    objective: str
    functions: list[Literal["prevent", "detect", "respond", "recover"]]
    acceptance_criteria: list[str]
    expected_functionality: str
    test_ids: list[ID]
    residual_unknowns: list[str]


class VerificationCase(Strict):
    test_id: ID
    threat_id: ID
    boundary_ids: list[ID]
    setup_assumptions: list[str]
    permitted_actor: str
    forbidden_actor: str
    positive_path: str
    negative_path: str
    expected_result: str
    required_evidence: list[str]
    prerequisites: list[str]
    scope_state: ScopeState
    roe_check_state: Literal["REQUIRES_NEW_AUTHORIZATION", "OUT_OF_SCOPE"]
    executor: Literal["human_assessor"] = "human_assessor"
    run_status: Literal["NOT_TESTED"] = "NOT_TESTED"
    executable: Literal[False] = False


class HumanReview(Strict):
    schema_version: Literal["p005-review-1.0"] = "p005-review-1.0"
    threat_id: ID
    model_digest: SHA
    sequence: int = Field(ge=1)
    reviewer_role: str
    decision: Decision
    reason: str = Field(min_length=8)
    priority_override: Literal["HIGH", "MEDIUM", "LOW"] | None = None
    at_utc: str
    synthetic_editorial_only: Literal[True] = True
    authenticated_identity: Literal[False] = False

    @field_validator("at_utc")
    @classmethod
    def utc(cls, value: str) -> str:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return value


class AdapterResult(Strict):
    tool: str
    version: str | None = None
    schema_version: str | None = None
    executed: Literal[False] = False
    exit_status: Literal[None] = None
    source_digest: SHA | None = None
    output_digest: Literal[None] = None
    warnings: list[str]
    unsupported_fields: list[str]
    tested_roundtrip: Literal[False] = False
    evidence_ref: str
    verification_status: Literal["BLOCKED", "NOT_TESTED"] = "BLOCKED"
