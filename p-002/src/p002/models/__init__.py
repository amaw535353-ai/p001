"""Version 1 canonical model. Schema changes require an explicit migration."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator
from p002 import NOTICE

ID = Annotated[str, StringConstraints(pattern=r"^p002:[a-z0-9][a-z0-9:_-]{0,127}$")]
Stamp = Annotated[str, StringConstraints(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")]
T0 = "2026-01-01T00:00:00Z"
NOW = "2026-01-15T12:00:00Z"
END = "2027-01-01T00:00:00Z"
Action = Literal["read", "update", "approve", "execute"]


class Classification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Record(Strict):
    id: ID
    tenant_id: ID
    owner_id: ID
    provenance_id: ID
    created_at: Stamp = T0
    schema_version: Literal["1.0"] = "1.0"
    notice: Literal["SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT"] = NOTICE
    lineage: list[ID] = Field(default_factory=list, max_length=64)
    status: Literal["active", "disabled", "deleted", "pending", "approved", "revoked"] = "active"

    @field_validator("created_at")
    @classmethod
    def real_date(cls, v):
        datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ")
        return v


class Enterprise(Record):
    name: str


class Tenant(Record):
    enterprise_id: ID
    name: str
    domain: Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]+\.example\.test$")]


class Department(Record):
    name: str
    manager_id: ID


class HumanUser(Record):
    department_id: ID
    display_name: str
    email: Annotated[str, StringConstraints(pattern=r"^[a-z0-9._-]+@[a-z0-9-]+\.example\.test$")]
    role: Literal["manager", "analyst", "reviewer"]
    manager_id: ID | None = None
    hired_at: Stamp = T0
    terminated_at: Stamp | None = None


class Group(Record):
    department_id: ID
    name: str


class GroupMembership(Record):
    group_id: ID
    user_id: ID
    valid_from: Stamp = T0
    valid_until: Stamp = END
    revoked_at: Stamp | None = None


class WorkloadIdentity(Record):
    department_id: ID
    name: str
    authentication: Literal["nonfunctional-placeholder"] = "nonfunctional-placeholder"


class Resource(Record):
    department_id: ID
    title: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    classification: Classification
    parent_id: ID | None = None
    deleted_at: Stamp | None = None
    retention: Literal["retain", "scheduled-delete", "deleted"] = "retain"
    approval_state: Literal["draft", "approved"] = "approved"
    kind: Literal[
        "folder",
        "document",
        "kb-page",
        "invoice",
        "tool-config",
        "mock-dataset",
        "cloud-object",
        "issue",
        "project",
    ]
    version: int = Field(default=1, ge=1)
    attributes: dict[str, str | int] = Field(default_factory=dict)


class Folder(Record):
    resource_id: ID


class Document(Record):
    resource_id: ID
    body: Annotated[str, StringConstraints(max_length=32768)]
    trust: Literal["trusted-template", "untrusted-text"] = "trusted-template"
    content_sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]


class DocumentVersion(Record):
    document_id: ID
    version: int = Field(ge=1)
    body_sha256: str
    effective_at: Stamp = T0


class DataOwner(Record):
    resource_id: ID
    user_id: ID


class Provenance(Record):
    source: Literal["self-created-template", "sdv-self-generated"] = "self-created-template"
    generator_version: Literal["1.0.0"] = "1.0.0"


class Project(Record):
    resource_id: ID
    name: str


class Issue(Record):
    resource_id: ID
    project_id: ID
    reporter_id: ID
    assignee_id: ID
    subject: str
    state: Literal["new", "in-review", "closed"] = "new"


class IssueComment(Record):
    issue_id: ID
    author_id: ID
    body: str


class LabelDefinition(Record):
    name: Classification
    semantics: Literal["metadata-only"] = "metadata-only"


class LabelingTask(Record):
    document_id: ID
    label_ids: list[ID] = Field(min_length=4, max_length=4)


class Annotation(Record):
    task_id: ID
    annotator_id: ID
    label_id: ID


class PermissionGrant(Record):
    principal_id: ID
    resource_id: ID
    actions: list[Action] = Field(min_length=1, max_length=4)
    effect: Literal["ALLOW", "DENY"] = "ALLOW"
    inherited: bool = False
    cross_tenant: bool = False
    valid_from: Stamp = T0
    valid_until: Stamp = END
    revoked_at: Stamp | None = None


class Delegation(Record):
    caller_id: ID
    service_id: ID
    resource_id: ID
    actions: list[Action]
    valid_from: Stamp = T0
    valid_until: Stamp = END
    revoked_at: Stamp | None = None


class ActionRequest(Record):
    requester_id: ID
    resource_id: ID
    action: Literal["execute"] = "execute"
    parameters: dict[str, str | int]
    parameters_sha256: str


class Approval(Record):
    request_id: ID
    approver_id: ID
    parameters_sha256: str
    valid_from: Stamp = T0
    valid_until: Stamp = END


class BusinessEvent(Record):
    event_type: Literal[
        "onboarding",
        "offboarding",
        "hr-case",
        "invoice-review",
        "engineering-change",
        "procurement",
        "knowledge-retrieval",
    ]
    actor_id: ID
    resource_id: ID
    effective_at: Stamp


class LifecycleEvent(Record):
    target_id: ID
    event_type: Literal["hire", "terminate", "membership-revoke", "delete", "reclassify"]
    effective_at: Stamp
    before: str
    after: str


class Context(Strict):
    time: Stamp = NOW
    caller_id: ID | None = None
    request_id: ID | None = None
    parameters_sha256: str | None = None

    @field_validator("time")
    @classmethod
    def valid_clock(cls, value):
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return value


class ExpectedDecision(Record):
    actor_id: ID
    action: Action
    resource_id: ID
    context: Context
    expected: Literal["ALLOW", "DENY"]
    reason: str
    rule_ids: list[str]
    origin: Literal["generated oracle"] = "generated oracle"
    observed_result: None = None


class EvidencePointer(Strict):
    path: str
    sha256: str


class ObservedResult(Strict):
    id: str
    expected_decision_id: str | None = None
    platform: str
    actor: str
    operation: str
    http_status: int
    outcome: Literal["ALLOW", "DENY"]
    utc: Stamp
    evidence: EvidencePointer | None = None
    origin: Literal["OBSERVED_ENFORCEMENT"] = "OBSERVED_ENFORCEMENT"


class ThreatHypothesis(Strict):
    risk_ids: list[int]
    taxonomy_status: Literal["number-from-user-request; source-taxonomy-unavailable"] = (
        "number-from-user-request; source-taxonomy-unavailable"
    )
    finding: None = None


class ScenarioStep(Strict):
    operation: Literal[
        "positive",
        "cross-tenant",
        "peer-department",
        "revoke",
        "delete-index",
        "delegation",
        "approval",
        "untrusted-text",
        "provenance",
        "canary",
        "ticket",
        "annotation",
    ]
    description: str


class Scenario(Strict):
    id: Annotated[str, StringConstraints(pattern=r"^S(0[1-9]|1[0-2])$")]
    schema_version: Literal["1.0"] = "1.0"
    title: str
    hypothesis: ThreatHypothesis
    supporting_pids: list[Literal["P-002"]]
    subsystem: str
    business_objective: str
    assets: list[ID]
    logical_time: Stamp = NOW
    initial_entitlements: list[str]
    test_oracle: str
    actor: str
    starting_state: str
    trust_boundary: str
    assumptions: list[str]
    steps: list[ScenarioStep] = Field(min_length=1)
    positive_expected: str
    negative_expected: str
    stop_reset: str
    unsafe: bool = False
    status: Literal["PREPARED", "SEEDED", "EXECUTED", "OBSERVED", "ASSESSED", "RETESTED"] = "PREPARED"
    human_finding: None = None
    remediation: None = None
    retest: None = None
    residual_risk: None = None
    human_verifier: None = None
    evidence_fields: list[str]


class Dataset(Strict):
    schema_version: Literal["1.0"] = "1.0"
    generator_version: Literal["1.0.0"] = "1.0.0"
    notice: Literal["SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT"] = NOTICE
    seed: int = Field(ge=0, le=2**32 - 1)
    logical_time: Stamp = NOW
    profile: Literal["tiny", "standard", "stress-local"]
    mode: Literal["fixtures", "sdv"] = "fixtures"
    sdv_report: dict = Field(default_factory=dict)
    enterprises: list[Enterprise]
    tenants: list[Tenant]
    departments: list[Department]
    humans: list[HumanUser]
    groups: list[Group]
    memberships: list[GroupMembership]
    workloads: list[WorkloadIdentity]
    resources: list[Resource]
    folders: list[Folder]
    documents: list[Document]
    versions: list[DocumentVersion]
    owners: list[DataOwner]
    provenance: list[Provenance]
    projects: list[Project]
    issues: list[Issue]
    comments: list[IssueComment]
    labels: list[LabelDefinition]
    tasks: list[LabelingTask]
    annotations: list[Annotation]
    grants: list[PermissionGrant]
    delegations: list[Delegation]
    requests: list[ActionRequest]
    approvals: list[Approval]
    business_events: list[BusinessEvent]
    lifecycle_events: list[LifecycleEvent]
    decisions: list[ExpectedDecision]
    scenarios: list[Scenario]

    @model_validator(mode="after")
    def graph(self):
        from p002.validation import validate_graph

        validate_graph(self)
        return self

    def tables(self):
        return {
            name: getattr(self, name)
            for name in type(self).model_fields
            if isinstance(getattr(self, name), list) and name != "scenarios"
        }
