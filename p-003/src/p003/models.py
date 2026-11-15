"""Typed schema contracts; cross-field and digest validation supplements JSON Schema."""

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from p003 import NOTICE, __version__
from p003.targets import normalize
from p003.util import clock, digest, safe

Text = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
Ref = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:_-]{0,127}$")]
SHA = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]


def utc_stamp(value: str) -> str:
    clock(value)
    return value


Stamp = Annotated[
    str, StringConstraints(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"), AfterValidator(utc_stamp)
]
Activity = Literal["passive-inspection", "config-review", "bounded-local-api", "synthetic-prompt-evaluation"]
Kind = Literal["url", "ip", "cidr", "host", "namespace", "project"]
Role = Literal["requestor", "assessor", "reviewer", "owner"]
State = Literal[
    "DRAFT",
    "SUBMITTED",
    "APPROVED",
    "ACTIVE",
    "SUSPENDED",
    "EXPIRED",
    "CLOSED",
    "REJECTED",
    "REVOKED",
    "SUPERSEDED",
]
Method = Literal["GET", "HEAD", "POST", "PUT", "OPTIONS"]


class Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, str_max_length=4096, allow_inf_nan=False
    )


class Artifact(Strict):
    schema_version: Literal["1.0"] = "1.0"
    id: str
    notice: Literal["SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING"] = NOTICE
    source: Text
    author: Ref
    reviewer: Ref | None = None
    classification: Literal["synthetic-public", "synthetic-internal"] = "synthetic-internal"
    created_at: Stamp
    content_digest: str = ""

    @field_validator("id")
    @classmethod
    def uuid_id(cls, value):
        UUID(value)
        return value

    @field_validator("created_at")
    @classmethod
    def timestamp(cls, value):
        clock(value)
        return value

    @model_validator(mode="after")
    def integrity(self):
        data = self.model_dump(mode="json")
        claimed = data.pop("content_digest")
        safe(data)
        if claimed and claimed != digest(data):
            raise ValueError("artifact digest mismatch")
        return self


def sealed(model: type[Artifact], **data):
    data.pop("content_digest", None)
    instance = model.model_validate(data)
    payload = instance.model_dump(mode="json")
    payload.pop("content_digest")
    return model.model_validate({**payload, "content_digest": digest(payload)})


def verified(instance: Artifact) -> None:
    if not instance.content_digest:
        raise ValueError("unsealed artifact")
    type(instance).model_validate(instance.model_dump(mode="json"))


class Window(Strict):
    start: Stamp
    end: Stamp

    @model_validator(mode="after")
    def interval(self):
        if clock(self.start) >= clock(self.end):
            raise ValueError("empty/reversed window")
        return self


class Actor(Strict):
    ref: Ref
    client_id: Ref
    tenant: Ref
    role: Role
    identity_status: Literal["fictional-role-not-identity-verification"] = (
        "fictional-role-not-identity-verification"
    )


class Client(Artifact):
    client_id: Ref
    name: Text
    owner_role: Literal["owner"] = "owner"
    contact_role: Literal["reviewer"] = "reviewer"
    data_sensitivity: Literal["synthetic-only"] = "synthetic-only"
    caveats: Text


class Selector(Strict):
    kind: Kind
    value: Annotated[str, StringConstraints(min_length=1, max_length=2048)]

    @model_validator(mode="after")
    def canonical_target(self):
        normalized = normalize(self.kind, self.value)
        object.__setattr__(self, "value", normalized)
        return self


class Asset(Artifact):
    asset_id: Ref
    tenant: Ref
    owner: Ref
    service: Text
    environment: Literal["local-lab", "offline"]
    selector: Selector
    methods: list[Method] = Field(min_length=1, max_length=5)
    data_class: Literal["synthetic-only"] = "synthetic-only"
    ownership: Literal["synthetic-owned", "external-unverified"]
    included: bool
    third_party_restrictions: list[Text] = Field(max_length=32)
    trust_boundaries: list[Text] = Field(min_length=1, max_length=32)


class Exclusion(Strict):
    selector: Selector
    reason: Text


class Scope(Artifact):
    included_asset_ids: list[Ref] = Field(min_length=1, max_length=256)
    exclusions: list[Exclusion] = Field(max_length=256)
    activities: list[Activity] = Field(min_length=1, max_length=4)
    procedures: list[Text] = Field(min_length=1, max_length=64)
    project_ids: list[Ref] = Field(min_length=1, max_length=16)
    candidate_risk_ids: list[Annotated[int, Field(ge=1, le=37)]] = Field(max_length=37)
    risk_mapping_status: Literal["candidate hypotheses; taxonomy source unavailable"] = (
        "candidate hypotheses; taxonomy source unavailable"
    )
    constraints: list[Text] = Field(min_length=1, max_length=64)


class EvidencePolicy(Artifact):
    data_class: Literal["synthetic-only"] = "synthetic-only"
    storage_ids: list[Ref] = Field(min_length=1, max_length=8)
    access_roles: list[Role] = Field(min_length=1, max_length=4)
    retention_days: int = Field(ge=1, le=365)
    redact_before_export: Literal[True] = True
    deletion: Text
    incident_notification: Text
    custody_references: list[Ref] = Field(max_length=64)


class ROE(Artifact):
    window: Window
    allowed: list[Activity] = Field(min_length=1, max_length=4)
    forbidden: list[Text] = Field(min_length=1, max_length=32)
    max_total_requests: int = Field(ge=1, le=1000)
    max_requests_per_minute: int = Field(ge=1, le=60)
    max_cost_units: int = Field(ge=0, le=1000)
    max_interruption_ms: int = Field(ge=0, le=100)
    source_identities: list[Ref] = Field(min_length=1, max_length=16)
    human_checkpoint: Literal[True] = True
    emergency_contact: Ref | None
    contact_confirmed: bool
    stop_conditions: list[
        Literal["budget-exhausted", "contact-missing", "data-breach", "service-interruption", "human-stop"]
    ] = Field(min_length=5, max_length=5)
    recovery: Text
    communications: Text

    @model_validator(mode="after")
    def stops_unique(self):
        if len(set(self.stop_conditions)) != 5:
            raise ValueError("all stop conditions are mandatory")
        return self


class Requirement(Strict):
    source: Literal["OWASP AISVS"] = "OWASP AISVS"
    version: Literal["1.01"] = "1.01"
    requirement_id: Annotated[str, StringConstraints(pattern=r"^v1\.01-C5\.\d+\.\d+$")]
    exact_text: Text
    level: int = Field(ge=1, le=3)
    applicability: Text
    asset_ids: list[Ref] = Field(min_length=1, max_length=256)
    planned_method: Text
    required_evidence: list[Text] = Field(min_length=1, max_length=16)
    state: Literal["planned", "not-tested", "not-applicable", "inconclusive"]


class Engagement(Artifact):
    engagement_id: Ref
    version: int = Field(ge=1, le=10000)
    client: Client
    tenant: Ref
    goals: list[Text] = Field(min_length=1, max_length=32)
    engagement_type: Literal["configuration-audit", "architecture-review", "llm-agent-assessment"]
    business_context: Text
    risk_assumptions: list[Text] = Field(min_length=1, max_length=32)
    sponsors: list[Ref] = Field(min_length=1, max_length=16)
    actors: list[Actor] = Field(min_length=4, max_length=4)
    window: Window
    scope: Scope
    roe: ROE
    assets: list[Asset] = Field(min_length=1, max_length=256)
    evidence_policy: EvidencePolicy
    requirements: list[Requirement] = Field(max_length=64)
    parent_digest: SHA | None
    change_reason: Text

    @model_validator(mode="after")
    def relations(self):
        for record in [self.client, self.scope, self.roe, self.evidence_policy, *self.assets]:
            verified(record)
        if len({a.ref for a in self.actors}) != 4 or {a.role for a in self.actors} != {
            "requestor",
            "assessor",
            "reviewer",
            "owner",
        }:
            raise ValueError("four distinct actors and roles required")
        if any(a.client_id != self.client.client_id or a.tenant != self.tenant for a in self.actors):
            raise ValueError("actor/client/tenant mismatch")
        assets = {a.asset_id: a for a in self.assets}
        if len(assets) != len(self.assets) or len(
            {(a.selector.kind, a.selector.value) for a in self.assets}
        ) != len(self.assets):
            raise ValueError("duplicate asset IDs/selectors")
        if any(a.tenant != self.tenant for a in self.assets):
            raise ValueError("asset tenant mismatch")
        actor_refs = {a.ref for a in self.actors}
        if any(a.owner not in actor_refs for a in self.assets) or set(self.sponsors) - actor_refs:
            raise ValueError("unknown asset owner or sponsor reference")
        contacts = {a.ref for a in self.actors if a.role in ("owner", "reviewer")}
        if self.roe.emergency_contact is not None and self.roe.emergency_contact not in contacts:
            raise ValueError("unknown emergency contact role reference")
        if any(x not in assets or not assets[x].included for x in self.scope.included_asset_ids):
            raise ValueError("scope references missing/excluded asset")
        if set(self.scope.activities) - set(self.roe.allowed):
            raise ValueError("scope exceeds ROE activities")
        if self.roe.window.start < self.window.start or self.roe.window.end > self.window.end:
            raise ValueError("ROE window exceeds engagement")
        if (self.version == 1) != (self.parent_digest is None):
            raise ValueError("version parent linkage")
        if self.author != next(a.ref for a in self.actors if a.role == "requestor"):
            raise ValueError("author must be requestor")
        from p003.frameworks import verify_requirement

        for req in self.requirements:
            verify_requirement(req)
            if set(req.asset_ids) - set(assets):
                raise ValueError("requirement references unknown asset")
        return self


class ReviewEvidence(Artifact):
    evidence_ref: Ref
    engagement_id: Ref
    version: int = Field(ge=1)
    policy_digest: SHA
    claimed_authority: Literal["fictional training reviewer only"] = "fictional training reviewer only"
    checklist: Literal["SIMULATED-REVIEW-NOT-IDENTITY-VERIFICATION"]
    reviewed: Literal[True]
    real_legal_authority: Literal["NOT VERIFIED"] = "NOT VERIFIED"


class Authorization(Artifact):
    engagement_id: Ref
    version: int = Field(ge=1)
    policy_digest: SHA
    approving_role: Literal["reviewer"] = "reviewer"
    evidence_ref: Ref
    evidence_sha256: SHA
    reviewed: Literal[True] = True
    checklist: Literal["SIMULATED-REVIEW-NOT-IDENTITY-VERIFICATION"]
    targets: list[Selector] = Field(min_length=1, max_length=256)
    activities: list[Activity] = Field(min_length=1, max_length=4)
    window: Window
    exceptions: list[Text] = Field(max_length=0)
    revocation_history: list[Ref] = Field(max_length=0)
    real_legal_authority: Literal["NOT VERIFIED"] = "NOT VERIFIED"


class Budget(Strict):
    used_total: int = Field(ge=0, le=1000000)
    used_last_minute: int = Field(ge=0, le=1000000)
    requested: int = Field(ge=1, le=1000000)
    used_cost_units: int = Field(ge=0, le=1000000)
    requested_cost_units: int = Field(ge=0, le=1000000)
    interruption_ms: int = Field(ge=0, le=1000000)


class Context(Strict):
    tenant: Ref
    environment: Literal["local-lab", "offline"]
    method: Method
    source_identity: Ref
    checkpoint_completed: bool
    contact_available: bool
    redirects_expected: bool
    data_class: Literal["synthetic-only"]
    storage_id: Ref
    redaction_confirmed: bool
    data_breach: bool


class CheckRequest(Strict):
    schema_version: Literal["1.0"] = "1.0"
    notice: Literal["SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING"] = NOTICE
    engagement_id: Ref
    engagement_version: int = Field(ge=1)
    actor: Ref
    test_class: Activity
    target: Selector
    at: Stamp
    budget: Budget
    context: Context

    @field_validator("at")
    @classmethod
    def timestamp(cls, value):
        clock(value)
        return value


class StopEvent(Artifact):
    engagement_id: Ref
    version: int = Field(ge=1)
    reason: Text
    effective_at: Stamp
    status: Literal["SUSPENDED", "REVOKED", "CLOSED", "EXPIRED"]
    approval_link: Ref | None


class Amendment(Artifact):
    engagement_id: Ref
    old_version: int = Field(ge=1)
    new_version: int = Field(ge=2)
    old_scope_digest: SHA
    new_scope_digest: SHA
    reason: Text
    approval_link: Ref | None = None
    status: Literal["pending-fresh-approval"] = "pending-fresh-approval"


class ExceptionRecord(Artifact):
    purpose: Text
    old_scope_digest: SHA
    new_scope_digest: SHA
    reason: Text
    evidence_ref: Ref
    approval_link: Ref | None
    effective_at: Stamp
    status: Literal["DENIED-REQUIRES-NEW-VERSION"] = "DENIED-REQUIRES-NEW-VERSION"


class Decision(Artifact):
    decision: Literal["ALLOW", "DENY"]
    rationale: list[Ref] = Field(min_length=1)
    matched_clauses: list[Ref]
    engagement_id: Ref | None
    engagement_version: int | None
    policy_digest: SHA | None
    approval_digest: SHA | None
    engine_version: Literal["1.0.0"] = __version__
    remaining_constraints: list[Text]
    request_digest: SHA
    authority_status: Literal["NOT VERIFIED"] = "NOT VERIFIED"
    target_enforcement: Literal["NOT VERIFIED"] = "NOT VERIFIED"


class Event(Artifact):
    sequence: int = Field(ge=1)
    engagement_id: Ref
    event_type: Literal["create", "submit", "approve", "activate", "amend", "stop", "reject", "decision"]
    actor: Ref
    purpose: Text
    previous_digest: SHA | None
    payload: dict


class PolicyManifest(Artifact):
    kind: Literal["engagement-policy"]
    engagement_id: Ref
    engagement_version: int = Field(ge=1)
    status: State
    policy_digest: SHA
    scope: Scope
    target_inventory: list[Asset] = Field(min_length=1, max_length=256)
    window: Window
    expires_at: Stamp
    resource_limits_and_stops: ROE
    evidence_policy: EvidencePolicy
    authority_provenance: Authorization | None
    ledger_head: SHA
    consumption: Text
    enforcement: Text
    real_legal_authority: Literal["NOT VERIFIED"]

    @model_validator(mode="after")
    def nested_seals(self):
        for artifact in [
            self.scope,
            self.resource_limits_and_stops,
            self.evidence_policy,
            *self.target_inventory,
        ]:
            verified(artifact)
        if self.authority_provenance:
            verified(self.authority_provenance)
        return self


class EventReference(Strict):
    reference: Ref
    sha256: SHA
    event_type: Ref
    sequence: int = Field(ge=1)


class ReviewReference(Strict):
    reference: Ref
    sha256: SHA


class EvidenceManifest(Artifact):
    kind: Literal["evidence-manifest"]
    engagement_id: Ref
    engagement_version: int = Field(ge=1)
    policy_digest: SHA
    chain_head: SHA
    artifacts: list[EventReference]
    review_references: list[ReviewReference]
    custody: Text
    sanitization: Text
    learner_gates: dict[Literal["G1", "G2", "G3", "G4"], Literal["NOT DEMONSTRATED"]]

    @model_validator(mode="after")
    def all_gates(self):
        if set(self.learner_gates) != {"G1", "G2", "G3", "G4"}:
            raise ValueError("all human gates must remain explicit")
        return self
