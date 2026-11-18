"""Strict, versioned records for the consultancy workflow."""

from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from p010 import NOTICE
from p010.safety import HASH_LIMIT, PRIVACY_VERSION, timestamp

ID = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$")]
SHA = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Commit = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{40}$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4096)]
Day = Annotated[str, StringConstraints(pattern=r"^\d{4}-\d\d-\d\d$")]


def nonzero(value: str) -> str:
    if not int(value, 16):
        raise ValueError("Zero context ID")
    return value


TraceID = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$"), AfterValidator(nonzero)]
SpanID = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{16}$"), AfterValidator(nonzero)]


def utc_text(value: str) -> str:
    timestamp(value)
    return value


UTCStamp = Annotated[str, AfterValidator(utc_text), Field(json_schema_extra={"format": "date-time"})]
Role = Literal["AUTHOR", "REVIEWER", "REMEDIATION_OWNER", "RISK_OWNER", "CUSTODIAN"]
Authorship = Literal["HUMAN_AUTHORED", "AI_ASSISTED", "TEMPLATE_GENERATED", "IMPORTED", "TRAINING_FIXTURE"]
Confidence = Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH"]
Quality = Literal["UNKNOWN", "INSUFFICIENT", "LIMITED", "CORROBORATED"]
Status = Literal["PASS", "FAIL", "BLOCKED", "NOT_TESTED", "INCONCLUSIVE", "NOT_APPLICABLE", "FLAKY"]
Rating = Literal["UNRATED", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Applicability = Literal["APPLICABLE", "NOT_APPLICABLE", "OUT_OF_SCOPE", "UNKNOWN", "NEEDS_INFORMATION"]
Treatment = Literal["MITIGATE", "AVOID", "TRANSFER_SHARE", "ACCEPT"]
Disposition = Literal[
    "CONFIRMED",
    "INCONCLUSIVE",
    "NOT_REPRODUCIBLE",
    "FALSE_POSITIVE",
    "OUT_OF_SCOPE",
    "BLOCKED",
    "NOT_TESTED",
    "WITHDRAWN",
]
RecordKind = Literal[
    "engagement",
    "source",
    "evidence",
    "observation",
    "finding",
    "risk",
    "remediation",
    "retest",
    "retest-plan",
    "acceptance",
    "atlas",
    "report",
    "redmine-sync",
]


class Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False, str_max_length=4096
    )


class Link(Strict):
    kind: RecordKind
    id: ID
    version: Annotated[int, Field(ge=1)]
    sha256: SHA


class Actor(Strict):
    ref: ID
    role: Role


class Decision(Strict):
    actor: Actor
    authorship: Authorship
    rationale: Text
    decided_at: UTCStamp


class Window(Strict):
    start: UTCStamp
    end: UTCStamp

    @model_validator(mode="after")
    def ordered(self):
        if timestamp(self.end) <= timestamp(self.start):
            raise ValueError("Assessment window is reversed or empty")
        return self


class Asset(Strict):
    ref: ID
    component: Text
    environment: ID
    scope_ref: ID
    included: bool


class Engagement(Strict):
    schema_version: Literal["p010-engagement-1.0"] = "p010-engagement-1.0"
    title: Text
    client_ref: ID
    status: Literal["SYNTHETIC_EXERCISE", "HISTORICAL_REVIEW"]
    assessment_scope_ref: ID
    p003_policy_digest: SHA | None = None
    assessment_window: Window
    assets: list[Asset] = Field(min_length=1, max_length=100)
    exclusions: list[Text] = Field(max_length=100)
    assessment_objectives: list[Text] = Field(min_length=1, max_length=50)
    methodology_version: ID
    actors: list[Actor] = Field(min_length=2, max_length=50)
    limitations: list[Text] = Field(min_length=1, max_length=50)
    authority_notice: str = NOTICE

    @model_validator(mode="after")
    def unique(self):
        if self.authority_notice != NOTICE:
            raise ValueError("Synthetic authority notice required")
        if len({a.ref for a in self.assets}) != len(self.assets) or len({a.ref for a in self.actors}) != len(
            self.actors
        ):
            raise ValueError("Duplicate asset or actor")
        if not {"AUTHOR", "REVIEWER"} <= {a.role for a in self.actors}:
            raise ValueError("Separate author and reviewer roles required")
        return self


class Artifact(Strict):
    path: Text
    media_type: Text
    declared_sha256: SHA
    declared_size: int = Field(ge=0, le=4_194_304)
    integrity: Literal["VERIFIED_BYTES", "REFERENCE_ONLY", "UNAVAILABLE"]


class SourceRecord(Strict):
    schema_version: Literal["p010-source-1.0"] = "p010-source-1.0"
    project: Literal["P-003", "P-004", "P-005", "P-006", "P-007", "P-008", "P-009", "P-010", "Langfuse"]
    contract: ID
    source_version: ID
    source_record_id: ID
    schema_sha256: SHA | None = None
    source_sha256: SHA | None = None
    source_commit: Commit | None = None
    source_time: UTCStamp | None = None
    imported_at: UTCStamp
    validation: Literal["SCHEMA_VALIDATED", "REFERENCE_ONLY", "VERIFIED_BYTES", "TRAINING_FIXTURE"]
    payload: dict[str, Any]
    artifacts: list[Artifact] = Field(default_factory=list, max_length=128)
    limitations: list[Text] = Field(min_length=1)
    omissions: list[Text] = Field(default_factory=list)
    privacy_policy: Literal["p010-minimization-1.0"] = PRIVACY_VERSION
    transform_version: Literal["p010-source-projection-1.0"] = "p010-source-projection-1.0"


class Reproduction(Strict):
    schema_version: Literal["p010-reproduction-record-1.0"] = "p010-reproduction-record-1.0"
    record_id: ID
    asset_ref: ID
    collection_time: UTCStamp
    preconditions: list[Text] = Field(min_length=1, max_length=20)
    steps: list[Text] = Field(min_length=1, max_length=20)
    expected: Text
    observed: Text
    status: Status
    configuration_ref: ID
    limitations: list[Text] = Field(min_length=1, max_length=20)


class Evidence(Strict):
    schema_version: Literal["p010-evidence-1.0"] = "p010-evidence-1.0"
    source: Link
    source_record_id: ID
    basis: Literal["REPRODUCTION_RECORD", "SOURCE_TEST", "REFERENCE"]
    source_artifact_ref: Text | None = None
    verified_sha256: SHA | None = None
    verified_size: int | None = Field(default=None, ge=0)
    media_type: Text | None = None
    source_time: UTCStamp | None = None
    trace_ref: TraceID | None = None
    observation_ref: SpanID | None = None
    integrity_status: Literal["VERIFIED_BYTES", "REFERENCE_ONLY", "UNAVAILABLE"]
    excerpt: Text | None = None
    excerpt_selected_by: ID | None = None
    evidence_quality: Quality = "UNKNOWN"
    human_review_status: Literal["PENDING", "INSPECTED"] = "PENDING"
    redaction_status: Literal["METADATA_ONLY", "SELECTED_REDACTED_EXCERPT"]
    limitations: list[Text] = Field(min_length=1)
    integrity_limit: str = HASH_LIMIT

    @model_validator(mode="after")
    def integrity(self):
        verified = self.integrity_status == "VERIFIED_BYTES"
        if verified != (self.verified_sha256 is not None and self.verified_size is not None) or (
            not verified and (self.verified_sha256 is not None or self.verified_size is not None)
        ):
            raise ValueError("Only verified bytes have a verified digest and size")
        if (self.excerpt is None) != (self.excerpt_selected_by is None):
            raise ValueError("Excerpt selection requires actor provenance")
        return self


class ObservationDraft(Strict):
    title: Text
    description: Text
    asset_refs: list[ID] = Field(min_length=1, max_length=30)
    scope_ref: ID
    evidence_refs: list[Link] = Field(min_length=1, max_length=30)
    context_refs: list[Link] = Field(default_factory=list, max_length=30)
    expected_behavior: Text
    observed_behavior: Text
    attacker_preconditions: list[Text] = Field(min_length=1, max_length=20)
    reproduction_conditions: Text
    evidence_quality: Quality
    epistemic_status: Literal["OBSERVED", "DECLARED", "INFERRED", "UNKNOWN"]
    alternative_explanations: list[Text] = Field(min_length=1, max_length=20)
    limitations: list[Text] = Field(min_length=1, max_length=30)
    authorship: Authorship


class Observation(ObservationDraft):
    schema_version: Literal["p010-observation-1.0"] = "p010-observation-1.0"
    author_ref: ID
    review_status: Literal["DRAFT", "CANDIDATE", "UNDER_REVIEW", "DISPOSITIONED"]
    disposition: Disposition | None = None
    review: Decision | None = None


class Validation(Strict):
    requirement_ids: list[ID] = Field(min_length=1, max_length=30)
    control_ids: list[ID] = Field(default_factory=list, max_length=30)
    attacker_capability: Text
    reproduction_steps: list[Text] = Field(min_length=1, max_length=20)
    security_impact: Text
    business_impact: Text
    data_impact: Text
    availability_impact: Text
    false_positive_analysis: Text
    limitations: list[Text] = Field(min_length=1, max_length=30)
    inspected_evidence: list[Link] = Field(min_length=1, max_length=30)


class SeverityInput(Strict):
    severity: Rating
    impact: Literal["UNKNOWN", "LIMITED", "MATERIAL", "SEVERE", "SYSTEMIC"]
    exploitability: Literal["UNKNOWN", "HIGH_PRECONDITIONS", "CONDITIONAL", "LIKELY", "REPEATABLE"]
    exposure: Text
    likelihood_rationale: Text
    exploitability_rationale: Text
    business_context: Text
    compensating_controls: list[Text] = Field(max_length=30)
    uncertainty: Text
    confidence: Confidence
    cvss_version: Literal["3.0", "3.1", "4.0"] | None = None
    cvss_vector: Text | None = None
    cvss_source: Text | None = None
    cvss_limitations: Text | None = None

    @model_validator(mode="after")
    def complete_cvss(self):
        parts = (self.cvss_version, self.cvss_vector, self.cvss_source, self.cvss_limitations)
        if any(parts) and (
            not all(parts)
            or self.cvss_vector is None
            or not self.cvss_vector.startswith(f"CVSS:{self.cvss_version}/")
        ):
            raise ValueError("CVSS requires exact source, version, vector and limitations")
        return self


class SeverityDecision(SeverityInput):
    rubric_version: Literal["p010-risk-rubric-1.0"] = "p010-risk-rubric-1.0"
    rubric_sha256: SHA
    suggested_severity: Rating
    decision: Decision


class Finding(Strict):
    schema_version: Literal["p010-finding-1.0"] = "p010-finding-1.0"
    observation: Link
    title: Text
    executive_summary: Text
    author_ref: ID
    validation_status: Literal["CONFIRMED", "WITHDRAWN"]
    validation: Validation
    review_history: list[Decision] = Field(min_length=1, max_length=100)
    severity: SeverityDecision | None = None
    remediation_status: Literal["UNPLANNED", "REMEDIATION_PLANNED", "REMEDIATION_REPORTED"] = "UNPLANNED"
    retest_status: Literal[
        "NOT_TESTED", "PENDING_RETEST", "RETEST_PASSED", "RETEST_FAILED", "INCONCLUSIVE"
    ] = "NOT_TESTED"
    lifecycle: Literal["OPEN", "RESIDUAL_RISK_ACCEPTED", "CLOSED"] = "OPEN"


class RiskInput(Strict):
    source_risk_id: ID
    catalog_source: Link
    description: Text
    affected_assets: list[ID] = Field(min_length=1, max_length=30)
    applicability: Applicability
    threat_refs: list[Link] = Field(default_factory=list, max_length=30)
    finding_refs: list[Link] = Field(default_factory=list, max_length=30)
    control_refs: list[ID] = Field(default_factory=list, max_length=30)
    basis_refs: list[Link] = Field(default_factory=list, max_length=30)
    inherent_risk: Rating
    current_control_state: Text
    residual_risk: Rating
    treatment: Treatment
    treatment_plan: Text
    risk_owner_ref: ID


class Risk(RiskInput):
    schema_version: Literal["p010-risk-register-1.0"] = "p010-risk-register-1.0"
    source_risk_definition: Text | None = None
    source_risk_provenance: Text
    applicability_rationale: Text
    review: Decision


class RemediationInput(Strict):
    recommendation: Text
    affected_control: ID
    owner_ref: ID
    target_date: Day
    dependencies: list[Text] = Field(max_length=30)
    verification_criteria: Text
    compensating_controls: list[Text] = Field(max_length=30)


class Remediation(RemediationInput):
    schema_version: Literal["p010-remediation-1.0"] = "p010-remediation-1.0"
    finding: Link
    recommendation_provenance: Decision
    implementation: Decision | None = None


class TestRef(Strict):
    source: Link
    test_id: ID


class RetestInput(Strict):
    remediation: Link
    plan_ref: Link | None = None
    original_tests: list[TestRef] = Field(min_length=1, max_length=30)
    new_tests: list[TestRef] = Field(min_length=1, max_length=30)
    regression_tests: list[TestRef] = Field(default_factory=list, max_length=30)
    comparable: bool
    configuration_comparison: Text
    source_version_comparison: Text
    expected_behavior: Text
    observed_behavior: Text
    evidence_refs: list[Link] = Field(max_length=30)
    limitations: list[Text] = Field(min_length=1, max_length=30)


class RetestPlanInput(Strict):
    remediation: Link
    original_tests: list[TestRef] = Field(min_length=1, max_length=30)
    planned_checks: list[Text] = Field(min_length=1, max_length=30)
    comparability_criteria: Text
    expected_behavior: Text


class RetestPlan(RetestPlanInput):
    schema_version: Literal["p010-retest-plan-1.0"] = "p010-retest-plan-1.0"
    finding: Link
    plan_provenance: Decision


class Retest(RetestInput):
    schema_version: Literal["p010-retest-1.0"] = "p010-retest-1.0"
    finding: Link
    source_results: list[Status]
    regression_results: list[Status]
    result_status: Status | Literal["NOT_COMPARABLE"]
    review: Decision


class AcceptanceInput(Strict):
    risk: Link
    scope_refs: list[ID] = Field(min_length=1, max_length=30)
    decision: Literal["ACCEPTED", "REJECTED"]
    constraints: list[Text] = Field(min_length=1, max_length=30)
    review_by: UTCStamp
    source_reference: Text


class Acceptance(AcceptanceInput):
    schema_version: Literal["p010-risk-acceptance-1.0"] = "p010-risk-acceptance-1.0"
    owner_decision: Decision


def effective_acceptances(decisions: list[Acceptance]) -> list[Acceptance]:
    """Use the latest decision per exact risk version and normalized scope."""
    latest: dict[tuple[Link, tuple[str, ...]], Acceptance] = {}
    for item in sorted(decisions, key=lambda item: timestamp(item.owner_decision.decided_at)):
        key = (item.risk, tuple(sorted(set(item.scope_refs))))
        if key in latest and timestamp(latest[key].owner_decision.decided_at) == timestamp(
            item.owner_decision.decided_at
        ):
            if latest[key].decision == "REJECTED":
                continue
        latest[key] = item
    return list(latest.values())


class AtlasInput(Strict):
    technique_id: Annotated[str, StringConstraints(pattern=r"^AML\.T\d{4}(?:\.\d{3})?$")]
    state: Literal["CANDIDATE", "REVIEWED", "ACCEPTED", "REJECTED", "NOT_APPLICABLE"]
    confidence: Confidence
    evidence_refs: list[Link] = Field(max_length=30)
    limitations: list[Text] = Field(min_length=1, max_length=30)


class AtlasMapping(AtlasInput):
    schema_version: Literal["p010-atlas-mapping-1.0"] = "p010-atlas-mapping-1.0"
    finding: Link
    title: Text | None
    catalog_version: ID
    catalog_commit: Commit
    catalog_sha256: SHA
    catalog_url: Text
    technique_url: Text | None
    review: Decision


class ReportNarrative(Strict):
    executive_summary: Text
    methodology: Text
    architecture_context: Text
    management_response: Text
    follow_up: Text
    limitations: list[Text] = Field(min_length=1, max_length=30)
    authorship: Authorship


class Gate(Strict):
    code: ID
    passed: bool
    detail: Text


class Report(Strict):
    schema_version: Literal["p010-report-package-1.0"] = "p010-report-package-1.0"
    template_version: Literal["p010-markdown-1.0"] = "p010-markdown-1.0"
    status: Literal["DRAFT", "REVIEW_READY", "REVIEWED", "APPROVED_FOR_DELIVERY", "PUBLISHED"]
    author: Decision
    narrative: ReportNarrative
    source_record_versions: list[Link]
    gates: list[Gate]
    reviews: list[Decision] = Field(default_factory=list)
    approvals: list[Decision] = Field(default_factory=list)
    generated_at: UTCStamp
    oscal_conformance: Literal["NOT VALID OSCAL"] = "NOT VALID OSCAL"
    privacy_policy: Literal["p010-minimization-1.0"] = PRIVACY_VERSION


class TraceReference(Strict):
    trace_id: TraceID
    observation_id: SpanID | None = None
    source_time: UTCStamp
    project_ref: ID
    source: Literal["p009-handoff", "operator-provided"]


class RedmineSync(Strict):
    schema_version: Literal["p010-redmine-sync-1.0"] = "p010-redmine-sync-1.0"
    finding: Link
    project: Literal["p010-synthetic"] = "p010-synthetic"
    mapping_version: Literal["p010-redmine-map-1.0"] = "p010-redmine-map-1.0"
    sync_key: ID
    state: Literal["PENDING_CREATE", "PENDING_UPDATE", "SYNCED", "REJECTED"]
    issue_id: int | None = Field(default=None, ge=1)
    expected_fields: SHA
    remote_fingerprint: SHA | None = None
    synced_at: UTCStamp | None = None


RECORDS: dict[RecordKind, type[Strict]] = {
    "engagement": Engagement,
    "source": SourceRecord,
    "evidence": Evidence,
    "observation": Observation,
    "finding": Finding,
    "risk": Risk,
    "remediation": Remediation,
    "retest": Retest,
    "retest-plan": RetestPlan,
    "acceptance": Acceptance,
    "atlas": AtlasMapping,
    "report": Report,
    "redmine-sync": RedmineSync,
}
