"""Strict, versioned contracts. Defaults are serialized in every evidence snapshot."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

ID = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,95}$")]
SHA = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Status = Literal["PASS", "FAIL", "BLOCKED", "NOT_TESTED", "INCONCLUSIVE", "NOT_APPLICABLE", "FLAKY"]
Adapter = Literal["offline", "promptfoo", "inspect_ai", "zap", "playwright", "p006"]
Category = Literal[
    "llm",
    "agent",
    "api",
    "browser",
    "passive_scan",
    "active_scan",
    "authorization",
    "secrets",
    "tenant_isolation",
    "availability",
]
ErrorClass = Literal[
    "none", "dependency", "scope", "timeout", "provider", "unsupported", "invalid", "resource"
]


class Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, str_max_length=8192, allow_inf_nan=False
    )
    schema_version: Literal["1.0"] = "1.0"


class Limits(Strict):
    timeout_seconds: int = Field(default=30, ge=1, le=180)
    requests: int = Field(default=16, ge=1, le=64)
    concurrency: Literal[1] = 1
    output_bytes: int = Field(default=262144, ge=1024, le=1048576)
    memory_mb: int = Field(default=1024, ge=256, le=2048)
    cpu_seconds: int = Field(default=60, ge=1, le=180)


class Operation(Strict):
    method: Literal["GET", "POST", "HEAD"] = "GET"
    path: str = Field(pattern=r"^/(?:[A-Za-z0-9_/-]*)$", max_length=120)
    category: Category


class Oracle(Strict):
    equals: dict[str, Any] = Field(min_length=1, max_length=16)
    absent_markers: list[str] = Field(default_factory=list, max_length=8)
    version: Literal["oracle-v1"] = "oracle-v1"


class TestCase(Strict):
    test_id: ID
    version: ID
    title: str
    objective: str
    description: str
    category: Category
    risk_ids: list[ID] = Field(max_length=16)
    threat_ids: list[ID] = Field(max_length=16)
    control_ids: list[ID] = Field(min_length=1, max_length=16)
    requirement_refs: list[ID] = Field(max_length=16)
    target_id: ID
    environment: Literal["offline", "local-lab"]
    authorization_class: Literal["offline-fixture", "bounded-local-api", "passive-inspection", "active-scan"]
    operation: Operation
    preconditions: list[str] = Field(min_length=1, max_length=16)
    fixture_ref: ID
    setup: list[str] = Field(max_length=16)
    adapter: Adapter
    tool_version: str
    oracle: Oracle
    limits: Limits = Field(default_factory=Limits)
    evidence_policy: Literal["synthetic-redacted-v1"] = "synthetic-redacted-v1"
    expected_class: Literal["security-behavior"] = "security-behavior"
    cleanup: list[str] = Field(max_length=16)
    limitations: list[str] = Field(min_length=1, max_length=16)
    owner: ID
    lifecycle: Literal["active", "retired"] = "active"
    safe_for_ci: bool
    offline_only: bool
    operator_approval: bool
    repetitions: int = Field(default=1, ge=1, le=5)
    minimum_pass_rate: float = Field(default=1.0, ge=0.0, le=1.0)


class Control(Strict):
    control_id: ID
    version: ID
    title: str
    requirement: str
    expected_behavior: str
    risk_ids: list[ID]
    threat_ids: list[ID]
    owner: ID
    remediation_state: Literal["hypothesis", "planned", "retested"]


class Target(Strict):
    target_id: ID
    version: ID
    environment: Literal["offline", "local-lab"]
    origin: str
    service_identity: ID
    owner: Literal["p007"]
    ownership_ref: str
    instance_id: ID
    allowed_ips: list[Literal["127.0.0.1"]] = Field(min_length=1, max_length=1)
    operations: list[Operation] = Field(min_length=1, max_length=32)
    capabilities: list[ID]


class AuthorizationReference(Strict):
    engagement_id: ID
    engagement_version: int = Field(ge=1)
    policy_digest: SHA
    store_path: str
    actor: ID
    tenant: ID
    source_identity: ID
    storage_id: ID
    checkpoint_completed: bool
    contact_available: bool
    redaction_confirmed: bool


class ExecutionPlan(Strict):
    plan_id: ID
    digest: SHA
    profile: Adapter
    target: Target
    tests: list[TestCase] = Field(min_length=1, max_length=64)
    controls: list[Control] = Field(min_length=1, max_length=64)
    fixtures: dict[str, Any]
    source_hash: SHA
    request_estimate: int = Field(ge=0, le=512)
    limitations: list[str]


class RunnerResult(Strict):
    adapter: Adapter
    executed: bool
    original_status: str
    exit_code: int | None
    error_class: ErrorClass = "none"
    observed: dict[str, Any] = Field(default_factory=dict)
    samples: list[dict[str, Any]] = Field(default_factory=list, max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)
    commands: list[list[str]] = Field(default_factory=list)
    tool_version: str


class NormalizedResult(Strict):
    test_id: ID
    test_version: ID
    control_ids: list[ID]
    status: Status
    assertion: str
    expected: dict[str, Any]
    observed: dict[str, Any]
    runner: RunnerResult
    definition_hash: SHA
    compatibility_hash: SHA
    compatibility: dict[str, Any]


class Artifact(Strict):
    path: str
    media_type: str
    size: int = Field(ge=0, le=1048576)
    sha256: SHA


class EvidenceManifest(Strict):
    owner: Literal["p007"] = "p007"
    run_id: ID
    started_at: str
    ended_at: str
    duration_seconds: float = Field(ge=0)
    actor_label: ID
    repository: dict[str, Any]
    framework_version: Literal["1.0.0"] = "1.0.0"
    plan_digest: SHA
    target: Target
    authorization: list[dict[str, Any]]
    artifacts: list[Artifact] = Field(min_length=1, max_length=128)
    results: list[NormalizedResult]
    source_hash: SHA
    redaction: list[str]
    limitations: list[str]
    reproduction: str
    provenance: dict[str, str]
    remediation_ref: str | None = None
    retest_of: ID | None = None


class BaselineReference(Strict):
    baseline_id: ID
    run_id: ID
    manifest_sha256: SHA


DiffKind = Literal[
    "REGRESSION",
    "IMPROVED",
    "UNCHANGED_PASS",
    "UNCHANGED_FAIL",
    "NEW_TEST",
    "REMOVED_OR_NOT_APPLICABLE",
    "BLOCKED_OR_NOT_COMPARABLE",
    "FLAKY_OR_INCONCLUSIVE",
]


class DiffEntry(Strict):
    test_id: ID
    classification: DiffKind
    before: Status | None
    after: Status | None
    reason: str


class RegressionDiff(Strict):
    baseline: ID
    current: ID
    entries: list[DiffEntry]
    compatibility_rule: str | None
    remediation_ref: str | None
    retest_evidence: str


class ReproductionRequest(Strict):
    run_id: ID
    test_id: ID
    repetitions: int = Field(default=1, ge=1, le=5)


class ReportExport(Strict):
    run_id: ID
    manifest_sha256: SHA
    results: list[NormalizedResult]
    control_status: dict[str, str]
    handoff: dict[str, Any]
    provenance: dict[str, str]


class Catalog(Strict):
    tests: list[TestCase] = Field(min_length=1, max_length=64)
    controls: list[Control] = Field(min_length=1, max_length=64)
    targets: list[Target] = Field(min_length=1, max_length=16)
    risk_ids: list[ID]
    threat_ids: list[ID]

    @model_validator(mode="after")
    def references(self):
        for rows, key in (
            (self.tests, "test_id"),
            (self.controls, "control_id"),
            (self.targets, "target_id"),
        ):
            if len({getattr(x, key) for x in rows}) != len(rows):
                raise ValueError("DUPLICATE-ID-OR-VERSION-CONFLICT")
        controls = {x.control_id for x in self.controls}
        targets = {x.target_id: x for x in self.targets}
        for test in self.tests:
            if not set(test.control_ids) <= controls or test.target_id not in targets:
                raise ValueError("INVALID-CONTROL-OR-TARGET-REFERENCE")
            if not set(test.risk_ids) <= set(self.risk_ids) or not set(test.threat_ids) <= set(
                self.threat_ids
            ):
                raise ValueError("INVALID-RISK-OR-THREAT-REFERENCE")
            if test.environment != targets[test.target_id].environment:
                raise ValueError("TARGET-ENVIRONMENT-MISMATCH")
        return self


CONTRACTS = {
    "test-case": TestCase,
    "control": Control,
    "target": Target,
    "authorization-reference": AuthorizationReference,
    "execution-plan": ExecutionPlan,
    "runner-result": RunnerResult,
    "normalized-result": NormalizedResult,
    "baseline-reference": BaselineReference,
    "regression-diff": RegressionDiff,
    "evidence-manifest": EvidenceManifest,
    "reproduction-request": ReproductionRequest,
    "report-export": ReportExport,
    "catalog": Catalog,
}
