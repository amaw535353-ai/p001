"""Strict canonical contracts. Unknown fields and fabricated source identities fail."""

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Ref = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$")]
SHA = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Trace = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]
Span = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{16}$")]
Status = Literal[
    "PASS",
    "FAIL",
    "BLOCKED",
    "NOT_TESTED",
    "INCONCLUSIVE",
    "NOT_APPLICABLE",
    "REFERENCE_ONLY",
    "PARTIAL",
    "FLAKY",
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False, str_max_length=4096
    )


class Source(Strict):
    source_id: Ref
    source_type: Literal["synthetic", "p006", "otel", "wazuh", "p007", "p008"]
    source_version: Ref
    tenant_ref: Literal["tenant-a", "tenant-b"]
    actor_ref: Ref
    service_id: Ref
    service_version: Ref = "1.0.0"


class SourceEvent(Strict):
    event_id: Ref
    event_type: Literal[
        "request",
        "authorization",
        "tool",
        "model",
        "completion",
        "error",
        "security",
        "alert",
        "health",
        "metric",
        "request_failed",
    ]
    event_time: str
    request_id: Ref | None = None
    trace_id: Trace | None = None
    span_id: Span | None = None
    parent_span_id: Span | None = None
    session_id: Ref | None = None
    conversation_id: Ref | None = None
    tool_call_id: Ref | None = None
    authorization_decision_id: Ref | None = None
    test_id: Ref | None = None
    test_run_id: Ref | None = None
    evaluation_run_id: Ref | None = None
    workload_identity_ref: Ref | None = None
    resource_ref: Ref | None = None
    operation: Ref = "observe"
    decision: Literal["allow", "deny", "unknown"] = "unknown"
    outcome: Literal["success", "denied", "error", "observed", "unknown"] = "observed"
    policy_version: Ref | None = None
    gateway_route_ref: Ref | None = None
    model_ref: Ref | None = None
    alert_id: Ref | None = None
    wazuh_rule_id: Ref | None = None
    artifact_ref: SHA | None = None
    related_event_id: Ref | None = None
    sequence: int | None = Field(default=None, ge=0, le=1_000_000)
    signal: Ref | None = None
    count: int | None = Field(default=None, ge=0, le=1_000_000)
    value: float | None = None

    @field_validator("trace_id", "span_id", "parent_span_id")
    @classmethod
    def nonzero_id(cls, value):
        if value is not None and set(value) == {"0"}:
            raise ValueError("ZERO-CONTEXT-ID")
        return value

    @field_validator("event_time")
    @classmethod
    def timestamp(cls, value):
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        offset = stamp.utcoffset()
        if stamp.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("UTC-REQUIRED")
        return value


class Event(SourceEvent):
    schema_version: Literal["p009-event-1.0"] = "p009-event-1.0"
    event_category: Literal["audit", "trace", "security", "metric", "health"]
    event_severity: int = Field(ge=0, le=15)
    observed_time: str
    source_id: Ref
    source_type: Ref
    source_version: Ref
    environment_id: Literal["p009-synthetic-local"] = "p009-synthetic-local"
    deployment_id: Ref = "p009-local-v1"
    service_id: Ref
    service_version: Ref
    tenant_ref: Literal["tenant-a", "tenant-b"]
    actor_ref: Ref
    source_event_digest: SHA
    correlation_status: Literal["unmatched", "partial"] = "unmatched"
    redaction_status: Literal["metadata-only"] = "metadata-only"
    redaction_policy: Literal["p009-metadata-v1"] = "p009-metadata-v1"
    redacted_fields: int = Field(ge=0)
    provenance: Literal["synthetic-executed", "synthetic-fixture", "source-adapter", "collector-observed"]

    @field_validator("observed_time")
    @classmethod
    def observed_utc(cls, value):
        return SourceEvent.timestamp(value)


class Principal(Strict):
    actor: Ref
    tenant: Literal["tenant-a", "tenant-b"]
    role: Literal["viewer", "exporter", "custodian", "producer"]


class ObjectRef(Strict):
    sha256: SHA
    size: int = Field(ge=0, le=1_048_576)
    kind: Literal["event", "import"]


class Manifest(Strict):
    schema_version: Literal["p009-manifest-1.0"] = "p009-manifest-1.0"
    owner: Literal["p009"] = "p009"
    sequence: int = Field(ge=1)
    previous: SHA | None
    created_at: str
    tenant_ref: Literal["tenant-a", "tenant-b"]
    object: ObjectRef
    source_id: Ref
    source_version: Ref
    source_event_time: str
    config_digest: SHA
    deployment_digest: SHA
    correlation_rule: Literal["p009-exact-v1"] = "p009-exact-v1"
    redaction_policy: Literal["p009-metadata-v1"] = "p009-metadata-v1"


class Link(Strict):
    left: Ref
    right: Ref
    key: Ref
    value: Ref
    rule: Literal["p009-exact-v1"] = "p009-exact-v1"


class Timeline(Strict):
    schema_version: Literal["p009-timeline-1.0"] = "p009-timeline-1.0"
    case_id: Ref
    tenant_ref: Literal["tenant-a", "tenant-b"]
    events: list[Event]
    links: list[Link]
    statuses: dict[str, Literal["exact", "partial", "unmatched", "ambiguous"]]
    missing_types: list[str]
    missing_sequences: list[int]
    out_of_order: list[str]
    clock_skew: list[str]
    rule: Literal["p009-exact-v1"] = "p009-exact-v1"
    integrity: Literal["PASS"] = "PASS"
    limitations: list[str]


class Handoff(Strict):
    schema_version: Literal["1.0"] = "1.0"
    contract: Literal["p009-handoff-v1"] = "p009-handoff-v1"
    tenant_ref: Literal["tenant-a", "tenant-b"]
    manifest_digests: list[SHA]
    objects: list[ObjectRef]
    status_counts: dict[Status, Annotated[int, Field(ge=0, le=1_000_000)]]
    redaction_policy: Literal["p009-metadata-v1"] = "p009-metadata-v1"
    correlation_rule: Literal["p009-exact-v1"] = "p009-exact-v1"
    source_provenance: dict[str, str]
    telemetry_coverage: dict[str, Status]
    limitations: list[str]
    consumer_status: Literal["NOT_TESTED"] = "NOT_TESTED"
    findings: list = Field(default_factory=list, max_length=0)


class Retention(Strict):
    schema_version: Literal["p009-retention-1.0"] = "p009-retention-1.0"
    trace_days: int = Field(default=1, ge=1, le=30)
    audit_days: int = Field(default=7, ge=1, le=30)
    metric_days: int = Field(default=1, ge=1, le=30)
    health_days: int = Field(default=1, ge=1, le=30)
    security_days: int = Field(default=7, ge=1, le=30)
    export_days: int = Field(default=1, ge=1, le=7)
