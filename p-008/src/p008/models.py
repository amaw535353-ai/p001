"""Strict versioned data contracts; executable checks supplement JSON Schema."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

ID = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$")]
SHA = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Version = Annotated[str, StringConstraints(pattern=r"^\d+\.\d+\.\d+$")]
Text = Annotated[str, StringConstraints(min_length=1, max_length=8192)]
Family = Literal["integrity", "injection", "authorization", "disclosure", "boundary", "context"]
SplitName = Literal["development", "validation", "public_benchmark", "sealed_holdout", "regression"]
Status = Literal["PASS", "FAIL", "BLOCKED", "NOT_TESTED", "INCONCLUSIVE", "FLAKY"]
Dimension = Literal["security", "utility", "refusal_correctness", "trace", "correctness"]


class Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False, str_max_length=8192
    )
    schema_version: Literal["1.0"] = "1.0"


class Provenance(Strict):
    source_type: Literal["synthetic", "user_authored", "upstream_benchmark"]
    author: Text
    generator: Text
    generator_version: Version
    seed: int = Field(ge=0, le=4294967295)
    source_sha256: SHA
    repository: Text
    commit: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{40}$")]
    location: Text
    license_id: Literal["MIT", "Apache-2.0", "CC0-1.0", "CC-BY-4.0", "LicenseRef-P008-Synthetic"]
    attribution: Text
    redistribution: Literal["allowed", "restricted", "review_required"]


class DatasetCard(Strict):
    dataset_id: ID
    version: Version
    name: Text
    description: Text
    purpose: Text
    owner: ID
    created: Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    last_reviewed: Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    status: Literal["draft", "frozen", "retired"]
    provenance: Provenance
    modalities: list[Literal["text"]] = Field(min_length=1, max_length=1)
    families: list[Family] = Field(min_length=1, max_length=6)
    risk_ids: list[Literal[21]] = Field(max_length=1)
    capabilities: list[Literal["structured_response", "mock_tool_trace"]] = Field(min_length=1, max_length=2)
    sample_count: int = Field(ge=1, le=256)
    manifest_digest: SHA
    split_policy: Literal["lineage-group-sha256-v1"]
    label_review: Literal["synthetic-rule-reviewed-by-Codex-not-human"]
    limitations: list[Text] = Field(min_length=1, max_length=16)
    non_use_cases: list[Text] = Field(min_length=1, max_length=16)


class Turn(Strict):
    role: Literal["user", "assistant", "retrieved"]
    content: Text
    trust: Literal["user", "untrusted", "simulated"]


class VisibleInput(Strict):
    operation: Literal["integrity", "direct", "indirect", "authorize", "disclose", "boundary", "context"]
    prompt: Text
    actor_tenant: Literal["tenant-a", "tenant-b"]
    object_tenant: Literal["tenant-a", "tenant-b"]
    classification: Literal["public", "restricted"]
    action: Literal["read", "write", "delete", "export"]
    approved: bool
    current_role: Literal["reader", "editor", "revoked"]
    history: list[Turn] = Field(max_length=8)
    resource_id: ID


class ToolAction(Strict):
    tool: Literal["mock_read", "mock_write", "mock_delete", "mock_export"]
    resource_id: ID
    decision: Literal["ALLOW", "DENY"]
    server_applied: bool


class AgentTrace(Strict):
    actions: list[ToolAction] = Field(max_length=8)
    environment: Literal["p008-isolated-memory-v1"] = "p008-isolated-memory-v1"


class Observation(Strict):
    decision: Literal["ALLOW", "DENY"]
    reply: Text
    disclosed: bool
    trace: AgentTrace


class ExpectedOutcome(Strict):
    outcome_id: ID
    version: Version
    decision: Literal["ALLOW", "DENY"]
    reply: Text
    allow_disclosure: Literal[False] = False
    allowed_actions: list[Literal["read", "write", "delete", "export"]] = Field(max_length=4)
    forbidden_actions: list[Literal["read", "write", "delete", "export"]] = Field(max_length=4)
    required_tool: Literal["mock_read", "mock_write", "mock_delete", "mock_export"] | None
    basis: Text
    label_provenance: Text
    adjudication: Literal["synthetic_rule", "ambiguous", "disputed", "human_adjudicated"]
    human_evidence_ref: Text | None = None
    label_key: Text

    @model_validator(mode="after")
    def consistency(self):
        if set(self.allowed_actions) & set(self.forbidden_actions):
            raise ValueError("CONFLICTING-ACTION-LABELS")
        if (self.adjudication == "human_adjudicated") != (self.human_evidence_ref is not None):
            raise ValueError("HUMAN-EVIDENCE-REQUIRED-ONLY-FOR-HUMAN-LABEL")
        return self


class Scenario(Strict):
    scenario_id: ID
    version: Version
    family: Family
    hypothesis: Text
    source_template: ID
    construction_method: ID
    risk_ids: list[Literal[21]] = Field(max_length=1)
    attacker_capability: Text
    trust: Literal["untrusted-content", "synthetic-user"]
    limitations: list[Text] = Field(min_length=1, max_length=8)


class Task(Strict):
    task_id: ID
    version: Version
    family: Family
    scenario_ids: list[ID] = Field(min_length=1, max_length=32)
    scorer_id: ID
    scorer_version: Version
    implementation_digest: SHA
    capabilities: list[Literal["structured_response", "mock_tool_trace"]] = Field(min_length=1, max_length=2)
    authorized_environment: Literal["p008-isolated-memory-v1"] = "p008-isolated-memory-v1"


class Rubric(Strict):
    rubric_id: ID
    version: Version
    dimensions: list[Dimension] = Field(min_length=1, max_length=5)
    rule: Literal["all-required-dimensions-at-threshold-v1"]
    threshold: float = Field(ge=0, le=1)
    critical_security_failure_veto: Literal[True] = True
    rationale: Text


class Scorer(Strict):
    scorer_id: ID
    version: Version
    implementation_digest: SHA
    rubric: Rubric
    kind: Literal["deterministic", "model_judge"]
    permitted_fields: list[Literal["observation", "expected_outcome", "untrusted_content"]] = Field(
        min_length=1
    )
    hidden_label_access: bool = False
    calibration_ref: Text | None = None
    limitations: list[Text] = Field(min_length=1, max_length=8)
    human_review_policy: Text

    @model_validator(mode="after")
    def label_access(self):
        if self.kind == "model_judge" and (
            self.hidden_label_access or "expected_outcome" in self.permitted_fields
        ):
            raise ValueError("JUDGE-HIDDEN-LABEL-ACCESS-FORBIDDEN")
        if ("expected_outcome" in self.permitted_fields) != self.hidden_label_access:
            raise ValueError("INCONSISTENT-SCORER-LABEL-ACCESS")
        return self


class Evaluator(Strict):
    evaluator_id: ID
    version: Version
    tool: Literal["offline", "inspect_ai", "inspect_evals", "agentdojo", "promptfoo"]
    tool_version: Text
    adapter_version: Version
    implementation_digest: SHA
    provider: Literal["p008-local"]
    model: Literal["deterministic-policy-v1"]
    model_version: Version
    prompt: Text
    config: Literal["reviewed-local-v1"]
    policy: Literal["baseline", "corrected", "alternating", "provider_error", "timeout"] = "baseline"
    temperature: Literal[0] = 0
    network: Literal["disabled"] = "disabled"
    judge_prompt: Text | None = None
    judge_role: Literal["disabled", "supplementary"] = "disabled"


class EvaluationSample(Strict):
    sample_id: ID
    version: Version
    dataset_id: ID
    dataset_version: Version
    scenario_id: ID
    scenario_version: Version
    task_id: ID
    task_version: Version
    scorer_id: ID
    scorer_version: Version
    expected_outcome_ref: ID
    input: VisibleInput
    modality: Literal["text"]
    encoding: Literal["utf-8"]
    provenance: Provenance
    split: SplitName
    group_key: ID
    difficulty: Literal["easy", "moderate"]
    tags: list[ID] = Field(min_length=1, max_length=8)
    limitations: list[Text] = Field(min_length=1, max_length=8)
    fixture_dependencies: list[ID] = Field(max_length=8)
    dimensions: list[Dimension] = Field(min_length=1, max_length=5)
    content_digest: SHA


class DatasetSplit(Strict):
    name: SplitName
    sample_ids: list[ID] = Field(min_length=1, max_length=256)
    seed: int = Field(ge=0, le=4294967295)
    policy: Literal["lineage-group-sha256-v1"]


class Artifact(Strict):
    path: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,160}$")]
    sha256: SHA
    size: int = Field(ge=0, le=4194304)


class DatasetManifest(Strict):
    dataset_id: ID
    version: Version
    generator_source_hash: SHA
    sample_ids: list[ID] = Field(min_length=1, max_length=256)
    sample_hashes: dict[ID, SHA]
    split_hash: SHA
    bundle_digest: SHA
    artifacts: list[Artifact] = Field(min_length=1, max_length=32)


class Bundle(Strict):
    card: DatasetCard
    samples: list[EvaluationSample] = Field(min_length=1, max_length=256)
    outcomes: list[ExpectedOutcome] = Field(min_length=1, max_length=256)
    scenarios: list[Scenario] = Field(min_length=1, max_length=64)
    tasks: list[Task] = Field(min_length=1, max_length=32)
    scorers: list[Scorer] = Field(min_length=1, max_length=16)
    splits: list[DatasetSplit] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def references(self):
        tables = (
            (self.samples, "sample_id"),
            (self.outcomes, "outcome_id"),
            (self.scenarios, "scenario_id"),
            (self.tasks, "task_id"),
            (self.scorers, "scorer_id"),
            (self.splits, "name"),
        )
        for rows, key in tables:
            if len({getattr(x, key) for x in rows}) != len(rows):
                raise ValueError("DUPLICATE-ID-OR-VERSION-CONFLICT")
        tasks = {t.task_id: t for t in self.tasks}
        scenarios = {s.scenario_id: s for s in self.scenarios}
        scorers = {s.scorer_id: s for s in self.scorers}
        outcomes = {o.outcome_id: o for o in self.outcomes}
        if self.card.sample_count != len(self.samples):
            raise ValueError("SAMPLE-COUNT-MISMATCH")
        for task in self.tasks:
            if task.scorer_id not in scorers or task.scorer_version != scorers[task.scorer_id].version:
                raise ValueError("TASK-SCORER-REFERENCE")
            if any(x not in scenarios or scenarios[x].family != task.family for x in task.scenario_ids):
                raise ValueError("TASK-SCENARIO-REFERENCE")
        for sample in self.samples:
            if (sample.dataset_id, sample.dataset_version) != (self.card.dataset_id, self.card.version):
                raise ValueError("DATASET-REFERENCE")
            if sample.task_id not in tasks or sample.scenario_id not in scenarios:
                raise ValueError("TASK-OR-SCENARIO-REFERENCE")
            task, scenario = tasks[sample.task_id], scenarios[sample.scenario_id]
            if sample.scenario_id not in task.scenario_ids or sample.scenario_version != scenario.version:
                raise ValueError("SAMPLE-SCENARIO-VERSION-REFERENCE")
            if sample.task_version != task.version or sample.scorer_id != task.scorer_id:
                raise ValueError("SAMPLE-TASK-SCORER-REFERENCE")
            if sample.scorer_version != task.scorer_version or sample.expected_outcome_ref not in outcomes:
                raise ValueError("SCORER-OR-OUTCOME-REFERENCE")
            if sample.dimensions != scorers[sample.scorer_id].rubric.dimensions:
                raise ValueError("SCORE-DIMENSIONS-MISMATCH")
            if not set(task.capabilities) <= set(self.card.capabilities):
                raise ValueError("UNSUPPORTED-CAPABILITY")
        if set(outcomes) != {s.expected_outcome_ref for s in self.samples}:
            raise ValueError("ORPHAN-EXPECTED-OUTCOME")
        split_ids = [x for split in self.splits for x in split.sample_ids]
        if len(split_ids) != len(set(split_ids)) or set(split_ids) != {s.sample_id for s in self.samples}:
            raise ValueError("SPLIT-MEMBERSHIP-MISMATCH")
        for split in self.splits:
            if set(split.sample_ids) != {s.sample_id for s in self.samples if s.split == split.name}:
                raise ValueError("SPLIT-DECLARATION-MISMATCH")
        return self


class Limits(Strict):
    timeout_seconds: int = Field(default=90, ge=1, le=180)
    cpu_seconds: int = Field(default=90, ge=1, le=180)
    memory_mb: int = Field(default=2048, ge=256, le=4096)
    output_bytes: int = Field(default=4194304, ge=1024, le=8388608)
    concurrency: Literal[1] = 1


class EvaluationPlan(Strict):
    plan_id: ID
    dataset_id: ID
    dataset_version: Version
    manifest_digest: SHA
    sample_ids: list[ID] = Field(min_length=1, max_length=256)
    split: SplitName | Literal["all"]
    split_hash: SHA
    task_hash: SHA
    scorer_hash: SHA
    evaluator: Evaluator
    repetitions: int = Field(ge=1, le=5)
    seed: int = Field(ge=0, le=4294967295)
    source_hashes: dict[str, SHA]
    dependency_lock_hash: SHA
    runtime: Text
    limits: Limits
    network: Literal["disabled"] = "disabled"


class SampleResult(Strict):
    sample_id: ID
    repetition: int = Field(ge=0, le=4)
    status: Status
    original_status: Text
    observation: Observation | None
    dimensions: dict[Dimension, Annotated[float, Field(ge=0, le=1)]]
    critical_failure: bool
    scorer_digest: SHA
    rubric_version: Version
    threshold: float = Field(ge=0, le=1)
    error_class: Literal["none", "dependency", "timeout", "provider", "unsupported", "resource"]
    explanation: Text


class Metrics(Strict):
    unique_samples: int = Field(ge=0, le=256)
    observations: int = Field(ge=0, le=1280)
    executed: int = Field(ge=0, le=1280)
    passed: int = Field(ge=0, le=1280)
    failed: int = Field(ge=0, le=1280)
    blocked: int = Field(ge=0, le=1280)
    not_tested: int = Field(ge=0, le=1280)
    inconclusive: int = Field(ge=0, le=1280)
    flaky_sample_ids: list[ID]
    critical_sample_ids: list[ID]
    unique_pass_rate: float | None = Field(ge=0, le=1)
    wilson95: list[float] | None
    categories: dict[str, dict[str, int]]
    false_accepts: int = Field(ge=0)
    false_rejects: int = Field(ge=0)
    definitions: Text
    limitations: Text


class EvaluationRun(Strict):
    owner: Literal["p008"] = "p008"
    run_id: ID
    started_at: Text
    ended_at: Text
    actor: Literal["Codex tested"] = "Codex tested"
    plan: EvaluationPlan
    plan_digest: SHA
    results: list[SampleResult] = Field(min_length=1, max_length=1280)
    metrics: Metrics
    status: Status
    artifacts: list[Artifact] = Field(max_length=32)
    baseline: bool
    limitations: list[Text] = Field(min_length=1)
    reproduction: Text


Classification = Literal[
    "IMPROVED",
    "REGRESSED",
    "UNCHANGED",
    "MIXED",
    "NEW_OR_REMOVED_SAMPLES",
    "DATASET_CHANGED",
    "SCORER_OR_EVALUATOR_CHANGED",
    "MODEL_OR_PROVIDER_CHANGED",
    "NOT_COMPARABLE",
    "BLOCKED",
    "INCONCLUSIVE",
    "FLAKY",
]


class Comparison(Strict):
    baseline: ID
    current: ID
    classification: Classification
    comparable: bool
    reasons: list[Text]
    transitions: dict[ID, list[str]]
    pass_rate_delta: float | None
    compatibility_rule: Literal["strict-identity-v1"] = "strict-identity-v1"


class IntegrityEvent(Strict):
    event_id: ID
    mutation: Text
    original_digest: SHA
    altered_digest: SHA
    detected: bool
    control: Text
    explanation: Text
    residual_limit: Text


class HumanAdjudication(Strict):
    adjudication_id: ID
    sample_id: ID
    previous_outcome_digest: SHA
    proposed_outcome_digest: SHA
    state: Literal["pending", "accepted", "rejected"]
    reviewer: ID | None
    evidence: Text | None
    reason: Text

    @model_validator(mode="after")
    def evidence_required(self):
        if self.state != "pending" and (not self.reviewer or not self.evidence):
            raise ValueError("HUMAN-REVIEW-EVIDENCE-REQUIRED")
        return self


class P007Import(Strict):
    contract: Literal["ReportExport-1.0"]
    original_run_id: ID
    original_manifest_sha256: SHA
    source_sha256: SHA
    report: dict
    live_integration: Literal["PASS", "BLOCKED", "NOT_TESTED"]
    limitation: Text


CONTRACTS = {
    "dataset-card": DatasetCard,
    "dataset-manifest": DatasetManifest,
    "evaluation-sample": EvaluationSample,
    "scenario": Scenario,
    "task": Task,
    "expected-outcome": ExpectedOutcome,
    "agent-trace": AgentTrace,
    "tool-action": ToolAction,
    "scoring-rubric": Rubric,
    "scorer-definition": Scorer,
    "evaluator-definition": Evaluator,
    "dataset-split": DatasetSplit,
    "evaluation-plan": EvaluationPlan,
    "sample-result": SampleResult,
    "evaluation-run": EvaluationRun,
    "evaluation-comparison": Comparison,
    "provenance-record": Provenance,
    "integrity-event": IntegrityEvent,
    "human-adjudication": HumanAdjudication,
    "p007-report-import": P007Import,
    "dataset-bundle": Bundle,
}
