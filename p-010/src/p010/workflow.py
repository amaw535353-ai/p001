"""Operator actions that turn evidence into reviewed records."""

from datetime import date
from typing import Literal

from p010.models import (
    Acceptance,
    AcceptanceInput,
    Actor,
    Authorship,
    Decision,
    Disposition,
    Engagement,
    Evidence,
    Finding,
    Link,
    Observation,
    ObservationDraft,
    Rating,
    RecordKind,
    Remediation,
    RemediationInput,
    Retest,
    RetestInput,
    RetestPlan,
    RetestPlanInput,
    Risk,
    RiskInput,
    Role,
    SeverityDecision,
    SeverityInput,
    SourceRecord,
    Status,
    Strict,
    TestRef,
    Validation,
    effective_acceptances,
)
from p010.safety import ROOT, Invalid, digest, is_placeholder, load, now, redact_text, timestamp
from p010.store import Store, Version, validate

REVIEW_AUTHORSHIP = {"HUMAN_AUTHORED", "AI_ASSISTED", "TRAINING_FIXTURE"}


def register_engagement(
    store: Store, id_: str, engagement: Engagement, actor_ref: str, *, at: str | None = None
) -> Version:
    actor = next((a for a in engagement.actors if a.ref == actor_ref and a.role == "AUTHOR"), None)
    if actor is None:
        raise Invalid("An engagement author must initialize the engagement")
    return store.save(
        "engagement",
        id_,
        id_,
        engagement,
        actor,
        action="engagement-init",
        rationale="Initialized a local synthetic engagement",
        at=at,
    )


def rubric() -> dict:
    data = load(ROOT / "data/rubric.json")
    return {**data, "sha256": digest(data)}


def suggest(value: SeverityInput, quality: str) -> Rating:
    if quality in {"UNKNOWN", "INSUFFICIENT"} or "UNKNOWN" in (value.impact, value.exploitability):
        return "UNRATED"
    return rubric()["matrix"][value.impact][value.exploitability]


class Workflow:
    def __init__(self, store: Store, engagement_id: str, actor_ref: str, *, at: str | None = None):
        self.store = store
        self.id = engagement_id
        self.at = at or now()
        self.engagement_version = store.current("engagement", engagement_id)
        self.engagement = self.engagement_version.as_type(Engagement)
        actor = next((item for item in self.engagement.actors if item.ref == actor_ref), None)
        if actor is None:
            raise Invalid("Operator is absent from the engagement role registry")
        self.actor: Actor = actor

    def require(self, *roles: Role) -> None:
        if self.actor.role not in roles:
            raise Invalid("Operator role cannot perform this action")

    def decision(
        self, rationale: str, authorship: Authorship, *, independent_of: str | None = None
    ) -> Decision:
        if not rationale.strip() or is_placeholder(rationale):
            raise Invalid("A substantive authored rationale is required")
        if authorship not in REVIEW_AUTHORSHIP:
            raise Invalid("An attributable operator decision is required")
        if authorship == "TRAINING_FIXTURE" and self.engagement.status != "SYNTHETIC_EXERCISE":
            raise Invalid("Simulated decisions are limited to synthetic exercises")
        if independent_of == self.actor.ref:
            raise Invalid("The actor must be independent of the author")
        return validate(
            Decision,
            dict(
                actor=self.actor.model_dump(), rationale=rationale, authorship=authorship, decided_at=self.at
            ),
        )

    def current(self, kind: RecordKind, id_: str) -> Version:
        version = self.store.current(kind, id_)
        if version.envelope.engagement_id != self.id:
            raise Invalid("Cross-engagement record access refused")
        return version

    def resolve(self, link: Link) -> Version:
        return self.store.resolve(link, self.id)

    def save(
        self,
        kind: RecordKind,
        id_: str,
        data: Strict,
        action: str,
        rationale: str,
        previous: Link | None = None,
    ) -> Version:
        return self.store.save(
            kind,
            id_,
            self.id,
            data,
            self.actor,
            previous=previous,
            action=action,
            rationale=rationale,
            at=self.at,
        )

    def audit(self, operation: str, rationale: str, records: list[Link] | None = None) -> None:
        self.store.audit(self.id, self.actor, operation, rationale, records=records, at=self.at)

    def import_source(self, source: SourceRecord) -> Version:
        self.require("AUTHOR", "CUSTODIAN")
        identity = source.source_sha256 or digest(source.payload)
        id_ = "src-" + digest([self.id, source.project, identity, source.source_record_id])[:42]
        current = self.store.latest("source", id_, required=False)
        if current is not None:
            old = current.as_type(SourceRecord)
            if old.model_dump(exclude={"imported_at"}) == source.model_dump(exclude={"imported_at"}):
                return current
            if old.validation == "VERIFIED_BYTES" and source.validation != "VERIFIED_BYTES":
                raise Invalid("Refusing to replace a byte-verified source with a reference")
        return self.save(
            "source",
            id_,
            source,
            "source-import",
            "Read-only import through a versioned source adapter",
            current.link if current else None,
        )

    def make_evidence(
        self,
        id_: str,
        source_link: Link,
        source_item: str,
        artifact_path: str | None,
        *,
        excerpt: str | None = None,
    ) -> Version:
        self.require("AUTHOR", "CUSTODIAN")
        source = self.resolve(source_link).as_type(SourceRecord)
        item_ids = {source.source_record_id}
        event = None
        if source.project == "P-007":
            item_ids.update(row["test_id"] for row in source.payload["results"])
        if source.project == "P-009":
            item_ids.update(row["event_id"] for row in source.payload["event_references"])
            event = next(
                (row for row in source.payload["event_references"] if row["event_id"] == source_item), None
            )
        if source.project == "P-005":
            item_ids.update(row["threat_id"] for row in source.payload.get("threats", []))
        if source_item not in item_ids:
            raise Invalid("Evidence source identity is unavailable")
        artifact = next((a for a in source.artifacts if a.path == artifact_path), None)
        if artifact_path and not artifact:
            raise Invalid("Artifact reference is absent from the selected source")
        if source.contract == "p010-reproduction-record-1.0" and artifact is None:
            artifact = source.artifacts[0]
        integrity = artifact.integrity if artifact else "REFERENCE_ONLY"
        basis: Literal["REPRODUCTION_RECORD", "SOURCE_TEST", "REFERENCE"] = "REFERENCE"
        if source.contract == "p010-reproduction-record-1.0" and integrity == "VERIFIED_BYTES":
            basis = "REPRODUCTION_RECORD"
        elif (
            source.project == "P-007"
            and artifact
            and artifact.path == source_item + ".json"
            and integrity == "VERIFIED_BYTES"
        ):
            basis = "SOURCE_TEST"
        evidence = Evidence(
            source=source_link,
            source_record_id=source_item,
            basis=basis,
            source_artifact_ref=artifact.path if artifact else None,
            media_type=artifact.media_type if artifact else None,
            verified_sha256=artifact.declared_sha256 if artifact and integrity == "VERIFIED_BYTES" else None,
            verified_size=artifact.declared_size if artifact and integrity == "VERIFIED_BYTES" else None,
            integrity_status=integrity,
            source_time=event["event_time"] if event else source.source_time,
            trace_ref=event.get("trace_id")
            if event
            else source.payload.get("trace_id")
            if source.project == "Langfuse"
            else None,
            observation_ref=event.get("span_id")
            if event
            else source.payload.get("observation_id")
            if source.project == "Langfuse"
            else None,
            excerpt=redact_text(excerpt) if excerpt else None,
            excerpt_selected_by=self.actor.ref if excerpt else None,
            redaction_status="SELECTED_REDACTED_EXCERPT" if excerpt else "METADATA_ONLY",
            limitations=source.limitations,
        )
        return self.save(
            "evidence", id_, evidence, "evidence-link", "Linked an explicitly selected source record"
        )

    def observation(self, id_: str, data: ObservationDraft) -> Version:
        self.require("AUTHOR")
        previous = self.store.latest("observation", id_, required=False)
        if previous and (
            previous.envelope.engagement_id != self.id
            or previous.as_type(Observation).review_status != "DRAFT"
            or previous.as_type(Observation).author_ref != self.actor.ref
        ):
            raise Invalid("Only the original author can edit an unsubmitted draft")
        if set(data.asset_refs) - {asset.ref for asset in self.engagement.assets}:
            raise Invalid("Unknown observation asset")
        for link in data.evidence_refs:
            self.resolve(link).as_type(Evidence)
        for link in data.context_refs:
            self.resolve(link).as_type(SourceRecord)
        if self.engagement.p003_policy_digest and not self.policy_matches():
            raise Invalid("P-003 policy, scope, assessment window and included assets must match")
        value = Observation(**data.model_dump(), author_ref=self.actor.ref, review_status="DRAFT")
        return self.save(
            "observation",
            id_,
            value,
            "observation-draft",
            "Authored an observation draft",
            previous.link if previous else None,
        )

    def policy_matches(self) -> bool:
        e = self.engagement
        return any(
            v.data.contract == "p003-engagement-policy-1.0"
            and v.data.payload.get("policy_digest") == e.p003_policy_digest
            and v.data.payload.get("scope", {}).get("id") == e.assessment_scope_ref
            and v.data.payload.get("window") == e.assessment_window.model_dump()
            and {row["asset_id"] for row in v.data.payload.get("assets", []) if row["included"]}
            == {a.ref for a in e.assets if a.included}
            for v in self.store.versions(self.id, current=True)
            if isinstance(v.data, SourceRecord)
        )

    def submit(self, id_: str) -> Version:
        self.require("AUTHOR")
        current = self.current("observation", id_)
        row = current.as_type(Observation)
        if row.review_status != "DRAFT" or row.author_ref != self.actor.ref:
            raise Invalid("Only the draft author may submit an unsubmitted observation")
        candidate = self.save(
            "observation",
            id_,
            row.model_copy(update={"review_status": "CANDIDATE"}),
            "candidate",
            "Prepared a candidate observation",
            current.link,
        )
        return self.save(
            "observation",
            id_,
            row.model_copy(update={"review_status": "UNDER_REVIEW"}),
            "submit-review",
            "Submitted a candidate for independent review",
            candidate.link,
        )

    def review_observation(
        self,
        id_: str,
        disposition: Disposition,
        rationale: str,
        authorship: Authorship,
        *,
        validation: Validation | None = None,
        finding_id: str | None = None,
    ) -> Version:
        self.require("REVIEWER")
        current = self.current("observation", id_)
        row = current.as_type(Observation)
        if row.review_status != "UNDER_REVIEW":
            raise Invalid("The observation must be under review")
        review = self.decision(rationale, authorship, independent_of=row.author_ref)
        if disposition == "CONFIRMED":
            if validation is None or not finding_id:
                raise Invalid("Confirmation requires structured validation and a finding ID")
            validation = self._validate_finding(row, validation)
        elif validation or finding_id:
            raise Invalid("Only confirmation creates a finding")
        reviewed = self.save(
            "observation",
            id_,
            row.model_copy(
                update={
                    "review_status": "DISPOSITIONED",
                    "disposition": disposition,
                    "review": review,
                }
            ),
            "observation-review",
            rationale,
            current.link,
        )
        if disposition != "CONFIRMED":
            return reviewed
        assert validation is not None and finding_id is not None
        return self.save(
            "finding",
            finding_id,
            Finding(
                observation=reviewed.link,
                title=row.title,
                executive_summary=row.description,
                author_ref=row.author_ref,
                validation=validation,
                validation_status="CONFIRMED",
                review_history=[review],
            ),
            "finding-confirm",
            rationale,
        )

    def _validate_finding(self, observation: Observation, validation: Validation) -> Validation:
        included = {
            a.ref for a in self.engagement.assets if a.included and a.scope_ref == observation.scope_ref
        }
        if (
            not set(observation.asset_refs) <= included
            or observation.scope_ref != self.engagement.assessment_scope_ref
        ):
            raise Invalid("Observation is outside the recorded engagement scope")
        if observation.epistemic_status != "OBSERVED" or observation.evidence_quality in {
            "UNKNOWN",
            "INSUFFICIENT",
        }:
            raise Invalid("Confirmation requires sufficient observed evidence")
        if self.engagement.p003_policy_digest and not self.policy_matches():
            raise Invalid("P-003 policy or scope reference is missing or incompatible")
        if not set(item.sha256 for item in validation.inspected_evidence) <= {
            item.sha256 for item in observation.evidence_refs
        }:
            raise Invalid("Inspected evidence must come from the observation")
        if any(
            is_placeholder(text)
            for text in (
                observation.observed_behavior,
                observation.expected_behavior,
                validation.security_impact,
                validation.business_impact,
                validation.false_positive_analysis,
                *validation.reproduction_steps,
            )
        ):
            raise Invalid("Finding validation contains unresolved placeholders")
        versions = [self.resolve(ref) for ref in validation.inspected_evidence]
        if not any(self._failure_basis(v.as_type(Evidence), observation) for v in versions):
            raise Invalid("Confirmation requires inspected direct evidence of the defined behavior")
        inspected = []
        for version in versions:
            evidence = version.as_type(Evidence)
            current = self.current("evidence", version.link.id)
            if current.link != version.link:
                # Evidence inspection is the only allowed change to this record type.
                if current.as_type(Evidence).source != evidence.source:
                    raise Invalid("Evidence changed since submission")
                version = current
                evidence = current.as_type(Evidence)
            if evidence.human_review_status == "PENDING":
                version = self.save(
                    "evidence",
                    version.link.id,
                    evidence.model_copy(
                        update={
                            "human_review_status": "INSPECTED",
                            "evidence_quality": observation.evidence_quality,
                        }
                    ),
                    "evidence-inspected",
                    "Reviewer inspected the evidence while validating the finding",
                    version.link,
                )
            inspected.append(version.link)
        return validation.model_copy(update={"inspected_evidence": inspected})

    def _failure_basis(self, evidence: Evidence, observation: Observation) -> bool:
        if evidence.integrity_status != "VERIFIED_BYTES":
            return False
        source = self.resolve(evidence.source).as_type(SourceRecord)
        if not source.source_time or not (
            timestamp(self.engagement.assessment_window.start)
            <= timestamp(source.source_time)
            < timestamp(self.engagement.assessment_window.end)
        ):
            return False
        if evidence.basis == "REPRODUCTION_RECORD":
            return (
                source.payload["asset_ref"] in observation.asset_refs
                and source.payload["status"] == "FAIL"
                and source.payload["expected"] == observation.expected_behavior
                and source.payload["observed"] == observation.observed_behavior
                and source.payload["expected"] != source.payload["observed"]
            )
        if evidence.basis == "SOURCE_TEST" and source.payload.get("target_ref") in observation.asset_refs:
            return any(
                row["test_id"] == evidence.source_record_id
                and row["status"] == "FAIL"
                and row["runner"]["executed"]
                for row in source.payload["results"]
            )
        return False

    def severity(self, id_: str, data: SeverityInput, rationale: str, authorship: Authorship) -> Version:
        self.require("REVIEWER")
        current = self.current("finding", id_)
        finding = current.as_type(Finding)
        if finding.validation_status != "CONFIRMED" or finding.lifecycle == "CLOSED":
            raise Invalid("Severity requires an active confirmed finding")
        observation = self.resolve(finding.observation).as_type(Observation)
        suggestion = suggest(data, observation.evidence_quality)
        if suggestion == "UNRATED" and data.severity != "UNRATED":
            raise Invalid("Unknown dimensions or insufficient evidence require UNRATED")
        decision = self.decision(rationale, authorship, independent_of=finding.author_ref)
        selection = SeverityDecision(
            **data.model_dump(),
            rubric_sha256=rubric()["sha256"],
            suggested_severity=suggestion,
            decision=decision,
        )
        return self.save(
            "finding",
            id_,
            finding.model_copy(update={"severity": selection}),
            "severity-decision",
            rationale,
            current.link,
        )

    def withdraw(self, id_: str, rationale: str, authorship: Authorship) -> Version:
        self.require("REVIEWER")
        current = self.current("finding", id_)
        finding = current.as_type(Finding)
        review = self.decision(rationale, authorship, independent_of=finding.author_ref)
        if finding.validation_status != "CONFIRMED":
            raise Invalid("Finding is already withdrawn")
        return self.save(
            "finding",
            id_,
            finding.model_copy(
                update={
                    "validation_status": "WITHDRAWN",
                    "review_history": [*finding.review_history, review],
                }
            ),
            "finding-withdraw",
            rationale,
            current.link,
        )

    def risk(self, id_: str, data: RiskInput, rationale: str, authorship: Authorship) -> Version:
        self.require("REVIEWER")
        decision = self.decision(rationale, authorship)
        catalog = self.resolve(data.catalog_source).as_type(SourceRecord)
        if catalog.contract != "p005-risk-1.0":
            raise Invalid("Risk references must resolve in the source taxonomy")
        source = next((row for row in catalog.payload["entries"] if row["id"] == data.source_risk_id), None)
        if source is None:
            raise Invalid("Unknown source risk ID")
        if not source["available"] and data.applicability not in {"UNKNOWN", "NEEDS_INFORMATION"}:
            raise Invalid("Unresolved source risk definition requires UNKNOWN or NEEDS_INFORMATION")
        if data.applicability in {"APPLICABLE", "NOT_APPLICABLE"} and not data.basis_refs:
            raise Invalid("Applicability requires explicit supporting context")
        if set(data.affected_assets) - {asset.ref for asset in self.engagement.assets}:
            raise Invalid("Unknown risk asset")
        if not any(a.ref == data.risk_owner_ref and a.role == "RISK_OWNER" for a in self.engagement.actors):
            raise Invalid("The risk owner must be registered")
        for link in data.threat_refs:
            if self.resolve(link).as_type(SourceRecord).contract != "p005-threat-1.0":
                raise Invalid("Risk threat reference does not resolve to a hypothesis export")
        for link in data.finding_refs:
            if self.resolve(link).as_type(Finding).validation_status != "CONFIRMED":
                raise Invalid("Risk finding reference is not confirmed")
        for link in data.basis_refs:
            self.resolve(link)
        previous = self.store.latest("risk", id_, required=False)
        if previous and self.current("risk", id_).as_type(Risk).source_risk_id != data.source_risk_id:
            raise Invalid("Create a new risk register ID for a different source risk")
        value = Risk(
            **data.model_dump(),
            source_risk_definition=source["description"] if source["available"] else None,
            source_risk_provenance=source["source"],
            applicability_rationale=rationale,
            review=decision,
        )
        return self.save("risk", id_, value, "risk-review", rationale, previous.link if previous else None)

    def remediation(
        self, id_: str, finding_id: str, data: RemediationInput, rationale: str, authorship: Authorship
    ) -> Version:
        self.require("AUTHOR")
        current = self.current("finding", finding_id)
        finding = current.as_type(Finding)
        if finding.validation_status != "CONFIRMED" or finding.lifecycle != "OPEN":
            raise Invalid("Remediation planning requires an open confirmed finding")
        if data.affected_control not in {
            *finding.validation.control_ids,
            *finding.validation.requirement_ids,
        }:
            raise Invalid("Remediation must address a recorded control or requirement")
        if not any(a.ref == data.owner_ref and a.role == "REMEDIATION_OWNER" for a in self.engagement.actors):
            raise Invalid("The remediation owner must be registered")
        try:
            date.fromisoformat(data.target_date)
        except ValueError:
            raise Invalid("Invalid remediation target date") from None
        decision = self.decision(rationale, authorship)
        action = Remediation(**data.model_dump(), finding=current.link, recommendation_provenance=decision)
        version = self.save("remediation", id_, action, "remediation-plan", rationale)
        if finding.remediation_status == "UNPLANNED":
            self.save(
                "finding",
                finding_id,
                finding.model_copy(update={"remediation_status": "REMEDIATION_PLANNED"}),
                "finding-remediation-plan",
                rationale,
                current.link,
            )
        return version

    def implemented(self, id_: str, rationale: str, authorship: Authorship) -> Version:
        self.require("REMEDIATION_OWNER")
        action = self.current("remediation", id_)
        remediation = action.as_type(Remediation)
        if remediation.owner_ref != self.actor.ref or remediation.implementation:
            raise Invalid("Only the named owner can report an outstanding implementation")
        decision = self.decision(rationale, authorship)
        current = self.current("finding", remediation.finding.id)
        finding = current.as_type(Finding)
        if finding.validation_status != "CONFIRMED" or finding.lifecycle != "OPEN":
            raise Invalid("Finding is no longer open")
        version = self.save(
            "remediation",
            id_,
            remediation.model_copy(update={"implementation": decision}),
            "remediation-reported",
            rationale,
            action.link,
        )
        self.save(
            "finding",
            current.link.id,
            finding.model_copy(
                update={
                    "remediation_status": "REMEDIATION_REPORTED",
                    "retest_status": "PENDING_RETEST",
                }
            ),
            "finding-pending-retest",
            rationale,
            current.link,
        )
        return version

    def _test(self, test: TestRef) -> tuple[SourceRecord, dict]:
        source = self.resolve(test.source).as_type(SourceRecord)
        if source.contract == "p010-reproduction-record-1.0" and source.source_record_id == test.test_id:
            return source, {
                "status": source.payload["status"],
                "compatibility_hash": source.payload["configuration_ref"],
            }
        if source.contract == "p007-handoff-v1":
            for row in source.payload["results"]:
                if row["test_id"] == test.test_id:
                    return source, row
        raise Invalid("Retest reference does not resolve to a source test result")

    def retest_plan(
        self, id_: str, finding_id: str, data: RetestPlanInput, rationale: str, authorship: Authorship
    ) -> Version:
        self.require("AUTHOR", "REVIEWER")
        current = self.current("finding", finding_id)
        finding = current.as_type(Finding)
        action = self.resolve(data.remediation).as_type(Remediation)
        if (
            action.finding.id != finding_id
            or finding.validation_status != "CONFIRMED"
            or finding.lifecycle != "OPEN"
        ):
            raise Invalid("Retest planning requires a remediation action for an open confirmed finding")
        inspected = {
            (
                self.resolve(ref).as_type(Evidence).source.sha256,
                self.resolve(ref).as_type(Evidence).source_record_id,
            )
            for ref in finding.validation.inspected_evidence
        }
        for test in data.original_tests:
            self._test(test)
            if (test.source.sha256, test.test_id) not in inspected:
                raise Invalid("Planned retest must reference an inspected original test")
        decision = self.decision(rationale, authorship)
        return self.save(
            "retest-plan",
            id_,
            RetestPlan(
                **data.model_dump(),
                finding=current.link,
                plan_provenance=decision,
            ),
            "retest-plan",
            rationale,
        )

    def retest(
        self, id_: str, finding_id: str, data: RetestInput, rationale: str, authorship: Authorship
    ) -> Version:
        self.require("REVIEWER")
        current = self.current("finding", finding_id)
        finding = current.as_type(Finding)
        action = self.resolve(data.remediation).as_type(Remediation)
        if (
            action.finding.id != finding_id
            or finding.validation_status != "CONFIRMED"
            or finding.lifecycle != "OPEN"
        ):
            raise Invalid("Retest must link remediation to an open confirmed finding")
        if data.plan_ref:
            plan = self.resolve(data.plan_ref).as_type(RetestPlan)
            if (
                plan.finding.id != finding_id
                or plan.remediation.id != data.remediation.id
                or plan.original_tests != data.original_tests
            ):
                raise Invalid("Retest differs from its selected plan")
        decision = self.decision(rationale, authorship, independent_of=finding.author_ref)
        original = [self._test(ref) for ref in data.original_tests]
        new = [self._test(ref) for ref in data.new_tests]
        regression = [self._test(ref) for ref in data.regression_tests]
        observed = {
            (item.source.sha256, item.source_record_id)
            for item in (self.resolve(ref).as_type(Evidence) for ref in finding.validation.inspected_evidence)
        }
        if any((ref.source.sha256, ref.test_id) not in observed for ref in data.original_tests) or not any(
            row["status"] == "FAIL" for _, row in original
        ):
            raise Invalid("Original tests must reference the inspected finding evidence")
        if {test.source.id for test in data.original_tests} & {
            test.source.id for test in [*data.new_tests, *data.regression_tests]
        }:
            raise Invalid("Retest and regression checks require a distinct source run")
        attached = [self.resolve(ref).as_type(Evidence) for ref in data.evidence_refs]
        statuses: list[Status] = [row["status"] for _, row in new]
        regression_statuses: list[Status] = [row["status"] for _, row in regression]
        compatible = len(original) == len(new) and all(
            a.contract == b.contract and first["compatibility_hash"] == second["compatibility_hash"]
            for (a, first), (b, second) in zip(original, new, strict=True)
        )
        result: Status | Literal["NOT_COMPARABLE"]
        if not data.comparable or not compatible:
            result = "NOT_COMPARABLE"
        elif len(set(statuses)) == 1:
            result = statuses[0]
        else:
            result = "INCONCLUSIVE"
        inspected = {
            (item.source.sha256, item.source_record_id)
            for item in attached
            if item.integrity_status == "VERIFIED_BYTES"
        }
        substantiated = (
            action.implementation is not None
            and bool(regression)
            and all(s == "PASS" for s in regression_statuses)
            and all(
                (ref.source.sha256, ref.test_id) in inspected
                for ref in [*data.new_tests, *data.regression_tests]
            )
        )
        state = (
            "RETEST_PASSED"
            if result == "PASS" and substantiated
            else "RETEST_FAILED"
            if result == "FAIL"
            else "PENDING_RETEST"
            if result in {"PASS", "NOT_TESTED", "BLOCKED"}
            else "INCONCLUSIVE"
        )
        version = self.save(
            "retest",
            id_,
            Retest(
                **data.model_dump(),
                finding=current.link,
                source_results=statuses,
                regression_results=regression_statuses,
                result_status=result,
                review=decision,
            ),
            "retest-review",
            rationale,
        )
        self.save(
            "finding",
            finding_id,
            finding.model_copy(update={"retest_status": state}),
            "finding-retest-state",
            rationale,
            current.link,
        )
        return version

    def accept(self, id_: str, data: AcceptanceInput, rationale: str, authorship: Authorship) -> Version:
        self.require("RISK_OWNER")
        risk_version = self.resolve(data.risk)
        risk = risk_version.as_type(Risk)
        if self.current("risk", data.risk.id).link != data.risk or risk.risk_owner_ref != self.actor.ref:
            raise Invalid("Only the accountable owner of the current risk can record a decision")
        if set(data.scope_refs) - set(risk.affected_assets):
            raise Invalid("Risk acceptance scope exceeds the reviewed risk assets")
        if timestamp(data.review_by) <= timestamp(self.at):
            raise Invalid("Risk acceptance must have a future review or expiry time")
        if data.decision == "ACCEPTED" and (risk.treatment != "ACCEPT" or risk.residual_risk == "UNRATED"):
            raise Invalid("Acceptance requires explicit treatment and rated residual risk")
        decision = self.decision(rationale, authorship)
        version = self.save(
            "acceptance",
            id_,
            Acceptance(**data.model_dump(), owner_decision=decision),
            "risk-owner-decision",
            rationale,
        )
        for link in risk.finding_refs:
            current = self.current("finding", link.id)
            finding = current.as_type(Finding)
            if finding.validation_status != "CONFIRMED" or finding.lifecycle == "CLOSED":
                continue
            lifecycle = "RESIDUAL_RISK_ACCEPTED" if self._residual_accepted(current) else "OPEN"
            if lifecycle != finding.lifecycle:
                self.save(
                    "finding",
                    link.id,
                    finding.model_copy(update={"lifecycle": lifecycle}),
                    "finding-residual-risk",
                    rationale,
                    current.link,
                )
        return version

    def _residual_accepted(self, current: Version) -> bool:
        finding = current.as_type(Finding)
        assets = set(self.resolve(finding.observation).as_type(Observation).asset_refs)
        records = self.store.versions(self.id, current=True)
        risks = {
            row.link: row.data
            for row in records
            if isinstance(row.data, Risk)
            and any(link.id == current.link.id for link in row.data.finding_refs)
        }
        decisions = effective_acceptances([row.data for row in records if isinstance(row.data, Acceptance)])
        accepted: dict[Link, set[str]] = {}
        for item in decisions:
            if item.risk not in risks or item.owner_decision.actor.ref != risks[item.risk].risk_owner_ref:
                continue
            if item.decision == "ACCEPTED" and timestamp(item.review_by) > timestamp(self.at):
                accepted.setdefault(item.risk, set()).update(item.scope_refs)
        return bool(risks) and all(assets <= accepted.get(ref, set()) for ref in risks)

    def close(self, finding_id: str, rationale: str, authorship: Authorship) -> Version:
        self.require("REVIEWER")
        current = self.current("finding", finding_id)
        finding = current.as_type(Finding)
        self.decision(rationale, authorship, independent_of=finding.author_ref)
        if (
            finding.validation_status != "CONFIRMED"
            or finding.lifecycle == "CLOSED"
            or finding.retest_status != "RETEST_PASSED"
        ):
            raise Invalid(
                "Closure requires a confirmed finding and comparable evidence-backed retest and regressions"
            )
        if not self._residual_accepted(current):
            raise Invalid("Closure requires current owner decisions on linked residual risk")
        return self.save(
            "finding",
            finding_id,
            finding.model_copy(update={"lifecycle": "CLOSED"}),
            "finding-closed",
            rationale,
            current.link,
        )
