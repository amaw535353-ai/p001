"""Deterministic training exercise with declared simulated actors and static evidence."""

from pathlib import Path
from typing import Final

from p010 import langfuse, oscal, redmine, reports, retention
from p010.models import (
    AcceptanceInput,
    Actor,
    Asset,
    Engagement,
    Evidence,
    Finding,
    ObservationDraft,
    RemediationInput,
    Report,
    ReportNarrative,
    RetestInput,
    RetestPlanInput,
    RiskInput,
    SeverityInput,
    SourceRecord,
    TestRef,
    Validation,
    Window,
)
from p010.safety import REPO, ROOT, Invalid
from p010.sources import import_file
from p010.store import Version, Workspace
from p010.workflow import Workflow, register_engagement

ENGAGEMENT = "ENG-DEMO-A"
AUTHOR = "demo-author"
REVIEWER = "demo-reviewer"
RISK_OWNER = "demo-risk-owner"
CUSTODIAN = "demo-custodian"
OWNER = "demo-system-owner"
AT = "2026-11-18T12:00:00Z"
SIMULATED: Final = "TRAINING_FIXTURE"
FINDING = "FIND-DEMO-001"
REPORT = "REPORT-DEMO-001"

EXERCISE_SOURCES = (
    ("p003", "p-003/examples/engagement-draft-a.json", None),
    ("p004", "p-004/fixtures/static/architecture.json", None),
    ("p005", "p-005/examples/reference-architecture/model.json", None),
    ("p005", "p-005/examples/reference-architecture/threat-register.json", "threats"),
    ("p005", "p-005/examples/reference-architecture/verification-plan.json", "verification"),
    ("p005", "p-005/examples/reference-architecture/sample-manifest.json", None),
    ("p005", "p-005/src/p005/data/risks.json", None),
    ("p006", "p-006/config/hardened.json", None),
    ("p006", "p-006/contracts/architecture/service-inventory.json", None),
    ("p006", "p-006/contracts/architecture/risk-applicability.json", None),
    ("p007", "p-007/examples/report-export.example.json", None),
)


def registration(policy: SourceRecord) -> Engagement:
    snapshot = policy.payload
    scope_id = snapshot["scope"]["id"]
    return Engagement(
        title="Fictional Aster Research · AI security assessment exercise",
        client_ref="CLIENT-DEMO-A",
        status="SYNTHETIC_EXERCISE",
        assessment_scope_ref=scope_id,
        p003_policy_digest=snapshot["policy_digest"],
        assessment_window=Window(**snapshot["window"]),
        assets=[
            Asset(
                ref=item["asset_id"],
                component=item["service"],
                environment=item["environment"],
                scope_ref=scope_id,
                included=item["included"],
            )
            for item in snapshot["assets"]
        ],
        exclusions=[entry["reason"] for entry in snapshot["scope"]["exclusions"]],
        assessment_objectives=["Practice evidence-linked review of synthetic diagnostic metadata."],
        methodology_version="p010-consultancy-method-1.0",
        actors=[
            Actor(ref=AUTHOR, role="AUTHOR"),
            Actor(ref=REVIEWER, role="REVIEWER"),
            Actor(ref=OWNER, role="REMEDIATION_OWNER"),
            Actor(ref=RISK_OWNER, role="RISK_OWNER"),
            Actor(ref=CUSTODIAN, role="CUSTODIAN"),
        ],
        limitations=[
            "Production, provider and cloud assessment coverage is NOT_TESTED.",
            "Source architecture, threat fixtures and control-regression exports have their own scope and provenance.",
            "All decisions in this exercise are simulated.",
        ],
    )


def _observation(author: Workflow, evidence: Version, source: SourceRecord) -> Version:
    return author.observation(
        "OBS-DEMO-001",
        ObservationDraft(
            title="Synthetic diagnostic metadata classification gap",
            description="A static fictional diagnostic row lacks the required classification label.",
            asset_refs=["demo-a-health"],
            scope_ref=author.engagement.assessment_scope_ref,
            evidence_refs=[evidence.link],
            expected_behavior=source.payload["expected"],
            observed_behavior=source.payload["observed"],
            attacker_preconditions=["The fictional workflow accepts a row from the diagnostic inventory."],
            reproduction_conditions="Compare the inert synthetic row and its policy field.",
            evidence_quality="LIMITED",
            epistemic_status="OBSERVED",
            alternative_explanations=[
                "The source fixture could represent an incomplete export instead of the storing system."
            ],
            limitations=["The exercise uses a static synthetic record."],
            authorship=SIMULATED,
        ),
    )


def _risk(catalog: Version, finding: Version) -> RiskInput:
    return RiskInput(
        source_risk_id="R4",
        catalog_source=catalog.link,
        description="Unlabelled metadata can bypass downstream handling decisions in the synthetic workflow.",
        affected_assets=["demo-a-health"],
        applicability="APPLICABLE",
        finding_refs=[finding.link],
        control_refs=["DEMO-C-CLASSIFICATION"],
        basis_refs=[finding.link],
        inherent_risk="MEDIUM",
        current_control_state="A static fixture exhibited one missing metadata label.",
        residual_risk="LOW",
        treatment="ACCEPT",
        treatment_plan="Accept limited fixture residual exposure until scheduled review.",
        risk_owner_ref=RISK_OWNER,
    )


def narrative() -> ReportNarrative:
    return ReportNarrative(
        executive_summary="The simulated reviewer recorded one diagnostic metadata classification gap for the fictional local asset.",
        methodology="Imported versioned context, inspected a static reproduction record and reviewed the alternate fixture outcome.",
        architecture_context="The exercise uses an inert marker service, with supplemental P-004 through P-006 declared context.",
        management_response="The fictional owner plans to require a classification label on diagnostic metadata.",
        follow_up="Obtain implementation evidence and reevaluate under the same conditions at the owner review date.",
        limitations=[
            "The simulated reviewer and risk owner have no independent human or real-client provenance."
        ],
        authorship=SIMULATED,
    )


def run(
    workspace: Workspace, *, p008: Path | None = None, p009: Path | None = None, events: Path | None = None
) -> dict:
    if events and p009 is None:
        raise Invalid("Select the P-009 handoff alongside its event export")
    if workspace.path.exists():
        raise Invalid("Select a fresh workspace for this exercise")
    workspace.init()
    policy = import_file("p003", REPO / "p-003/examples/synthetic-approved-policy.json", imported_at=AT)
    with workspace.session() as store:
        register_engagement(store, ENGAGEMENT, registration(policy), AUTHOR, at=AT)
        author = Workflow(store, ENGAGEMENT, AUTHOR, at=AT)
        reviewer = Workflow(store, ENGAGEMENT, REVIEWER, at=AT)
        owner = Workflow(store, ENGAGEMENT, RISK_OWNER, at=AT)
        author.import_source(policy)
        prior = {}
        for project, path, flavor in EXERCISE_SOURCES:
            source = import_file(project, REPO / path, flavor=flavor, imported_at=AT)
            prior[source.contract] = author.import_source(source)
        p008_import = None
        if p008:
            p008_import = author.import_source(import_file("p008", p008, imported_at=AT))
        p009_import = author.import_source(
            import_file(
                "p009",
                p009 or REPO / "p-009/contracts/examples/p009-handoff.json",
                events=events,
                imported_at=AT,
            )
        )
        traces = p009_import.as_type(SourceRecord).payload["event_references"]
        event = next((row for row in traces if row.get("trace_id")), None)
        if event:
            author.make_evidence("EVID-P009-TRACE", p009_import.link, event["event_id"], None)
        p007 = prior["p007-handoff-v1"].as_type(SourceRecord)
        example_fail = next(row["test_id"] for row in p007.payload["results"] if row["status"] == "FAIL")
        if any(row.link.kind == "finding" for row in store.versions(ENGAGEMENT, current=True)):
            raise Invalid("Unexpected finding created during source intake")
        evidence_ref = author.make_evidence(
            "EVID-P007-REF", prior["p007-handoff-v1"].link, example_fail, example_fail + ".json"
        )
        if evidence_ref.as_type(Evidence).integrity_status != "REFERENCE_ONLY":
            raise Invalid("Unexpected source example artifact state")

        before = import_file("reproduction", ROOT / "fixtures/reproduction-before.json", imported_at=AT)
        after = import_file("reproduction", ROOT / "fixtures/reproduction-after.json", imported_at=AT)
        b, a = author.import_source(before), author.import_source(after)
        original = author.make_evidence(
            "EVID-METADATA-BEFORE",
            b.link,
            before.source_record_id,
            None,
            excerpt="Approved fixture excerpt. Diagnostic sample P010_SECRET_EXERCISE and pii-canary@example.invalid were removed.",
        )
        newer = author.make_evidence("EVID-METADATA-AFTER", a.link, after.source_record_id, None)
        _observation(author, original, before)
        author.submit("OBS-DEMO-001")
        reviewer.review_observation(
            "OBS-DEMO-001",
            "CONFIRMED",
            "Simulated reviewer checked the static row against its required label.",
            SIMULATED,
            finding_id=FINDING,
            validation=Validation(
                requirement_ids=["DEMO-REQ-CLASSIFICATION"],
                control_ids=["DEMO-C-CLASSIFICATION"],
                attacker_capability="A fictional metadata producer can submit rows to the described workflow.",
                reproduction_steps=before.payload["steps"],
                security_impact="A downstream workflow may misclassify an unlabelled diagnostic row.",
                business_impact="The training workflow would require manual classification review.",
                data_impact="One inert diagnostic metadata row.",
                availability_impact="Availability effects are untested.",
                false_positive_analysis="The paired static fixture confirms the field is present only in the alternate record.",
                limitations=[
                    "Limited to the supplied synthetic fixture, without a live application assessment."
                ],
                inspected_evidence=[original.link],
            ),
        )
        early = reports.build(
            author, REPORT, narrative(), "Prepared initial report before severity adjudication."
        )
        try:
            reports.review(
                reviewer,
                REPORT,
                "Attempted approval before review and complete content.",
                SIMULATED,
                approve=True,
                expected=early.link,
            )
        except Invalid:
            rejected = True
        else:
            raise Invalid("Incomplete draft unexpectedly approved")
        reviewer.severity(
            FINDING,
            SeverityInput(
                severity="LOW",
                impact="LIMITED",
                exploitability="CONDITIONAL",
                exposure="Local synthetic diagnostic workflow with recorded access conditions.",
                likelihood_rationale="One static sample establishes a possible case within the fixture.",
                exploitability_rationale="Dependence on the local diagnostic input limits exposure.",
                business_context="Fictional manual review overhead.",
                compensating_controls=["Manual review"],
                uncertainty="Program behavior and real data impact are unverified.",
                confidence="MEDIUM",
            ),
            "Simulated reviewer accepted the local rubric suggestion within the fixture scope.",
            SIMULATED,
        )
        remediated = author.remediation(
            "REM-DEMO-001",
            FINDING,
            RemediationInput(
                recommendation="Require a classification field and reject rows missing that field.",
                affected_control="DEMO-C-CLASSIFICATION",
                owner_ref=OWNER,
                target_date="2026-12-01",
                dependencies=["Approved diagnostic schema change"],
                verification_criteria="Compare the same fixture field after change.",
                compensating_controls=["Manual review queue"],
            ),
            "Linked recommendation to the observed classification requirement.",
            SIMULATED,
        )
        original_tests = [TestRef(source=b.link, test_id=before.source_record_id)]
        plan = author.retest_plan(
            "RET-PLAN-DEMO-001",
            FINDING,
            RetestPlanInput(
                remediation=remediated.link,
                original_tests=original_tests,
                planned_checks=["Read the classification field from the alternate synthetic row."],
                comparability_criteria="Use the same fixture record shape and classification rule.",
                expected_behavior=after.payload["expected"],
            ),
            "Documented the retest review criteria.",
            SIMULATED,
        )
        reviewer.retest(
            "RET-DEMO-001",
            FINDING,
            RetestInput(
                remediation=remediated.link,
                plan_ref=plan.link,
                original_tests=original_tests,
                new_tests=[TestRef(source=a.link, test_id=after.source_record_id)],
                comparable=True,
                configuration_comparison="Same record shape and classification rule.",
                source_version_comparison="Both are p010-reproduction-record-1.0 fixture snapshots.",
                expected_behavior=after.payload["expected"],
                observed_behavior=after.payload["observed"],
                evidence_refs=[newer.link],
                limitations=["Owner implementation and additional regressions are NOT_TESTED."],
            ),
            "Simulated retest reviewer compared the separate static records.",
            SIMULATED,
        )
        finding = reviewer.current("finding", FINDING)
        risk = reviewer.risk(
            "RISK-DEMO-001",
            _risk(prior["p005-risk-1.0"], finding),
            "Source R4 applies to synthetic metadata handling in this exercise.",
            SIMULATED,
        )
        owner.accept(
            "ACCEPT-DEMO-001",
            AcceptanceInput(
                risk=risk.link,
                scope_refs=["demo-a-health"],
                decision="ACCEPTED",
                constraints=["Fictional asset and labelled records only."],
                review_by="2027-01-15T12:00:00Z",
                source_reference="Simulated P-010 risk-owner exercise",
            ),
            "Training role records limited residual review scope and a follow-up date.",
            SIMULATED,
        )

        ready = reports.build(
            author, REPORT, narrative(), "Assembled the revised consultancy package for review."
        )
        reviewed = reports.review(
            reviewer,
            REPORT,
            "Training role verified traceability and unresolved gates.",
            SIMULATED,
            approve=False,
            expected=ready.link,
        )
        target = reports.export(author, reviewed, workspace.root)
        package = reports.verify(author, reviewed, target)
        export = reports.handoff(author, reviewed).model_dump(mode="json")
        all_bytes = b"".join(reports.files(author, reviewed).values())
        if (
            b"P010_SECRET_EXERCISE" in all_bytes
            or b"pii-canary@example.invalid" in all_bytes
            or b"[REDACTED]" not in all_bytes
        ):
            raise Invalid("Privacy canary check failed")
        draft = oscal.export(author, reviewed, None)
        decision = reviewed.as_type(Report)
        trace_status = "NOT_TESTED"
        if event:
            ref = langfuse.from_event(author, p009_import.link.id, event["event_id"], "demo-project")
            trace_status = langfuse.show(ref)["status"]
        final = reviewer.current("finding", FINDING).as_type(Finding)
        return {
            "mode": SIMULATED,
            "workspace": workspace.root.name,
            "engagement": ENGAGEMENT,
            "finding": FINDING,
            "p007_result_without_finding": example_fail,
            "p007_fail_preserved": True,
            "p005_hypotheses": len(prior["p005-threat-1.0"].as_type(SourceRecord).payload["threats"]),
            "p008": p008_import.as_type(SourceRecord).payload["summary"]["omission_policy"]
            if p008_import
            else "NOT_TESTED",
            "p009_source_events": len(traces),
            "langfuse": trace_status,
            "oscal": draft["conformance"],
            "atlas": "No technique demonstrated by this static diagnostic metadata example",
            "draft_approval_rejected": rejected,
            "report_status": decision.status,
            "package": str(target),
            "manifest_sha256": package["files"]["manifest.json"],
            "report_sha256": package["files"]["report.json"],
            "finding_state": final.lifecycle,
            "retest_state": final.retest_status,
            "future_handoff": export["schema_version"],
            "canaries_removed": True,
            "report_gate_count": len(decision.gates),
            "redmine": redmine.preview(author, FINDING)["status"],
            "audit_verification": store.verify(),
            "retention_eligible": retention.plan(Workflow(store, ENGAGEMENT, CUSTODIAN, at=AT))["eligible"],
        }
