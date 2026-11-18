"""Decision, evidence, audit and report workflow acceptance cases."""

from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import ValidationError

from p010 import langfuse, reports, retention
from p010.demo import AT, AUTHOR, CUSTODIAN, ENGAGEMENT, FINDING, REPORT, REVIEWER, RISK_OWNER
from p010.demo import _risk, narrative, registration
from p010.models import (
    AcceptanceInput,
    Engagement,
    Evidence,
    Finding,
    Link,
    Observation,
    ObservationDraft,
    Report,
    RiskInput,
    SeverityInput,
    SourceRecord,
    TraceReference,
    Validation,
)
from p010.safety import REPO, ROOT, Invalid, canonical, digest
from p010.sources import import_file
from p010.store import Version, Workspace, validate
from p010.workflow import Workflow, register_engagement, rubric, suggest

REASON = "Reviewed the exact synthetic requirement and static source record."
FIXTURE = "TRAINING_FIXTURE"


@dataclass
class Sample:
    workspace: Workspace
    evidence: Version
    observation: ObservationDraft
    validation: Validation


@pytest.fixture
def case(tmp_path: Path) -> Sample:
    workspace = Workspace(tmp_path / "workflow")
    workspace.init()
    policy = import_file("p003", REPO / "p-003/examples/synthetic-approved-policy.json", imported_at=AT)
    source = import_file("reproduction", ROOT / "fixtures/reproduction-before.json", imported_at=AT)
    with workspace.session() as store:
        register_engagement(store, ENGAGEMENT, registration(policy), AUTHOR, at=AT)
        author = Workflow(store, ENGAGEMENT, AUTHOR, at=AT)
        author.import_source(policy)
        imported = author.import_source(source)
        item = author.make_evidence(
            "EVID-001",
            imported.link,
            source.source_record_id,
            None,
            excerpt="Static fixture P010_SECRET_HERE and report-person@example.invalid",
        )
        draft = ObservationDraft(
            title="Synthetic metadata validation gap",
            description="Reviewed static metadata record.",
            asset_refs=["demo-a-health"],
            scope_ref=author.engagement.assessment_scope_ref,
            evidence_refs=[item.link],
            expected_behavior=source.payload["expected"],
            observed_behavior=source.payload["observed"],
            attacker_preconditions=["The fictional workflow accepts a record."],
            reproduction_conditions="Review the static fixture.",
            evidence_quality="LIMITED",
            epistemic_status="OBSERVED",
            alternative_explanations=["The export may omit the original field."],
            limitations=["The static fixture does not show runtime enforcement."],
            authorship="HUMAN_AUTHORED",
        )
        detail = Validation(
            requirement_ids=["DEMO-REQ"],
            control_ids=["DEMO-C-CLASSIFICATION"],
            attacker_capability="A fictional producer may submit metadata.",
            reproduction_steps=source.payload["steps"],
            security_impact="Classification is incomplete.",
            business_impact="Additional review is needed.",
            data_impact="One fictional row.",
            availability_impact="Not assessed.",
            false_positive_analysis="The reviewed record contains one missing classification value.",
            limitations=["Only the static record was inspected."],
            inspected_evidence=[item.link],
        )
    return Sample(workspace, item, draft, detail)


def actors(store):
    return Workflow(store, ENGAGEMENT, AUTHOR, at=AT), Workflow(store, ENGAGEMENT, REVIEWER, at=AT)


def rating(**update) -> SeverityInput:
    return SeverityInput(
        **{
            "severity": "LOW",
            "impact": "LIMITED",
            "exploitability": "CONDITIONAL",
            "exposure": "Limited fictional source.",
            "likelihood_rationale": "One inspected record supports a conditional case.",
            "exploitability_rationale": "The state depends on local data shape.",
            "business_context": "Synthetic workflow only.",
            "compensating_controls": ["Manual handling"],
            "uncertainty": "Live enforcement is untested.",
            "confidence": "HIGH",
            **update,
        }
    )


def confirm(case: Sample, store, *, authorship="HUMAN_AUTHORED", id_="OBS-001", finding=FINDING) -> Version:
    author, reviewer = actors(store)
    author.observation(id_, case.observation)
    author.submit(id_)
    return reviewer.review_observation(
        id_, "CONFIRMED", REASON, authorship, validation=case.validation, finding_id=finding
    )


def test_B01_engagement_roundtrip(case):
    with case.workspace.session() as store:
        version = store.current("engagement", ENGAGEMENT)
        assert (
            version.as_type(Engagement).model_dump()
            == validate(Engagement, version.envelope.data).model_dump()
        )
        assert version.envelope.engagement_id == ENGAGEMENT


@pytest.mark.parametrize("field", ["legal_authority", "is_real_client", "source_signature_verified"])
def test_B02_strict_engagement_rejects_undeclared_claims(case, field):
    with case.workspace.session() as store:
        data = store.current("engagement", ENGAGEMENT).envelope.data
        with pytest.raises(Invalid):
            validate(Engagement, {**data, field: True})


@pytest.mark.parametrize(
    ("key", "value"), [("id", "../scope"), ("sha256", "0" * 63), ("kind", "report-approved"), ("version", 0)]
)
def test_B03_reference_types(case, key, value):
    with pytest.raises(ValidationError):
        Link.model_validate({**case.evidence.link.model_dump(), key: value})


@pytest.mark.parametrize(
    "invalid_stamp", ["2026-02-30T03:00:00Z", "2026-11-20T03:00:00", "2026-11-20T03:00:00+01:00"]
)
def test_B03_actual_utc_required(case, invalid_stamp):
    source = case.evidence.as_type(Evidence).model_dump()
    source["source_time"] = invalid_stamp
    with pytest.raises(Invalid):
        validate(Evidence, source)


def test_F01_candidate_and_inspected_evidence(case):
    with case.workspace.session() as store:
        author, reviewer = actors(store)
        draft = author.observation("OBS-001", case.observation)
        assert draft.as_type(Observation).review_status == "DRAFT"
        submitted = author.submit("OBS-001")
        assert submitted.as_type(Observation).review_status == "UNDER_REVIEW"
        assert store.get("observation", "OBS-001", 2).as_type(Observation).review_status == "CANDIDATE"
        verified = reviewer.review_observation(
            "OBS-001",
            "CONFIRMED",
            REASON,
            "HUMAN_AUTHORED",
            validation=case.validation,
            finding_id=FINDING,
        ).as_type(Finding)
        assert (
            store.resolve(verified.validation.inspected_evidence[0]).as_type(Evidence).human_review_status
            == "INSPECTED"
        )


def test_F02_D08_p007_fail_cannot_create_finding(case):
    with case.workspace.session() as store:
        author, _ = actors(store)
        source = author.import_source(import_file("p007", REPO / "p-007/examples/report-export.example.json"))
        fail = next(row for row in source.as_type(SourceRecord).payload["results"] if row["status"] == "FAIL")
        evidence = author.make_evidence("p007-ref", source.link, fail["test_id"], fail["test_id"] + ".json")
        authored = author.observation(
            "OBS-NEW", case.observation.model_copy(update={"evidence_refs": [evidence.link]})
        )
        assert authored.as_type(Observation).disposition is None
        assert store.latest("finding", FINDING, required=False) is None


@pytest.mark.parametrize("role", [AUTHOR, CUSTODIAN, RISK_OWNER])
def test_F03_role_gate(case, role):
    with case.workspace.session() as store:
        author, _ = actors(store)
        author.observation("OBS-001", case.observation)
        author.submit("OBS-001")
        unauthorized = Workflow(store, ENGAGEMENT, role, at=AT)
        with pytest.raises(Invalid, match="role"):
            unauthorized.review_observation(
                "OBS-001",
                "CONFIRMED",
                REASON,
                FIXTURE,
                validation=case.validation,
                finding_id=FINDING,
            )


@pytest.mark.parametrize("reason", [" ", "TBD"])
def test_F04_rationale_required(case, reason):
    with case.workspace.session() as store:
        author, reviewer = actors(store)
        author.observation("OBS-001", case.observation)
        author.submit("OBS-001")
        with pytest.raises(Invalid, match="rationale"):
            reviewer.review_observation(
                "OBS-001",
                "CONFIRMED",
                reason,
                FIXTURE,
                validation=case.validation,
                finding_id=FINDING,
            )


def test_F05_out_of_scope_cannot_confirm(case):
    with case.workspace.session() as store:
        author, reviewer = actors(store)
        author.observation("OBS-OUT", case.observation.model_copy(update={"scope_ref": "OTHER-SCOPE"}))
        author.submit("OBS-OUT")
        with pytest.raises(Invalid, match="outside"):
            reviewer.review_observation(
                "OBS-OUT",
                "CONFIRMED",
                REASON,
                FIXTURE,
                validation=case.validation,
                finding_id=FINDING,
            )


@pytest.mark.parametrize(
    "disposition",
    [
        pytest.param("FALSE_POSITIVE", id="F06"),
        pytest.param("INCONCLUSIVE", id="F07-inconclusive"),
        pytest.param("NOT_REPRODUCIBLE", id="F07-nonreproducible"),
        pytest.param("OUT_OF_SCOPE", id="F05-disposition"),
        "BLOCKED",
        "NOT_TESTED",
        "WITHDRAWN",
    ],
)
def test_negative_dispositions_are_distinct(case, disposition):
    with case.workspace.session() as store:
        author, reviewer = actors(store)
        author.observation("OBS-001", case.observation)
        author.submit("OBS-001")
        resolved = reviewer.review_observation("OBS-001", disposition, REASON, FIXTURE).as_type(Observation)
        assert resolved.disposition == disposition
        assert store.latest("finding", FINDING, required=False) is None


@pytest.mark.parametrize(
    "basis",
    [
        pytest.param("hypothesis", id="C10-F08"),
        pytest.param("trace", id="F09"),
        pytest.param("alert", id="F10"),
    ],
)
def test_reference_evidence_cannot_confirm(case, basis, tmp_path):
    if basis == "hypothesis":
        source = import_file(
            "p005", REPO / "p-005/examples/reference-architecture/threat-register.json", flavor="threats"
        )
        item_id = source.payload["threats"][0]["threat_id"]
    elif basis == "trace":
        reference = TraceReference(
            trace_id="1" * 32,
            observation_id="2" * 16,
            source_time="2026-11-15T10:00:00Z",
            project_ref="fixture",
            source="operator-provided",
        )
        source = langfuse.source_record("trace-fixture", reference, langfuse.show(reference), AT)
        item_id = source.source_record_id
    else:
        from test_sources import p009_event_files

        manifest, events = p009_event_files(
            tmp_path,
            event_type="alert",
            event_category="security",
            alert_id="fixture-alert",
            wazuh_rule_id="100001",
        )
        source = import_file("p009", manifest, events=events)
        item_id = source.payload["event_references"][0]["event_id"]
        assert source.payload["event_references"][0]["alert_id"] == "fixture-alert"
    with case.workspace.session() as store:
        author, reviewer = actors(store)
        version = author.import_source(source)
        evidence = author.make_evidence("EVID-NEW", version.link, item_id, None)
        assert evidence.as_type(Evidence).basis == "REFERENCE"
        if basis == "trace":
            assert evidence.as_type(Evidence).trace_ref == reference.trace_id
        author.observation(
            "OBS-THREAT", case.observation.model_copy(update={"evidence_refs": [evidence.link]})
        )
        author.submit("OBS-THREAT")
        with pytest.raises(Invalid, match="direct evidence"):
            reviewer.review_observation(
                "OBS-THREAT",
                "CONFIRMED",
                REASON,
                FIXTURE,
                finding_id=FINDING,
                validation=case.validation.model_copy(update={"inspected_evidence": [evidence.link]}),
            )


def test_F11_F12_R08_versioning_and_severity_override(case):
    with case.workspace.session() as store:
        first = confirm(case, store)
        _, reviewer = actors(store)
        rated = reviewer.severity(
            FINDING, rating(), "Assigned a low rating from the fixture.", "HUMAN_AUTHORED"
        )
        newer = reviewer.severity(
            FINDING, rating(severity="MEDIUM"), "Recorded a conservative reviewed override.", "AI_ASSISTED"
        )
        assert store.resolve(first.link).as_type(Finding).severity is None
        assert store.resolve(rated.link).as_type(Finding).severity.severity == "LOW"
        decision = newer.as_type(Finding).severity
        assert decision.severity == "MEDIUM" and decision.suggested_severity == "LOW"
        assert [a.operation for a in store.audit_events()].count("severity-decision") == 2
        assert store.verify()["status"] == "PASS"


def test_R01_rubric_has_exact_content_digest():
    versioned = rubric()
    assert versioned["version"] == "p010-risk-rubric-1.0"
    assert versioned["sha256"] == digest({key: value for key, value in versioned.items() if key != "sha256"})


@pytest.mark.parametrize("override", ["", "TBD"])
def test_R02_severity_requires_rationale(case, override):
    with case.workspace.session() as store:
        confirm(case, store)
        _, reviewer = actors(store)
        with pytest.raises(Invalid):
            reviewer.severity(FINDING, rating(), override, "HUMAN_AUTHORED")


@pytest.mark.parametrize(
    ("impact", "exploitability", "quality"),
    [
        ("UNKNOWN", "REPEATABLE", "LIMITED"),
        ("SYSTEMIC", "UNKNOWN", "CORROBORATED"),
        ("SEVERE", "LIKELY", "INSUFFICIENT"),
        ("MATERIAL", "CONDITIONAL", "UNKNOWN"),
    ],
)
def test_R03_unknown_is_unrated(impact, exploitability, quality):
    assert suggest(rating(impact=impact, exploitability=exploitability), quality) == "UNRATED"


def test_R04_R05_R06_R07_rating_and_impact_provenance(case):
    with case.workspace.session() as store:
        assert suggest(rating(), "LIMITED") == "LOW"
        assert store.latest("finding", FINDING, required=False) is None
        found = confirm(case, store).as_type(Finding)
        _, reviewer = actors(store)
        final = reviewer.severity(FINDING, rating(), REASON, "AI_ASSISTED").as_type(Finding)
        assert final.severity.severity == "LOW" and final.severity.confidence == "HIGH"
        assert final.validation_status == "CONFIRMED"
        assert found.validation.business_impact == case.validation.business_impact
        evidence = store.resolve(final.validation.inspected_evidence[0]).as_type(Evidence)
        assert store.resolve(evidence.source).as_type(SourceRecord).payload["status"] == "FAIL"


def test_R09_R10_applicability_basis_required(case):
    with case.workspace.session() as store:
        finding = confirm(case, store)
        author, reviewer = actors(store)
        catalog = author.import_source(import_file("p005", REPO / "p-005/src/p005/data/risks.json"))
        data = _risk(catalog, finding)
        with pytest.raises(Invalid, match="rationale"):
            reviewer.risk("RISK-001", data, "", FIXTURE)
        no_basis = data.model_copy(update={"applicability": "NOT_APPLICABLE", "basis_refs": []})
        with pytest.raises(Invalid, match="supporting context"):
            reviewer.risk("RISK-001", no_basis, REASON, FIXTURE)
        missing = next(
            x["id"] for x in catalog.as_type(SourceRecord).payload["entries"] if not x["available"]
        )
        with pytest.raises(Invalid, match="Unresolved"):
            reviewer.risk("RISK-001", data.model_copy(update={"source_risk_id": missing}), REASON, FIXTURE)


def test_R11_R12_acceptance_is_separate_and_attributable(example):
    with example.session() as store:
        risk = store.current("risk", "RISK-DEMO-001")
        owner = Workflow(store, ENGAGEMENT, RISK_OWNER, at=AT)
        reviewer = Workflow(store, ENGAGEMENT, REVIEWER, at=AT)
        original = store.current("finding", FINDING).as_type(Finding)
        acceptance = AcceptanceInput(
            risk=risk.link,
            scope_refs=["demo-a-health"],
            decision="ACCEPTED",
            constraints=["Synthetic scope"],
            review_by="2027-01-01T00:00:00Z",
            source_reference="Exercise decision",
        )
        with pytest.raises(Invalid, match="role"):
            reviewer.accept("TEST-ACCEPT", acceptance, REASON, FIXTURE)
        with pytest.raises(Invalid, match="scope"):
            owner.accept(
                "TEST-ACCEPT", acceptance.model_copy(update={"scope_refs": ["OTHER"]}), REASON, FIXTURE
            )
        with pytest.raises(Invalid, match="future"):
            owner.accept("TEST-ACCEPT", acceptance.model_copy(update={"review_by": AT}), REASON, FIXTURE)
        assert (
            risk.as_type(RiskInput).treatment == "ACCEPT" and original.lifecycle == "RESIDUAL_RISK_ACCEPTED"
        )
        assert (
            store.current("acceptance", "ACCEPT-DEMO-001").envelope.data["owner_decision"]["authorship"]
            == FIXTURE
        )


def test_E01_E02_E07_E09_evidence_reference_and_redaction(case):
    record = case.evidence.as_type(Evidence)
    assert record.source_record_id == "fixture-metadata-before"
    assert record.excerpt and record.excerpt.count("[REDACTED]") == 2
    assert record.excerpt_selected_by == AUTHOR
    assert "authenticity" in record.integrity_limit
    with pytest.raises(Invalid, match="validation"):
        validate(Evidence, {**record.model_dump(), "integrity_status": "REFERENCE_ONLY"})


def test_E05_reproduction_steps_and_expected_and_observed_are_required(case):
    with pytest.raises(Invalid):
        validate(Validation, {**case.validation.model_dump(), "reproduction_steps": []})
    with pytest.raises(Invalid):
        validate(ObservationDraft, {**case.observation.model_dump(), "expected_behavior": ""})
    with pytest.raises(Invalid):
        validate(ObservationDraft, {**case.observation.model_dump(), "attacker_preconditions": []})


def test_Q01_Q02_Q03_Q07_demo_gates_and_approval(case):
    with case.workspace.session() as store:
        _, reviewer = actors(store)
        confirm(case, store, authorship=FIXTURE)
        author, _ = actors(store)
        draft = reports.build(author, REPORT, narrative(), REASON)
        package = draft.as_type(Report)
        assert package.status == "DRAFT"
        assert {g.code for g in package.gates if not g.passed} == {"G09", "G21"}
        with pytest.raises(Invalid):
            reports.review(reviewer, REPORT, REASON, "HUMAN_AUTHORED", approve=True, expected=draft.link)


def test_Q04_Q05_Q06_L05_L06_L08_L10_report_projection(example):
    with example.session() as store:
        author, _ = actors(store)
        report = store.current("report", REPORT)
        body = reports.files(author, report)
        text = body["assessment.md"].decode()
        assert "NOT&#95;TESTED" in text and "Human independently reproduced" in text
        assert "Confirmed findings: 1" in text
        assert "TRAINING&#95;FIXTURE" in text
        assert "Original instructions intentionally omitted" not in text
        assert not any(
            b"P010_SECRET_EXERCISE" in part or b"pii-canary@example.invalid" in part for part in body.values()
        )
        assert b"p010-minimization-1.0" in body["manifest.json"]
        assert (
            b"Source authenticity, trusted time and independent custody are unverified" in body["evidence.md"]
        )


def test_Q08_E10_approval_versions_and_report_verification(case):
    with case.workspace.session() as store:
        confirm(case, store)
        author, reviewer = actors(store)
        reviewer.severity(FINDING, rating(), REASON, "HUMAN_AUTHORED")
        narrative_input = narrative().model_copy(update={"authorship": "HUMAN_AUTHORED"})
        built = reports.build(author, REPORT, narrative_input, REASON)
        reviewed = reports.review(
            reviewer, REPORT, REASON, "HUMAN_AUTHORED", approve=False, expected=built.link
        )
        approved = reports.review(
            reviewer, REPORT, REASON, "HUMAN_AUTHORED", approve=True, expected=reviewed.link
        )
        assert approved.as_type(Report).status == "APPROVED_FOR_DELIVERY"
        original = reports.export(author, approved, case.workspace.root)
        later = reports.build(author, REPORT, narrative_input, "Created another independent local version.")
        assert later.link.version > approved.link.version
        assert store.resolve(approved.link).as_type(Report).status == "APPROVED_FOR_DELIVERY"
        assert reports.verify(author, approved, original)["status"] == "PASS"
        (original / "assessment.md").write_text("Synthetic mutation")
        with pytest.raises(Invalid, match="changed"):
            reports.verify(author, approved, original)


def test_Q07_report_review_concurrency_lease(case):
    with case.workspace.session() as store:
        author, reviewer = actors(store)
        first = reports.build(author, REPORT, narrative(), REASON)
        reports.build(author, REPORT, narrative(), REASON)
        with pytest.raises(Invalid, match="changed"):
            reports.review(reviewer, REPORT, REASON, FIXTURE, approve=False, expected=first.link)


def test_Q09_audit_mutation(case):
    with case.workspace.session() as store:
        assert store.verify()["status"] == "PASS"
        store.connection.execute("UPDATE audit SET hash = ? WHERE seq = 2", ("f" * 64,))
        with pytest.raises(Invalid, match="Audit"):
            store.verify()


def test_Q09_missing_version_is_an_integrity_error(case):
    with case.workspace.session() as store:
        store.connection.execute("DELETE FROM records WHERE kind='evidence'")
        with pytest.raises(Invalid, match="missing"):
            store.verify()


def test_Q10_Q12_only_local_retention(case):
    with case.workspace.session() as store:
        future = Workflow(store, ENGAGEMENT, CUSTODIAN, at="2030-01-01T00:00:00Z")
        source = ROOT / "fixtures/reproduction-before.json"
        baseline = digest(source.read_bytes())
        plan = retention.plan(future)
        assert plan["eligible"]
        with pytest.raises(Invalid):
            retention.purge(future, "0" * 64, "p010-owned-engagement")
        assert retention.purge(future, plan["plan_sha256"], "p010-owned-engagement")["purged"] == 4
        assert digest(source.read_bytes()) == baseline
        assert store.verify()["status"] == "PASS"
        assert not store.versions(ENGAGEMENT)


def test_L09_report_rejected_when_privacy_gate_fails(case, monkeypatch):
    from p010 import reports as module

    with case.workspace.session() as store:
        author, reviewer = actors(store)
        built = reports.build(author, REPORT, narrative(), REASON)

        def denied(_):
            raise Invalid("Privacy check failed")

        monkeypatch.setattr(module, "privacy_check", denied)
        with pytest.raises(Invalid, match="quality"):
            reports.review(reviewer, REPORT, REASON, FIXTURE, approve=False, expected=built.link)


@pytest.mark.parametrize("key", ["raw_prompt", "private_key", "label_key"])
def test_L08_disallowed_keys_cannot_persist(case, key):
    with case.workspace.session() as store:
        source = store.resolve(case.evidence.as_type(Evidence).source).as_type(SourceRecord)
        author, _ = actors(store)
        safe = source.model_copy(
            update={"payload": {key: "inert fixture"}, "source_sha256": digest(canonical(key))}
        )
        with pytest.raises(Invalid, match="prohibited"):
            author.import_source(safe)
