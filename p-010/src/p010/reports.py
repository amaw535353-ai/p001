"""Deterministic, review-gated Markdown and machine-readable report packages."""

import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Literal, TypeVar

from pydantic import Field

from p010 import NOTICE
from p010.models import (
    ID,
    SHA,
    Acceptance,
    AtlasMapping,
    Authorship,
    Engagement,
    Evidence,
    Finding,
    Gate,
    Link,
    Observation,
    Remediation,
    Report,
    ReportNarrative,
    Retest,
    RetestPlan,
    Risk,
    SourceRecord,
    Strict,
    effective_acceptances,
)
from p010.safety import (
    HASH_LIMIT,
    MAX_RECORD,
    PRIVACY_VERSION,
    Invalid,
    canonical,
    checked_path,
    digest,
    is_placeholder,
    privacy_check,
    read,
    report_text,
    select,
    timestamp,
)
from p010.store import Version, validate
from p010.workflow import Workflow, rubric

Model = TypeVar("Model", bound=Strict)


class ReportManifest(Strict):
    schema_version: Literal["p010-report-manifest-1.0"] = "p010-report-manifest-1.0"
    report: Link
    files: dict[str, SHA]
    source_record_versions: list[Link]
    source_hashes: dict[ID, SHA]
    privacy_policy: Literal["p010-minimization-1.0"] = PRIVACY_VERSION
    hash_limitation: str = HASH_LIMIT


class FindingHandoff(Strict):
    finding: Link
    validation_status: Literal["CONFIRMED", "WITHDRAWN"]
    disposition: Literal["OPEN", "RESIDUAL_RISK_ACCEPTED", "CLOSED"]
    reviewed_severity: ID | None
    review_basis: Authorship


class Handoff(Strict):
    schema_version: Literal["p010-handoff-v1"] = "p010-handoff-v1"
    engagement_id: ID
    report: Link
    report_status: str
    findings: list[FindingHandoff]
    risks: list[Link]
    evidence: list[Link]
    source_records: list[Link]
    reports_limited_to: Literal["SYNTHETIC_TRAINING"] = "SYNTHETIC_TRAINING"
    limitations: list[str] = Field(min_length=1)
    privacy_policy: Literal["p010-minimization-1.0"] = PRIVACY_VERSION


def record_links(value: Any):
    if isinstance(value, dict):
        if set(value) == {"kind", "id", "version", "sha256"}:
            yield validate(Link, value)
        else:
            for child in value.values():
                yield from record_links(child)
    elif isinstance(value, list):
        for child in value:
            yield from record_links(child)


class Context:
    def __init__(self, flow: Workflow, refs: list[Link] | None = None):
        self.flow = flow
        if refs is None:
            self.current = [
                version
                for version in flow.store.versions(flow.id, current=True)
                if version.link.kind not in {"report", "redmine-sync"}
            ]
        else:
            self.current = [flow.resolve(ref) for ref in refs]
        self.engagement = next(value for _, value in self.of(Engagement))
        self.records = {record.link: record for record in self.current}
        pending = self.current.copy()
        while pending:
            record = pending.pop()
            if isinstance(record.data, SourceRecord):
                continue
            for ref in record_links(record.envelope.data):
                if ref not in self.records:
                    new = flow.resolve(ref)
                    self.records[ref] = new
                    pending.append(new)
            if len(self.records) > 4000:
                raise Invalid("Report dependency count exceeds the limit")

    def of(self, model: type[Model]) -> list[tuple[Version, Model]]:
        return [(row, row.as_type(model)) for row in self.current if isinstance(row.data, model)]

    def selected(self, ref: Link, model: type[Model]) -> Model:
        return self.records[ref].as_type(model)


def quality(ctx: Context, report: Report, *, at: str) -> list[Gate]:
    engagement = ctx.engagement
    findings = [item for _, item in ctx.of(Finding) if item.validation_status == "CONFIRMED"]
    risks = [item for _, item in ctx.of(Risk)]
    sources = [item for _, item in ctx.of(SourceRecord)]
    evidence = [item for _, item in ctx.of(Evidence)]
    remediations = [item for _, item in ctx.of(Remediation)]
    decisions = [item for _, item in ctx.of(Acceptance)]
    mappings = [item for _, item in ctx.of(AtlasMapping) if item.state == "ACCEPTED"]
    observations = [ctx.selected(item.observation, Observation) for item in findings]
    all_fields = [report.narrative.model_dump(mode="json"), *(r.export() for r in ctx.records.values())]
    private = True
    try:
        privacy_check(all_fields)
    except Invalid:
        private = False
    relevant = {version.link: item for version, item in ctx.of(Risk)}
    acceptance_current = all(
        item.decision != "ACCEPTED"
        or (
            timestamp(item.review_by) > timestamp(at)
            and item.risk in relevant
            and relevant[item.risk].risk_owner_ref == item.owner_decision.actor.ref
        )
        for item in effective_acceptances(decisions)
    )
    policy_match = engagement.p003_policy_digest is None or any(
        source.contract == "p003-engagement-policy-1.0"
        and source.payload.get("policy_digest") == engagement.p003_policy_digest
        and source.payload.get("scope", {}).get("id") == engagement.assessment_scope_ref
        and source.payload.get("window") == engagement.assessment_window.model_dump()
        and {row["asset_id"] for row in source.payload.get("assets", []) if row["included"]}
        == {row.ref for row in engagement.assets if row.included}
        for source in sources
    )
    verified = ctx.flow.store.verify()["status"] == "PASS"
    source_status = all(
        (item.project != "P-008" or item.payload["p010"]["findings"] == [])
        and (item.project != "P-009" or item.payload["findings"] == [])
        for item in sources
    )
    checks = (
        (bool(engagement.assessment_scope_ref) and policy_match, "Engagement and selected scope provenance"),
        (engagement.authority_notice == NOTICE, "Synthetic authority caveat"),
        (
            bool(engagement.assets) and bool(engagement.assessment_window),
            "Scope, exclusions and assessment window",
        ),
        (all(item.applicability_rationale for item in risks), "Risk applicability rationale"),
        (
            all(
                item.review_history
                and item.review_history[0].actor.role == "REVIEWER"
                and item.review_history[0].actor.ref != item.author_ref
                for item in findings
            ),
            "Independent finding decisions",
        ),
        (
            all(
                any(
                    ctx.selected(ref, Evidence).human_review_status == "INSPECTED"
                    for ref in item.validation.inspected_evidence
                )
                for item in findings
            ),
            "Inspected evidence for every finding",
        ),
        (
            all(item.source in ctx.records for item in evidence),
            "Exact source versions and evidence references",
        ),
        (
            all(item.disposition == "CONFIRMED" for item in observations),
            "Finding dispositions separate from source results",
        ),
        (
            all(
                item.severity
                and item.severity.decision.rationale
                and item.severity.rubric_sha256 == rubric()["sha256"]
                for item in findings
            ),
            "Authored severity and pinned rubric",
        ),
        (
            all(item.evidence_quality not in {"INSUFFICIENT", "UNKNOWN"} for item in observations),
            "Evidence quality separate from rating",
        ),
        (
            all(item.validation.security_impact and item.validation.business_impact for item in findings),
            "Reviewer-supplied impact statements",
        ),
        (
            all(
                obs.attacker_preconditions
                and obs.expected_behavior
                and obs.observed_behavior
                and f.validation.reproduction_steps
                for obs, f in zip(observations, findings, strict=True)
            ),
            "Reproduction prerequisites, expectation and observation",
        ),
        (all(rem.finding in ctx.records for rem in remediations), "Remediation linked to finding evidence"),
        (
            all(rem.owner_ref and rem.target_date for rem in remediations),
            "Remediation owner and target date or open gap",
        ),
        (
            all(item.review.actor.role == "REVIEWER" for _, item in ctx.of(Retest)),
            "Separate reviewed retest outcomes",
        ),
        (acceptance_current, "Residual risk and attributable current owner decisions"),
        (
            all(item.title and item.review.rationale and item.evidence_refs for item in mappings),
            "Versioned reviewed ATLAS mapping",
        ),
        (report.oscal_conformance == "NOT VALID OSCAL", "Explicit OSCAL status of internal report"),
        (
            bool(engagement.limitations) and bool(report.narrative.limitations),
            "Limitations and incomplete coverage",
        ),
        (
            report.narrative.authorship in {"HUMAN_AUTHORED", "AI_ASSISTED", "TRAINING_FIXTURE"},
            "Narrative authorship",
        ),
        (
            bool(report.reviews)
            and all(
                r.actor.ref != report.author.actor.ref and r.actor.role == "REVIEWER" for r in report.reviews
            ),
            "Attributable independent report review",
        ),
        (
            not any(
                is_placeholder(text)
                for text in (
                    report.narrative.executive_summary,
                    report.narrative.methodology,
                    report.narrative.architecture_context,
                    report.narrative.management_response,
                    report.narrative.follow_up,
                )
            ),
            "No unresolved narrative placeholders",
        ),
        (source_status, "Source results remain source-owned"),
        (private, "Redacted approved projection"),
        (verified, "Verified local audit and frozen record hashes"),
    )
    return [
        Gate(code=f"G{number:02}", passed=bool(result), detail=detail)
        for number, (result, detail) in enumerate(checks, 1)
    ]


def build(flow: Workflow, id_: str, narrative: ReportNarrative, rationale: str) -> Version:
    flow.require("AUTHOR")
    author = flow.decision(rationale, narrative.authorship)
    ctx = Context(flow)
    prior = flow.store.latest("report", id_, required=False)
    if prior is not None:
        flow.current("report", id_)
    package = Report(
        author=author,
        narrative=narrative,
        source_record_versions=[v.link for v in ctx.current],
        generated_at=flow.at,
        gates=[],
        status="DRAFT",
    )
    gates = quality(ctx, package, at=flow.at)
    updated = package.model_copy(
        update={
            "gates": gates,
            "status": "REVIEW_READY" if all(gate.passed for gate in gates if gate.code != "G21") else "DRAFT",
        }
    )
    return flow.save("report", id_, updated, "report-build", rationale, prior.link if prior else None)


def review(
    flow: Workflow,
    id_: str,
    rationale: str,
    authorship: Authorship,
    *,
    approve: bool,
    expected: Link,
) -> Version:
    flow.require("REVIEWER")
    version = flow.current("report", id_)
    if version.link != expected:
        raise Invalid("Report version changed since review")
    package = version.as_type(Report)
    if package.approvals or package.status not in {"REVIEW_READY", "REVIEWED"}:
        raise Invalid("The report must pass content gates and be unapproved")
    decision = flow.decision(rationale, authorship, independent_of=package.author.actor.ref)
    ctx = Context(flow, package.source_record_versions)
    if approve:
        if (
            not package.reviews
            or any(
                item.authorship == "TRAINING_FIXTURE" for item in [decision, package.author, *package.reviews]
            )
            or any(
                reviewer.authorship == "TRAINING_FIXTURE"
                for _, finding in ctx.of(Finding)
                for reviewer in [
                    *finding.review_history,
                    *([finding.severity.decision] if finding.severity else []),
                ]
            )
            or any(item.owner_decision.authorship == "TRAINING_FIXTURE" for _, item in ctx.of(Acceptance))
        ):
            raise Invalid("Delivery approval requires attributable non-simulated review and decisions")
        # A complete frozen review may be historical. Approval applies only while its selected current records are unchanged.
        if {v.link for v in ctx.current} != {v.link for v in Context(flow).current}:
            raise Invalid("Report sources changed. Rebuild and review a new version.")
        updated = package.model_copy(update={"status": "APPROVED_FOR_DELIVERY", "approvals": [decision]})
    else:
        updated = package.model_copy(
            update={
                "status": "REVIEW_READY" if decision.authorship == "TRAINING_FIXTURE" else "REVIEWED",
                "reviews": [*package.reviews, decision],
            }
        )
    gates = quality(ctx, updated, at=flow.at)
    if not all(gate.passed for gate in gates):
        raise Invalid("Report quality gates reject this review or approval")
    return flow.save(
        "report",
        id_,
        updated.model_copy(update={"gates": gates}),
        "report-approve" if approve else "report-review",
        rationale,
        version.link,
    )


def _rows(values) -> str:
    return (
        "\n".join("- " + " — ".join(report_text(str(value)) for value in row) for row in values)
        or "- None recorded."
    )


def _sections(ctx: Context, version: Version, report: Report) -> dict[str, str]:
    e, n = ctx.engagement, report.narrative
    findings, risks, sources = ctx.of(Finding), ctx.of(Risk), ctx.of(SourceRecord)
    confirmed = [f for _, f in findings if f.validation_status == "CONFIRMED"]
    counts = Counter((item.severity.severity if item.severity else "UNRATED") for item in confirmed)
    source_rows = []
    for record, item in sources:
        note = item.payload.get("snapshot_context", item.validation)
        if item.project == "P-007":
            statuses = Counter(row["status"] for row in item.payload["results"])
            note = ", ".join(f"{k}={v}" for k, v in sorted(statuses.items()))
        if item.project == "P-008":
            summary = item.payload.get("summary")
            note = (
                f"{summary['status']}, {len(summary['results'])} non-sealed result rows, "
                f"{summary['omission_policy']['sealed_results_excluded']} sealed rows omitted"
                if summary
                else "NOT_TESTED: no evaluation run in this handoff"
            )
        if item.project == "P-009":
            note = ", ".join(
                f"{activity}={status}"
                for activity, status in sorted(item.payload["telemetry_coverage"].items())
            )
        source_rows.append((record.link.id, item.project, item.contract, item.source_record_id, note))
    sections = {
        "Executive summary": "\n\n".join(
            (
                report_text(n.executive_summary),
                f"Confirmed findings: {len(confirmed)}. "
                + (
                    ", ".join(f"{key} {value}" for key, value in sorted(counts.items()))
                    or "No reviewed severities recorded."
                ),
                f"Observation records: {len(ctx.of(Observation))}. The source results and their units appear below.",
            )
        ),
        "Scope and methodology": "\n".join(
            (
                NOTICE,
                report_text(n.methodology),
                "",
                _rows(
                    [
                        (
                            e.assessment_scope_ref,
                            e.assessment_window.start,
                            e.assessment_window.end,
                            e.methodology_version,
                        )
                    ]
                ),
                "",
                "Included assets",
                _rows((a.ref, a.component, a.environment) for a in e.assets if a.included),
                "",
                "Exclusions",
                _rows((x,) for x in e.exclusions),
                "",
                "Assessment objectives",
                _rows((x,) for x in e.assessment_objectives),
            )
        ),
        "Architecture and assumptions": report_text(n.architecture_context) + "\n\n" + _rows(source_rows),
        "Risk applicability and prioritization": _rows(
            (
                v.link.id,
                r.source_risk_id,
                r.source_risk_definition or "UNRESOLVED",
                r.applicability,
                r.applicability_rationale,
                r.inherent_risk,
                r.current_control_state,
                r.risk_owner_ref,
            )
            for v, r in risks
        ),
        "Findings summary": _rows(
            (
                v.link.id,
                f.title,
                f.validation_status,
                f.severity.severity if f.severity else "UNRATED",
                f.remediation_status,
                f.retest_status,
                f.lifecycle,
            )
            for v, f in findings
        ),
    }
    details = []
    for v, finding in findings:
        obs = ctx.selected(finding.observation, Observation)
        info = finding.validation
        severity = finding.severity
        lines = [
            f"### {report_text(v.link.id)} · {report_text(finding.title)}",
            _rows(
                [
                    ("Executive description", finding.executive_summary),
                    ("Technical detail", obs.description),
                    ("Assets and scope", ", ".join(obs.asset_refs), obs.scope_ref),
                    ("Expected", obs.expected_behavior),
                    ("Observed", obs.observed_behavior),
                    ("Requirements", ", ".join(info.requirement_ids)),
                    ("Control IDs", ", ".join(info.control_ids)),
                    ("Attacker capability", info.attacker_capability),
                    ("Preconditions", ", ".join(obs.attacker_preconditions)),
                    ("Reproduction conditions", obs.reproduction_conditions),
                    ("Reproduction steps", " / ".join(info.reproduction_steps)),
                    ("Security impact", info.security_impact),
                    ("Business impact", info.business_impact),
                    ("Data impact", info.data_impact),
                    ("Availability impact", info.availability_impact),
                    (
                        "False-positive review",
                        info.false_positive_analysis,
                        " / ".join(obs.alternative_explanations),
                    ),
                    ("Evidence quality", obs.evidence_quality),
                    ("Evidence references", ", ".join(ref.id for ref in info.inspected_evidence)),
                    ("Limitations", " / ".join([*info.limitations, *obs.limitations])),
                    ("Assessment", finding.validation_status, obs.epistemic_status),
                    ("Finding version", v.link.version),
                ]
            ),
        ]
        if severity:
            lines.append(
                _rows(
                    [
                        ("Severity", severity.severity, severity.rubric_version, severity.decision.rationale),
                        ("Confidence", severity.confidence),
                        ("Exposure", severity.exposure),
                        ("Exploitability", severity.exploitability_rationale),
                        ("Likelihood", severity.likelihood_rationale),
                        ("Business context", severity.business_context),
                        ("Uncertainty", severity.uncertainty),
                        (
                            "Compensating controls",
                            " / ".join(severity.compensating_controls) or "None entered",
                        ),
                    ]
                )
            )
        lines.append(
            _rows(
                ("Review", x.actor.ref, x.authorship, x.decided_at, x.rationale)
                for x in finding.review_history
            )
        )
        details.append("\n\n".join(lines))
    sections["Technical findings"] = "\n\n".join(details) or "No confirmed or withdrawn finding records."
    sections["Evidence and reproduction"] = _rows(
        (
            v.link.id,
            item.source.id,
            item.source_record_id,
            item.source_time or "Time unavailable",
            item.integrity_status,
            item.redaction_status,
            item.verified_sha256 or "No verified file digest",
            item.human_review_status,
            item.trace_ref or "No trace linked",
            item.observation_ref or "No observation ID linked",
            " / ".join(item.limitations),
            item.excerpt or "Metadata only",
        )
        for v, item in ctx.of(Evidence)
    )
    sections["Severity and risk methodology"] = (
        report_text(rubric()["purpose"])
        + "\n\n"
        + _rows(
            (
                v.link.id,
                f.severity.severity,
                f.severity.suggested_severity,
                f.severity.decision.rationale,
                f.severity.rubric_version,
                f.severity.rubric_sha256,
            )
            for v, f in findings
            if f.severity is not None
        )
    )
    sections["MITRE ATLAS mappings"] = _rows(
        (
            item.finding.id,
            item.technique_id,
            item.title or "UNRESOLVED_HISTORICAL",
            item.catalog_version,
            item.catalog_commit,
            item.state,
            item.confidence,
            "PINNED_AT_REVIEW" if item.title else "UNRESOLVED_HISTORICAL",
            item.review.rationale,
            ", ".join(ref.id for ref in item.evidence_refs),
            " / ".join(item.limitations),
        )
        for _, item in ctx.of(AtlasMapping)
    )
    sections["Control and requirement traceability"] = _rows(
        (
            v.link.id,
            *f.validation.requirement_ids,
            *f.validation.control_ids,
            *(
                item.source_risk_id
                for _, item in risks
                if any(link.id == v.link.id for link in item.finding_refs)
            ),
        )
        for v, f in findings
    )
    sections["Remediation roadmap"] = _rows(
        (
            item.finding.id,
            item.recommendation,
            item.affected_control,
            item.owner_ref,
            item.target_date,
            item.verification_criteria,
            " / ".join(item.dependencies),
            " / ".join(item.compensating_controls),
            item.implementation.rationale if item.implementation else "Implementation unverified",
        )
        for _, item in ctx.of(Remediation)
    )
    sections["Retest and regressions"] = (
        _rows(
            (
                item.finding.id,
                item.result_status,
                item.configuration_comparison,
                item.source_version_comparison,
                " / ".join(item.limitations),
                ", ".join(item.source_results),
                ", ".join(item.regression_results),
                ", ".join(ref.test_id for ref in item.original_tests),
                ", ".join(ref.test_id for ref in item.new_tests),
            )
            for _, item in ctx.of(Retest)
        )
        + "\n\n"
        + _rows(
            (
                item.finding.id,
                "Retest plan",
                item.remediation.id,
                item.comparability_criteria,
                item.expected_behavior,
                " / ".join(item.planned_checks),
            )
            for _, item in ctx.of(RetestPlan)
        )
    )
    sections["Residual risk and acceptance"] = (
        _rows((v.link.id, item.residual_risk, item.treatment, item.treatment_plan) for v, item in risks)
        + "\n\n"
        + _rows(
            (
                item.risk.id,
                item.decision,
                item.owner_decision.actor.ref,
                item.owner_decision.authorship,
                item.owner_decision.rationale,
                ", ".join(item.scope_refs),
                item.review_by,
                " / ".join(item.constraints),
            )
            for _, item in ctx.of(Acceptance)
        )
    )
    sections["Limitations and untested areas"] = _rows(
        [(x,) for x in [*e.limitations, *n.limitations, HASH_LIMIT]]
        + [(s.project, x) for _, s in sources for x in [*s.limitations, *s.omissions]]
        + [("Structured exchange", report.oscal_conformance)]
    )
    sections["Management response"] = report_text(n.management_response)
    sections["Peer review and approval"] = _rows(
        [(gate.code, "PASS" if gate.passed else "OPEN", gate.detail) for gate in report.gates]
        + [
            (item.actor.ref, item.authorship, item.decided_at, item.rationale)
            for item in [*report.reviews, *report.approvals]
        ]
        + [
            ("Author", report.author.actor.ref, n.authorship),
            ("Template", report.template_version),
            ("Human independently reproduced", "NOT DEMONSTRATED"),
            ("External human reviewer verified", "NOT DEMONSTRATED"),
        ]
    )
    sections["Handover and follow-up"] = report_text(n.follow_up)
    return sections


def _summary(source: SourceRecord) -> dict:
    row = source.model_dump(mode="json", exclude={"payload", "artifacts"})
    if source.project == "P-007":
        row["source_results"] = [
            select(result, "test_id status test_version") for result in source.payload["results"]
        ]
    elif source.project == "P-008" and source.payload["summary"]:
        row["evaluation_summary"] = select(source.payload["summary"], "run_id status omission_policy")
    elif source.project == "P-009":
        row["event_references"] = [
            select(event, "event_id trace_id span_id event_time redaction_status")
            for event in source.payload["event_references"]
        ]
    elif source.project == "Langfuse":
        row["trace_reference"] = source.payload
    return row


def files(flow: Workflow, version: Version) -> dict[str, bytes]:
    report = version.as_type(Report)
    ctx = Context(flow, report.source_record_versions)
    e = ctx.engagement
    sections = _sections(ctx, version, report)
    text = (
        f"# {report_text(e.title)}\n\n"
        f"Report {report_text(version.link.id)} · Version {version.link.version} · {report.status}\n\n"
        f"{NOTICE}\n\n"
        + "\n\n".join("## " + heading + "\n\n" + value for heading, value in sections.items())
        + "\n"
    )
    safe = {
        "report": version.export(),
        "records": [v.export() for v in ctx.records.values() if not isinstance(v.data, SourceRecord)],
        "source_metadata": [
            {"record": v.link.model_dump(mode="json"), **_summary(v.data)}
            for v in ctx.records.values()
            if isinstance(v.data, SourceRecord)
        ],
    }
    privacy_check(safe)
    package: dict[str, bytes] = {
        "assessment.md": text.encode(),
        "report.json": canonical(safe) + b"\n",
    }
    for heading, name in (
        ("Executive summary", "executive-summary.md"),
        ("Technical findings", "findings.md"),
        ("Risk applicability and prioritization", "risk-register.md"),
        ("Evidence and reproduction", "evidence.md"),
        ("Remediation roadmap", "remediation.md"),
        ("Retest and regressions", "retest.md"),
    ):
        package[name] = (f"# {heading}\n\n{NOTICE}\n\n{sections[heading]}\n").encode()
    manifest = ReportManifest(
        report=version.link,
        files={name: digest(raw) for name, raw in package.items()},
        source_record_versions=list(ctx.records),
        source_hashes={
            v.link.id + ".v" + str(v.link.version): v.data.source_sha256
            for v in ctx.records.values()
            if isinstance(v.data, SourceRecord) and v.data.source_sha256
        },
    )
    package["manifest.json"] = canonical(manifest.model_dump(mode="json")) + b"\n"
    if sum(map(len, package.values())) > MAX_RECORD:
        raise Invalid("Report package exceeds the byte limit")
    return package


def verify(flow: Workflow, version: Version, directory: Path | None = None) -> dict:
    flow.store.verify()
    package = files(flow, version)
    digests = {name: digest(raw) for name, raw in package.items()}
    if directory is not None:
        target = checked_path(directory)
        if not target.is_dir() or any(
            read(target / name, limit=MAX_RECORD) != raw for name, raw in package.items()
        ):
            raise Invalid("Report package is missing files or its contents changed")
        if {path.name for path in target.iterdir()} != set(package):
            raise Invalid("Report package contains unexpected files")
    return {"status": "PASS", "files": digests, "report": version.link.model_dump(mode="json")}


def export(flow: Workflow, version: Version, root: Path) -> Path:
    root = checked_path(root)
    parent = root / "reports"
    parent.mkdir(mode=0o700, exist_ok=True)
    checked_path(parent)
    if parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077:
        raise Invalid("Reports directory must remain private")
    target = checked_path(parent / f"{version.link.id}-v{version.link.version}")
    package = files(flow, version)
    if target.exists():
        verify(flow, version, target)
    else:
        with tempfile.TemporaryDirectory(dir=parent, prefix=".staging-") as scratch:
            staged = Path(scratch) / "package"
            staged.mkdir(mode=0o700)
            for name, payload in package.items():
                fd = os.open(staged / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            staged.rename(target)
    flow.audit("report-export", "Exported a synthetic package to the private workspace", [version.link])
    return target


def handoff(flow: Workflow, version: Version) -> Handoff:
    report = version.as_type(Report)
    ctx = Context(flow, report.source_record_versions)
    verified = verify(flow, version)
    assert verified["status"] == "PASS"
    value = Handoff(
        engagement_id=flow.id,
        report=version.link,
        report_status=report.status,
        findings=[
            FindingHandoff(
                finding=v.link,
                validation_status=f.validation_status,
                disposition=f.lifecycle,
                reviewed_severity=f.severity.severity if f.severity else None,
                review_basis=f.review_history[0].authorship,
            )
            for v, f in ctx.of(Finding)
        ],
        risks=[v.link for v, _ in ctx.of(Risk)],
        evidence=[v.link for v, _ in ctx.of(Evidence)],
        source_records=[v.link for v, _ in ctx.of(SourceRecord)],
        limitations=[NOTICE, HASH_LIMIT, "Source and review records require authorized local access."],
    )
    flow.audit("handoff-export", "Exported reference-only synthetic handoff", [version.link])
    return value
