"""Pinned NIST OSCAL validation and a bounded Assessment Results exporter."""

from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

import jsonschema
import regex
from pydantic import Field

from p010.models import SHA, Evidence, Finding, Link, Observation, Remediation, Risk, Strict
from p010.reports import Context
from p010.safety import ROOT, Invalid, digest, load, parse, privacy_check, read, report_text
from p010.store import Version
from p010.workflow import Workflow

OSCAL_VERSION = "1.2.3"
OSCAL_COMMIT = "e061961c7702afeabffdf5e59894d35e748dade1"
BASE_URL = f"https://github.com/usnistgov/OSCAL/releases/download/v{OSCAL_VERSION}"
PIN = {
    "assessment-plan": ("ap", "ea687b9d0ab1d84c9cb11ee0a5e22b17956fe892ee93f5acca937bef81d23ea2"),
    "assessment-results": ("ar", "4034e2032332dbf597e59e0646ec16c2c31df992962490371e91f47b219ff42c"),
    "catalog": ("catalog", "ab95836e9e8dfeb6fde80007f6cc76fa3192f595d427c751a3f3923c3f474fc2"),
    "poam": ("poam", "f4fd94487408a9589954b5b92d88965c984d4f79b85365cc574b860898759437"),
    "ssp": ("ssp", "99b1bee2df5604a7d4f1faeab43148e0bd4c4a1f513cd0d2d0c7896aa216a1e7"),
}
_ROOTS = {"ssp": "system-security-plan", "poam": "plan-of-action-and-milestones"}
NS = "urn:p010:synthetic:assessment-results:1"
LIMIT = "OSCAL validation asserts byte-pinned schema conformance and the implemented local reference checks. Assurance, certification and ATO remain outside this validation."


class OscalManifest(Strict):
    kind: Literal["oscal-assessment-results", "oscal-mapping-draft", "oscal-validation"]
    conformance: Literal["NOT VALID OSCAL", "VALIDATED_LOCAL_SUBSET", "SCHEMA_VALID_ONLY"]
    source_report: Link | None = None
    metadata: dict[str, Any]
    controls: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)
    context_hashes: dict[str, SHA] = Field(default_factory=dict)
    limitations: list[str]


def _pattern(validator, pattern, value, schema):
    if validator.is_type(value, "string") and regex.search(pattern, value, timeout=0.2) is None:
        yield jsonschema.ValidationError("OSCAL pattern mismatch")


Official = jsonschema.validators.extend(jsonschema.Draft7Validator, {"pattern": _pattern})


def official_schema(model: str) -> tuple[dict, dict]:
    if model not in PIN:
        raise Invalid("Unsupported OSCAL model")
    code, sha = PIN[model]
    raw = read(ROOT / "data/oscal" / (model + ".json"))
    assert raw is not None
    schema_id = f"http://csrc.nist.gov/ns/oscal/{OSCAL_VERSION}/oscal-{code}-schema.json"
    if digest(raw) != sha:
        raise Invalid("Official OSCAL schema digest mismatch")
    document = parse(raw)
    if document["$id"] != schema_id:
        raise Invalid("Official OSCAL schema identity mismatch")
    return document, {
        "version": OSCAL_VERSION,
        "commit": OSCAL_COMMIT,
        "schema_id": schema_id,
        "sha256": sha,
        "source": f"{BASE_URL}/oscal_{model}_schema.json",
        "validator": f"jsonschema {distribution_version('jsonschema')} / regex {distribution_version('regex')}",
    }


def structural(model: str, data: Any) -> dict:
    schema, pin = official_schema(model)
    try:
        validator = Official(schema, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)
        errors = []
        for error in validator.iter_errors(data):
            errors.append(error.validator or "schema")
            if len(errors) == 24:
                break
    except (ValueError, TimeoutError):
        raise Invalid("Official OSCAL structural validation could not complete") from None
    root = _ROOTS.get(model, model)
    compatible = not errors and data[root]["metadata"]["oscal-version"] == OSCAL_VERSION
    record = OscalManifest(
        kind="oscal-validation",
        conformance="SCHEMA_VALID_ONLY" if compatible else "NOT VALID OSCAL",
        metadata=pin,
        missing=sorted(set(errors)) + ([] if compatible or errors else ["Exact OSCAL metadata version"]),
        limitations=[LIMIT, "Semantic context requires explicit locally linked inputs."],
    )
    return record.model_dump(mode="json")


def _list_controls(catalog) -> list[dict]:
    controls = []
    for row in catalog.get("controls", []):
        controls += [row, *_list_controls(row)]
    for row in catalog.get("groups", []):
        controls.extend(_list_controls(row))
    return controls


def _selected_controls(controls: dict) -> dict[str, set[str]]:
    if controls.get("control-objective-selections"):
        raise Invalid("OSCAL objective selections are outside the supported subset")
    selection = controls["control-selections"]
    if any(set(s) - {"include-controls", "description", "props", "links", "remarks"} for s in selection):
        raise Invalid("OSCAL selection needs explicit included controls")
    rows = [row for group in selection for row in group.get("include-controls", [])]
    result = {row["control-id"]: set(row.get("statement-ids", [])) for row in rows}
    if not result or len(result) != len(rows):
        raise Invalid("OSCAL control selection is missing or ambiguous")
    return result


def _statements(control: dict) -> list[str]:
    return [
        statement
        for part in control.get("parts", [])
        for statement in (
            ([part["id"]] if part.get("name") == "statement" and "id" in part else []) + _statements(part)
        )
    ]


def prerequisites(directory: Path) -> tuple[dict, dict]:
    model_roots = {
        "assessment-plan": "assessment-plan",
        "catalog": "catalog",
        "ssp": "system-security-plan",
    }
    hashes = {}
    data = {}
    for model, name in model_roots.items():
        raw = read(directory / (model + ".json"))
        assert raw is not None
        source = parse(raw)
        validation = structural(model, source)
        if validation["conformance"] != "SCHEMA_VALID_ONLY":
            raise Invalid(f"OSCAL {model} input failed official validation")
        privacy_check(source)
        hashes[model] = digest(raw)
        data[name] = source[name]
    ap, ssp, catalog = data["assessment-plan"], data["system-security-plan"], data["catalog"]
    if ap["import-ssp"]["href"] != "ssp.json" or ssp["import-profile"]["href"] != "catalog.json":
        raise Invalid("OSCAL AP and SSP must link their explicit local inputs")
    catalog_rows = _list_controls(catalog)
    catalog_controls = {row["id"]: set(_statements(row)) for row in catalog_rows}
    implemented = {row["control-id"] for row in ssp["control-implementation"]["implemented-requirements"]}
    selected = _selected_controls(ap["reviewed-controls"])
    if len(catalog_controls) != len(catalog_rows) or not set(selected) <= set(catalog_controls) & implemented:
        raise Invalid("OSCAL controls do not resolve consistently in the SSP and catalog")
    if any(not statements <= catalog_controls[control] for control, statements in selected.items()):
        raise Invalid("OSCAL assessed statement is missing from its catalog control")
    if not ap.get("tasks") or not ssp["system-implementation"].get("components"):
        raise Invalid("OSCAL assessment activity and SSP component context are required")
    return data, hashes


def _oid(*parts: str) -> str:
    return str(uuid5(NAMESPACE_URL, NS + ":" + ":".join(parts)))


def _prop(name: str, value: str) -> dict:
    return {"name": name, "ns": NS, "value": value}


def _matrix(ctx: Context) -> list[dict]:
    return [
        {
            "finding": v.link.model_dump(),
            "controls": finding.validation.control_ids,
            "requirements": finding.validation.requirement_ids,
            "evidence": [x.model_dump() for x in finding.validation.inspected_evidence],
        }
        for v, finding in ctx.of(Finding)
        if finding.validation_status == "CONFIRMED"
    ]


def export(flow: Workflow, report_version: Version, directory: Path | None) -> dict:
    from p010.models import Report

    report = report_version.as_type(Report)
    ctx = Context(flow, report.source_record_versions)
    mapping = _matrix(ctx)
    _, pin = official_schema("assessment-results")
    unsupported = [
        "OSCAL objectives, profile resolution and include-all selection",
        "POA&M generation",
        "Source artifact binary copies, activities beyond reviewed observation records",
    ]
    manifest = OscalManifest(
        kind="oscal-mapping-draft",
        conformance="NOT VALID OSCAL",
        source_report=report_version.link,
        metadata=pin,
        missing=[
            "Validated SSP and resolved catalog",
            "Validated assessment plan and explicit control selection",
        ],
        unsupported=unsupported,
        limitations=[LIMIT],
    )
    if directory is None:
        return {**manifest.model_dump(mode="json"), "mappings": mapping}
    data, hashes = prerequisites(directory)
    ap = data["assessment-plan"]
    controls = _selected_controls(ap["reviewed-controls"])
    if not mapping or any(
        not row["controls"]
        or not set(row["controls"]) <= set(controls)
        or not any(set(row["requirements"]) & controls[control] for control in row["controls"])
        for row in mapping
    ):
        return {
            **manifest.model_copy(
                update={
                    "missing": [
                        "Reviewed findings mapped to exact selected OSCAL controls and statement IDs"
                    ],
                    "context_hashes": hashes,
                }
            ).model_dump(mode="json"),
            "mappings": mapping,
        }
    findings, observations, risks = [], {}, {}
    for record, finding in ctx.of(Finding):
        if finding.validation_status != "CONFIRMED":
            continue
        observation = ctx.selected(finding.observation, Observation)
        review = finding.review_history[0]
        evidence_items = []
        for ref in finding.validation.inspected_evidence:
            evidence = ctx.selected(ref, Evidence)
            oid = _oid("evidence", ref.sha256)
            props = [_prop("p010-evidence-id", ref.id), _prop("source-record-id", evidence.source_record_id)]
            if evidence.verified_sha256:
                props.append(_prop("verified-evidence-sha256", evidence.verified_sha256))
            if evidence.source_time is None:
                return {
                    **manifest.model_copy(
                        update={
                            "missing": ["Source collection timestamp for each mapped observation"],
                            "context_hashes": hashes,
                        }
                    ).model_dump(mode="json"),
                    "mappings": mapping,
                }
            observations[oid] = {
                "uuid": oid,
                "description": report_text(observation.observed_behavior),
                "methods": ["EXAMINE"],
                "collected": evidence.source_time,
                "props": props,
            }
            evidence_items.append({"observation-uuid": oid})
        related_risks = []
        for risk_version, risk in ctx.of(Risk):
            if not any(ref.id == record.link.id for ref in risk.finding_refs):
                continue
            rid = _oid("risk", risk_version.sha256)
            risks[rid] = {
                "uuid": rid,
                "title": report_text(risk.source_risk_id),
                "description": report_text(risk.description),
                "statement": report_text(risk.treatment_plan),
                "status": "open",
                "props": [
                    _prop("p010-risk-id", risk_version.link.id),
                    _prop("residual-rating", risk.residual_risk),
                ],
                "related-observations": evidence_items,
            }
            related_risks.append({"risk-uuid": rid})
        targets = [
            (control, statement)
            for control in finding.validation.control_ids
            for statement in sorted(controls[control] & set(finding.validation.requirement_ids))
        ]
        for control, statement in targets:
            found = {
                "uuid": _oid("finding", record.sha256, control, statement),
                "title": report_text(finding.title),
                "description": report_text(finding.validation.security_impact),
                "target": {
                    "type": "statement-id",
                    "target-id": statement,
                    "status": {"state": "not-satisfied"},
                },
                "props": [
                    _prop("p010-finding-id", record.link.id),
                    _prop("reviewed-at", review.decided_at),
                    _prop("oscal-control-id", control),
                ],
                "related-observations": evidence_items,
            }
            if related_risks:
                found["related-risks"] = related_risks
            findings.append(found)
    actions = [_prop("p010-remediation-id", rec.link.id) for rec, _ in ctx.of(Remediation)]
    result = {
        "uuid": _oid("result", report_version.sha256),
        "title": "P-010 synthetic assessment results",
        "description": "Reviewed findings with references to local evidence records.",
        "start": ctx.engagement.assessment_window.start,
        "end": ctx.engagement.assessment_window.end,
        "reviewed-controls": ap["reviewed-controls"],
        "findings": findings,
        "observations": list(observations.values()),
        "props": [_prop("p010-report-id", report_version.link.id), *actions],
    }
    if risks:
        result["risks"] = list(risks.values())
    output = {
        "assessment-results": {
            "uuid": _oid("assessment-results", report_version.sha256),
            "metadata": {
                "title": "P-010 synthetic assessment results",
                "last-modified": report.generated_at,
                "version": str(report_version.link.version),
                "oscal-version": OSCAL_VERSION,
            },
            "import-ap": {"href": "assessment-plan.json"},
            "results": [result],
        }
    }
    outcome = validate_document("assessment-results", output, directory)
    if outcome["conformance"] != "VALIDATED_LOCAL_SUBSET":
        return {
            **manifest.model_copy(
                update={"missing": outcome["missing"], "context_hashes": hashes}
            ).model_dump(mode="json"),
            "mappings": mapping,
        }
    return {
        "manifest": {
            **outcome,
            "kind": "oscal-assessment-results",
            "source_report": report_version.link.model_dump(),
            "unsupported": unsupported,
        },
        "document": output,
    }


def validate_document(model: str, document: dict, directory: Path | None) -> dict:
    outcome = structural(model, document)
    if (
        outcome["conformance"] == "NOT VALID OSCAL"
        or directory is None
        or model not in {"assessment-results", "poam"}
    ):
        return outcome
    data, hashes = prerequisites(directory)
    if model == "poam":
        body = document["plan-of-action-and-milestones"]
        groups = [body]
        valid = body.get("import-ssp", {}).get("href") == "ssp.json"
    else:
        body = document["assessment-results"]
        groups = body["results"]
        valid = body["import-ap"]["href"] == "assessment-plan.json"
    controls = _selected_controls(data["assessment-plan"]["reviewed-controls"])
    missing = []
    for row in groups:
        observed_ids = [item["uuid"] for item in row.get("observations", [])]
        risk_ids = [item["uuid"] for item in row.get("risks", [])]
        finding_ids = [item["uuid"] for item in row.get("findings", [])]
        if len(set(observed_ids + risk_ids + finding_ids)) != len(observed_ids + risk_ids + finding_ids):
            missing.append("Unique local observation, finding and risk UUIDs")
        row_controls = (
            _selected_controls(row["reviewed-controls"]) if "reviewed-controls" in row else controls
        )
        if any(
            control not in controls or not statements <= controls[control]
            for control, statements in row_controls.items()
        ):
            missing.append("Result controls and statements selected in assessment plan")
        for collection in ("findings", "risks", "poam-items"):
            for item in row.get(collection, []):
                if collection == "findings":
                    target = item["target"]
                    linked = [
                        p["value"]
                        for p in item.get("props", [])
                        if p.get("ns") == NS and p["name"] == "oscal-control-id"
                    ]
                    if (
                        target["type"] != "statement-id"
                        or len(linked) != 1
                        or (target["target-id"] not in row_controls.get(linked[0], set()))
                    ):
                        missing.append("Finding target linked to an exact selected control statement")
                for field, ident, ids in (
                    ("related-observations", "observation-uuid", observed_ids),
                    ("related-risks", "risk-uuid", risk_ids),
                    ("related-findings", "finding-uuid", finding_ids),
                ):
                    if not all(ref[ident] in ids for ref in item.get(field, [])):
                        missing.append(f"Resolved {field}")
    if not valid:
        missing.append("Exact local assessment plan or SSP link")
    return {
        **outcome,
        "conformance": "NOT VALID OSCAL" if missing else "VALIDATED_LOCAL_SUBSET",
        "missing": sorted(set(missing)),
        "controls": sorted(controls),
        "context_hashes": hashes,
    }


def validate_file(model: str, path: Path, directory: Path | None) -> dict:
    return validate_document(model, load(path), directory)
