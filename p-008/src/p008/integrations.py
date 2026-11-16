"""Read-only actual sibling schemas. Imported metadata never becomes execution authority."""

from pathlib import Path
import jsonschema

from p008.models import P007Import
from p008.safety import REPO, Blocked, Invalid, digest, load, read_bytes


def import_p007(path: Path) -> P007Import:
    schema = REPO / "p-007/schemas/report-export.schema.json"
    if not schema.is_file():
        raise Blocked("P007-ACTUAL-CONTRACT-ABSENT")
    try:
        from p007.models import ReportExport
    except ImportError as exc:
        raise Blocked("P007-ACTUAL-VALIDATOR-UNAVAILABLE") from exc

    value = load(path)
    if value.get("schema_version") != "1.0":
        raise Invalid("P007-INCOMPATIBLE-SCHEMA")
    jsonschema.Draft202012Validator(load(schema)).validate(value)
    report = ReportExport.model_validate(value)
    return P007Import(
        contract="ReportExport-1.0",
        original_run_id=report.run_id,
        original_manifest_sha256=report.manifest_sha256,
        source_sha256=digest(read_bytes(path)),
        report=report.model_dump(mode="json"),
        live_integration="PASS",
        limitation="Actual merged P007 contract validated read-only. Evidence references retained, not re-executed or authenticated; results are not dataset labels or fresh authorization.",
    )


def available_siblings() -> list[dict]:
    from p002.generators import generate
    from p002.models import Dataset
    from p003.models import Engagement, verified
    from p005.ingestion.fixtures import build
    from p005.modeling.rule_engine import analyze

    dataset = Dataset.model_validate(generate(seed=20261116, profile="tiny").model_dump(mode="json"))
    policy_path = REPO / "p-003/examples/engagement-draft-a.json"
    policy = Engagement.model_validate(load(policy_path))
    verified(policy)
    model = build(REPO / "p-005/fixtures/baseline/architecture.yaml")
    threats = analyze(model)
    imported = import_p007(REPO / "p-007/examples/report-export.example.json")
    return [
        {
            "project": "P-002",
            "status": "PASS",
            "contract": "Dataset-1.0",
            "source_hash": digest(dataset),
            "synthetic_identity_ids": [x.id for x in dataset.humans],
            "tenant_ids": [x.id for x in dataset.tenants],
            "scenario_ids": [x.id for x in dataset.scenarios],
            "limit": "Generated references only, not native enforcement.",
        },
        {
            "project": "P-003",
            "status": "PASS",
            "contract": "sealed-Engagement-1.0",
            "source_hash": policy.content_digest,
            "limit": "Read-only metadata validation; time window may be expired. No network tasks or real authority used.",
        },
        {
            "project": "P-005",
            "status": "PASS",
            "contract": "p005-model-1.0",
            "source_hash": digest(model),
            "hypothesis_ids": [x["threat_id"] for x in threats.get("threats", [])],
            "limit": "Modelled candidate threats only; no findings or automatic P008 labels.",
        },
        {
            "project": "P-007",
            "status": imported.live_integration,
            "contract": imported.contract,
            "source_hash": imported.source_sha256,
            "run_id": imported.original_run_id,
            "result_count": len(imported.report["results"]),
            "limit": imported.limitation,
        },
        {
            "project": "P-006",
            "status": "BLOCKED" if not (REPO / "p-006").exists() else "NOT_TESTED",
            "contract": None,
            "limit": "No committed application or independently verified runtime at inspected base.",
        },
        {
            "project": "P-009",
            "status": "NOT_TESTED",
            "contract": "p008-handoff-1.0",
            "limit": "Export-only future consumer.",
        },
        {
            "project": "P-010",
            "status": "NOT_TESTED",
            "contract": "p008-handoff-1.0",
            "limit": "Export-only future consumer; no consultancy findings generated.",
        },
    ]


def siblings() -> list[dict]:
    """Optional metadata exercise; absence must not prevent the standalone demo."""
    try:
        return available_siblings()
    except (ImportError, Blocked) as exc:
        return [
            {
                "project": project,
                "status": "BLOCKED",
                "contract": None,
                "limit": "Optional sibling validator/runtime unavailable: "
                + type(exc).__name__
                + "; standalone evaluation core remains usable.",
            }
            for project in ("P-002", "P-003", "P-005", "P-007", "P-006")
        ] + [
            {
                "project": project,
                "status": "NOT_TESTED",
                "contract": "p008-handoff-1.0",
                "limit": "Future export-only consumer.",
            }
            for project in ("P-009", "P-010")
        ]
