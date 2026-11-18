"""Read-only adapters for the sibling contracts in the approved source tree."""

import json
import re
from pathlib import Path
from typing import Any

import jsonschema

from p010.models import Artifact, Reproduction, SourceRecord
from p010.safety import (
    HASH_LIMIT,
    REPO,
    Invalid,
    digest,
    load,
    now,
    parse,
    privacy_check,
    read,
    relative_parts,
    select,
    timestamp,
)
from p010.store import validate

PROJECTS = {"p003", "p004", "p005", "p006", "p007", "p008", "p009", "reproduction"}
SOURCE_NAMES = {f"p00{number}": f"P-00{number}" for number in range(3, 10)}
SOURCE_NAMES["reproduction"] = "P-010"


def schema(project: str, name: str) -> tuple[dict, str]:
    raw = read(REPO / f"p-{project[1:]}" / "schemas" / (name + ".schema.json"))
    assert raw is not None
    return parse(raw), digest(raw)


def check(value: Any, document: dict, label: str) -> None:
    if not jsonschema.Draft202012Validator(document).is_valid(value):
        raise Invalid(f"Incompatible {label} schema")


def record_object(value: Any, required: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != required:
        raise Invalid(f"Incompatible {label} fields")
    return value


def rows(value: Any, label: str, *, limit: int = 1280) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise Invalid(f"Incompatible {label} list")
    return value


def hex_commit(value: Any) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value) else None


def import_file(
    project: str,
    path: Path,
    *,
    flavor: str | None = None,
    run_root: Path | None = None,
    events: Path | None = None,
    imported_at: str | None = None,
) -> SourceRecord:
    if project not in PROJECTS:
        raise Invalid("Unsupported source project")
    if (run_root and project != "p007") or (events and project != "p009"):
        raise Invalid("Artifact root or event export does not match the source adapter")
    raw = read(path)
    assert raw is not None
    if project == "p005" and flavor == "reviews" and path.suffix == ".jsonl":
        lines = [line for line in raw.splitlines() if line.strip()]
        if len(lines) > 512:
            raise Invalid("P-005 review log exceeds the record limit")
        value = [parse(line) for line in lines]
    else:
        value = parse(raw)
    at = imported_at or now()
    if project == "p003":
        data = p003(value, at)
    elif project == "p004":
        data = architecture(project, value)
    elif project == "p005":
        data = p005(value, flavor)
    elif project == "p006":
        data = architecture(project, value)
    elif project == "p007":
        data = p007(value, run_root)
    elif project == "p008":
        data = p008(value)
    elif project == "p009":
        data = p009(value, events)
    else:
        reproduction = validate(Reproduction, value)
        data = {
            "contract": reproduction.schema_version,
            "source_version": reproduction.schema_version,
            "source_record_id": reproduction.record_id,
            "source_time": reproduction.collection_time,
            "payload": reproduction.model_dump(mode="json"),
            "validation": "VERIFIED_BYTES",
            "artifacts": [
                Artifact(
                    path="reproduction-record.json",
                    media_type="application/json",
                    declared_sha256=digest(raw),
                    declared_size=len(raw),
                    integrity="VERIFIED_BYTES",
                )
            ],
            "limitations": [
                *reproduction.limitations,
                "Operator-supplied observation record. P-010 did not run the described procedure.",
            ],
        }
    data.setdefault("validation", "SCHEMA_VALIDATED")
    data.setdefault("source_record_id", digest(raw))
    data.setdefault("source_version", data["contract"])
    data.setdefault("limitations", [])
    data["limitations"] = [*data["limitations"], HASH_LIMIT]
    result = validate(
        SourceRecord,
        {
            **data,
            "artifacts": [a.model_dump(mode="json") for a in data.get("artifacts", [])],
            "project": SOURCE_NAMES[project],
            "source_sha256": digest(raw),
            "imported_at": at,
        },
    )
    privacy_check(result.model_dump(mode="json"))
    return result


def _p003_digest(value: dict) -> None:
    claimed = value.get("content_digest")
    if (
        not claimed
        or digest({key: child for key, child in value.items() if key != "content_digest"}) != claimed
    ):
        raise Invalid("P-003 content digest mismatch")


def p003(value: Any, at: str) -> dict:
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        raise Invalid("Unsupported P-003 version")
    kind = value.get("kind", "engagement")
    if kind == "oscal-mapping-draft":
        if value.get("conformance") != "NOT VALID OSCAL":
            raise Invalid("P-003 OSCAL drafts must retain nonconformance")
        return dict(
            contract="oscal-mapping-draft",
            source_version="1.0",
            validation="REFERENCE_ONLY",
            payload=select(value, "kind conformance"),
            limitations=["P-003 mapping draft. Official AP schema rejects it."],
        )
    if kind not in {"engagement", "engagement-policy", "evidence-manifest"}:
        raise Invalid("Unsupported P-003 export kind")
    document, pin = schema("p003", kind)
    check(value, document, "P-003 " + kind)
    _p003_digest(value)
    safe = select(
        value,
        "schema_version id notice engagement_id engagement_version version status content_digest "
        "policy_digest scope window expires_at ledger_head chain_head artifacts review_references "
        "consumption enforcement real_legal_authority goals",
    )
    for dest, name, fields in (
        (
            "assets",
            "target_inventory" if kind == "engagement-policy" else "assets",
            "asset_id tenant service environment selector methods included ownership data_class trust_boundaries",
        ),
        (
            "roe",
            "resource_limits_and_stops" if kind == "engagement-policy" else "roe",
            "window allowed forbidden max_total_requests max_requests_per_minute max_cost_units "
            "max_interruption_ms human_checkpoint stop_conditions recovery communications",
        ),
        (
            "evidence_policy",
            "evidence_policy",
            "data_class storage_ids access_roles retention_days redact_before_export deletion custody_references",
        ),
        (
            "authority_provenance",
            "authority_provenance",
            "id version content_digest policy_digest approving_role reviewed checklist evidence_ref "
            "evidence_sha256 targets activities window exceptions revocation_history real_legal_authority",
        ),
    ):
        child = value.get(name)
        if isinstance(child, dict):
            _p003_digest(child)
            safe[dest] = select(child, fields)
        elif isinstance(child, list):
            for item in child:
                _p003_digest(item)
            safe[dest] = [select(item, fields) for item in child]
    if "scope" in value:
        _p003_digest(value["scope"])
    if "window" in safe:
        start, end = (timestamp(safe["window"][key]) for key in ("start", "end"))
        if start >= end or (value.get("expires_at") and timestamp(value["expires_at"]) != end):
            raise Invalid("P-003 policy window mismatch")
        approval = safe.get("authority_provenance", {})
        if approval and (
            approval["policy_digest"] != safe["policy_digest"]
            or approval["version"] != safe["engagement_version"]
            or approval["window"] != safe["window"]
        ):
            raise Invalid("P-003 approval and policy provenance disagree")
        safe["snapshot_context"] = (
            "REVOKED"
            if approval.get("revocation_history") or safe.get("status") == "REVOKED"
            else "OUTSIDE_WINDOW"
            if timestamp(at) < start
            else "EXPIRED"
            if timestamp(at) >= end
            else "HISTORICAL_REFERENCE"
        )
    return dict(
        contract=f"p003-{kind}-1.0",
        source_version=str(value.get("engagement_version", value.get("version", "1.0"))),
        schema_sha256=pin,
        source_record_id=value["id"],
        source_time=value["created_at"],
        payload=safe,
        limitations=[
            "Historical training context. Real legal authority, current ledger and target enforcement are unverified.",
            "An exported decision cannot authorize target testing.",
        ],
        omissions=["Client contacts and unneeded identity fields"],
    )


def architecture(project: str, value: Any) -> dict:
    if not isinstance(value, dict):
        raise Invalid("Invalid architecture source")
    version = value.get("schema_version")
    if not isinstance(version, str):
        raise Invalid("Architecture contract version is required")
    variants = {
        ("p004", "p004-architecture-v1"): "architecture",
        ("p004", "p004-snapshot-v1"): "snapshot",
        ("p006", "p006-inventory-v1"): "service-inventory",
        ("p006", "p006-profile-v1"): "architecture-profile",
    }
    name = variants.get((project, version))
    if project == "p006" and version == "p006-proposed-risk-v1":
        record_object(
            value, {"schema_version", "source_mapping", "source_status", "relationships"}, "P-006 risks"
        )
        for row in rows(value["relationships"], "P-006 risks", limit=37):
            record_object(
                row,
                {"risk_id", "source_description", "source_available", "relationship", "rationale"},
                "P-006 risk row",
            )
        return dict(contract=version, payload=value, limitations=["P-006 proposed applicability only."])
    if name is None:
        raise Invalid("Unsupported architecture contract")
    document, pin = schema(project, name)
    check(value, document, project.upper())
    if name == "architecture-profile":
        payload = select(
            value, "schema_version name model_mode tenants models route policy egress deployment"
        )
        payload["identity"] = select(value["identity"], "issuer audience algorithms")
        payload["principal_roles"] = [select(row, "tenant roles") for row in value["principals"]]
    else:
        payload = value
    return dict(
        contract=version,
        source_record_id=value.get("name") or value.get("snapshot_id") or digest(value),
        schema_sha256=pin,
        payload=payload,
        limitations=[
            "Architecture metadata as declared by its source. Cloud and production enforcement are untested."
        ],
        omissions=["Identity credentials and individual principal details"]
        if name == "architecture-profile"
        else [],
    )


def p005(value: Any, flavor: str | None) -> dict:
    version = value.get("schema_version") if isinstance(value, dict) else None
    flavors = {
        "threats": ("threat", "p005-threat-1.0"),
        "verification": ("verification", "p005-verification-1.0"),
        "reviews": ("review", "p005-review-1.0"),
    }
    common = {
        "limitations": [
            "Threats and applicability remain hypotheses. Planned verification remains NOT_TESTED."
        ]
    }
    if flavor in flavors:
        assert flavor is not None
        schema_name, contract = flavors[flavor]
        document, pin = schema("p005", schema_name)
        original = rows(value, f"P-005 {flavor}", limit=512) if isinstance(value, list) else [value]
        for row in original:
            check(row, document, f"P-005 {flavor}")
            if flavor == "threats" and (row.get("schema_version"), row.get("hypothesis_status")) != (
                "p005-threat-1.0",
                "HYPOTHESIS",
            ):
                raise Invalid("P-005 threat must retain its hypothesis status")
            if flavor == "verification" and (row.get("run_status"), row.get("executable")) != (
                "NOT_TESTED",
                False,
            ):
                raise Invalid("P-005 verification work must remain planned")
            if flavor == "reviews" and (
                row.get("schema_version"),
                row.get("synthetic_editorial_only"),
                row.get("authenticated_identity"),
            ) != ("p005-review-1.0", True, False):
                raise Invalid("P-005 reviews must retain synthetic editorial provenance")
        projected = [
            select(
                row,
                "schema_version threat_id title node_ids edge_ids boundary_ids risk_ids risk_source "
                "test_id test_ids control_ids hypothesis_status confidence triage evidence_refs rule_trace applicability status "
                "review_status run_status executable scope_state roe_check_state model_digest sequence at_utc "
                "decision reviewer_role reason synthetic_editorial_only authenticated_identity",
            )
            for row in original
        ]
        if flavor == "reviews" and [row["sequence"] for row in projected] != list(
            range(1, len(projected) + 1)
        ):
            raise Invalid("P-005 review sequence mismatch")
        return dict(**common, contract=contract, schema_sha256=pin, payload={flavor: projected})
    simple = {"p005-model-1.0": "model", "p005-risk-1.0": "risk"}
    if version in simple:
        document, pin = schema("p005", simple[version])
        check(value, document, "P-005 " + simple[version])
        if version == "p005-risk-1.0" and (
            len(value["entries"]) != 37 or len({row["id"] for row in value["entries"]}) != 37
        ):
            raise Invalid("P-005 taxonomy slots do not match the source contract")
        payload = (
            value
            if version == "p005-risk-1.0"
            else select(
                value,
                "schema_version model_id model_version engagement_id engagement_version system_id nodes "
                "flows boundaries source_snapshot_hash evidence assumptions exclusions integrations model_scope review_state",
            )
        )
        return dict(
            **common,
            contract=version,
            schema_sha256=pin,
            payload=payload,
            source_record_id=value.get("model_id", digest(value)),
            source_time=value.get("created_utc"),
            source_commit=hex_commit(value.get("git_commit")),
        )
    fields = {
        "p005-traceability-1.0": "schema_version taxonomy applicability links",
        "p005-atlas-mapping-1.0": "schema_version catalog mappings",
        "p005-manifest-1.0": "schema_version notice files content_root_sha256 model_digest source_snapshot_hash "
        "source_refs run_clock_utc tool_versions environment seed rules_sha256 risk_catalog_sha256 "
        "dependency_lock_sha256 sanitizer target_test_status engineering_tests limitations git_commit",
        "p005-selected-examples-1.0": "schema_version model_digest candidate_count full_run_candidate_count "
        "scope target_testing files",
        "p005-analysis-1.0": "schema_version model_digest threats attack_paths controls mitigations verification_plan "
        "suppressions risk_applicability",
    }
    if version not in fields:
        raise Invalid("Unsupported P-005 contract")
    record_object(value, set(fields[version].split()), "P-005 export")
    if version == "p005-analysis-1.0":
        payload = select(value, "schema_version model_digest risk_applicability")
        payload.update(p005(value["threats"], "threats")["payload"])
        payload.update(p005(value["verification_plan"], "verification")["payload"])
    else:
        payload = value
        if version == "p005-traceability-1.0":
            p005(payload["taxonomy"], None)
        if version.endswith("manifest-1.0") and (
            value["target_test_status"] != "NOT_TESTED"
            or digest(value["files"]) != value["content_root_sha256"]
        ):
            # P-005 uses its own pretty canonical serialization for this field.
            pretty = (json.dumps(value["files"], indent=2, ensure_ascii=True, sort_keys=True) + "\n").encode()
            if value["target_test_status"] != "NOT_TESTED" or digest(pretty) != value["content_root_sha256"]:
                raise Invalid("P-005 manifest digest or target scope mismatch")
    return dict(
        **common,
        contract=version,
        payload=payload,
        source_time=value.get("run_clock_utc"),
        source_commit=hex_commit(value.get("git_commit")),
    )


_MEASUREMENTS = (
    "decision http_status disclosure downstream_calls executed_markup valid_output observation_recorded "
    "confirmed_vulnerability refusal tool_calls model_calls event_count allowed matched expected_status"
)
_RUN_METADATA = (
    "empirical_only fixture_version minimum_pass_rate model sample_count seed temperature backend engine"
)
_COMPATIBILITY = (
    "adapter browser controls environment fixture_cases_hash fixture_version model oracle origin ownership_instance "
    "policy_hash policy_version seed service_identity source_hash target_id target_version tool_version"
)


def _scalars(value: dict, fields: str) -> dict:
    return {
        key: item
        for key, item in select(value, fields).items()
        if item is None or type(item) in {str, bool, int, float}
    }


def p007(value: Any, run_root: Path | None) -> dict:
    document, pin = schema("p007", "report-export")
    check(value, document, "P-007 ReportExport")
    if value.get("schema_version") != "1.0":
        raise Invalid("Unsupported P-007 ReportExport version")
    handoff = record_object(value["handoff"], {"contract", "p008", "p009", "p010"}, "P-007 handoff")
    p010 = record_object(
        handoff["p010"], {"remediation_ref", "retest_of", "result_kind"}, "P-007 P-010 handoff"
    )
    if (
        handoff["contract"] != "p007-handoff-v1"
        or p010["result_kind"] != ("synthetic test outcomes; no confirmed client findings")
        or not all(
            p010[key] is None or isinstance(p010[key], str) for key in ("retest_of", "remediation_ref")
        )
    ):
        raise Invalid("Unsupported P-007 handoff version or result kind")
    reference = record_object(handoff["p009"], {"manifest_ref", "artifacts"}, "P-007 manifest reference")
    run_id = value["run_id"]
    if reference["manifest_ref"] != f"{run_id}/manifest.json":
        raise Invalid("P-007 manifest reference mismatch")
    artifact_rows = rows(reference["artifacts"], "P-007 artifacts", limit=128)
    artifacts = []
    seen = set()
    manifest = None
    if run_root is not None:
        if run_root.name != run_id or load(run_root / "owner.json") != {"owner": "p007", "run_id": run_id}:
            raise Invalid("P-007 run root ownership mismatch")
        raw = read(run_root / "manifest.json")
        assert raw is not None
        if digest(raw) != value["manifest_sha256"]:
            raise Invalid("P-007 manifest digest mismatch")
        manifest = parse(raw)
        evidence_schema, _ = schema("p007", "evidence-manifest")
        check(manifest, evidence_schema, "P-007 evidence manifest")
        if any(manifest[key] != value[key] for key in ("run_id", "results", "provenance")) or (
            manifest["artifacts"] != artifact_rows
            or any(manifest.get(key) != p010[key] for key in ("retest_of", "remediation_ref"))
        ):
            raise Invalid("P-007 manifest and report do not match")
    for entry in artifact_rows:
        item = record_object(
            entry, {"path", "sha256", "size", "media_type", "schema_version"}, "P-007 evidence item"
        )
        if item["schema_version"] != "1.0" or not isinstance(item["path"], str):
            raise Invalid("Unsupported P-007 evidence item")
        parts = relative_parts(item["path"])
        if item["path"] in seen:
            raise Invalid("Duplicate P-007 artifact reference")
        seen.add(item["path"])
        artifact = Artifact(
            path=item["path"],
            declared_sha256=item["sha256"],
            declared_size=item["size"],
            media_type=item["media_type"],
            integrity="REFERENCE_ONLY",
        )
        if artifact.declared_size > 1_048_576:
            raise Invalid("P-007 artifact exceeds contract size")
        if run_root is not None:
            content = read(run_root.joinpath(*parts), limit=1_048_576, missing=True)
            if content is not None and (
                len(content) != artifact.declared_size or digest(content) != artifact.declared_sha256
            ):
                raise Invalid("P-007 artifact size or digest mismatch")
            artifact = artifact.model_copy(
                update={"integrity": "UNAVAILABLE" if content is None else "VERIFIED_BYTES"}
            )
        artifacts.append(artifact)
    result_rows = []
    tests_seen = set()
    for row in rows(value["results"], "P-007 results", limit=128):
        if row["test_id"] in tests_seen:
            raise Invalid("Duplicate P-007 test identity")
        tests_seen.add(row["test_id"])
        runner = row["runner"]
        slim_runner = select(runner, "adapter executed original_status exit_code error_class tool_version")
        slim_runner["metadata"] = _scalars(runner["metadata"], _RUN_METADATA)
        slim_runner["observed"] = _scalars(runner["observed"], _MEASUREMENTS)
        result_rows.append(
            {
                **select(
                    row,
                    "test_id test_version control_ids status assertion definition_hash compatibility_hash",
                ),
                "expected": _scalars(row["expected"], _MEASUREMENTS),
                "observed": _scalars(row["observed"], _MEASUREMENTS),
                "compatibility": select(row["compatibility"], _COMPATIBILITY),
                "runner": slim_runner,
            }
        )
    any_bytes = bool(artifacts) and all(a.integrity == "VERIFIED_BYTES" for a in artifacts)
    commit = manifest.get("repository", {}).get("commit") if manifest else None
    return dict(
        contract="p007-handoff-v1",
        source_version="1.0",
        source_record_id=run_id,
        schema_sha256=pin,
        source_commit=hex_commit(commit),
        source_time=manifest.get("ended_at") if manifest else None,
        payload={
            **select(value, "run_id manifest_sha256 control_status provenance"),
            "handoff": {
                "contract": handoff["contract"],
                "p010": p010,
                "manifest_ref": reference["manifest_ref"],
            },
            "results": result_rows,
            "manifest_verified": manifest is not None,
            "target_ref": manifest["target"]["target_id"] if manifest else None,
        },
        artifacts=artifacts,
        validation="VERIFIED_BYTES" if any_bytes else "REFERENCE_ONLY",
        limitations=[
            "P-007 statuses measure source assertions. P-010 ran no source tests and creates no finding on import.",
            "All selected run bytes were verified."
            if any_bytes
            else "One or more original artifacts remain unavailable.",
        ],
        omissions=["Raw observations and output, runner commands, samples, and free-form configuration"],
    )


def p008(value: Any) -> dict:
    value = record_object(value, {"schema_version", "contract", "p007", "p009", "p010", "summary"}, "P-008")
    if (value["schema_version"], value["contract"]) != ("1.0", "p008-handoff-1.0"):
        raise Invalid("Unsupported P-008 handoff version")
    target = record_object(value["p010"], {"kind", "findings", "limitations"}, "P-008 P-010 target")
    if target["kind"] != "synthetic-evaluation-summary" or target["findings"] != []:
        raise Invalid("P-008 cannot supply confirmed findings")
    source = record_object(value["p007"], {"kind", "dataset", "manifest"}, "P-008 dataset reference")
    join = record_object(value["p009"], {"kind", "run_id", "evidence_manifest_digest"}, "P-008 run reference")
    if source["kind"] != "evaluation-metadata-only" or join["kind"] != "evaluation-event-references":
        raise Invalid("Unsupported P-008 target kinds")
    for candidate in (source["manifest"], join["evidence_manifest_digest"]):
        if candidate is not None and (
            not isinstance(candidate, str) or not re.fullmatch(r"[a-f0-9]{64}", candidate)
        ):
            raise Invalid("Invalid P-008 digest")
    document, pin = schema("p008", "evaluation-run")
    summary = value["summary"]
    if summary is not None:
        fields = (
            "schema_version run_id status plan_digest dataset_manifest_digest dataset evaluator metrics results "
            "limitations provenance omission_policy"
        )
        record_object(summary, set(fields.split()), "P-008 sanitized summary")
        if summary["schema_version"] != "1.0" or summary["run_id"] != join["run_id"]:
            raise Invalid("P-008 run reference mismatch")
        dataset = rows(summary["dataset"], "P-008 dataset", limit=2)
        if (
            len(dataset) != 2
            or dataset[0] != source["dataset"]
            or not all(isinstance(x, str) for x in dataset)
        ):
            raise Invalid("P-008 dataset reference mismatch")
        properties = document["properties"]
        for field, contract in (
            ("status", "status"),
            ("plan_digest", "plan_digest"),
            ("dataset_manifest_digest", "plan_digest"),
        ):
            check(summary[field], properties[contract], "P-008 " + field)
        for field, model in (("evaluator", "Evaluator"), ("metrics", "Metrics")):
            check(summary[field], {"$defs": document["$defs"], "$ref": f"#/$defs/{model}"}, "P-008 " + field)
        omissions = record_object(
            summary["omission_policy"], {"sealed_results_excluded", "reason"}, "P-008 omissions"
        )
        row_fields = set(
            "sample_id repetition status dimensions critical_failure scorer_digest rubric_version threshold".split()
        )
        sample_model = document["$defs"]["SampleResult"]
        result_schema = {
            "type": "object",
            "properties": {key: sample_model["properties"][key] for key in row_fields},
            "required": sorted(row_fields),
            "additionalProperties": False,
        }
        result_rows = rows(summary["results"], "P-008 results")
        for result in result_rows:
            check(result, result_schema, "P-008 sanitized row")
        ids = {(row["sample_id"], row["repetition"]) for row in result_rows}
        if (
            type(omissions["sealed_results_excluded"]) is not int
            or omissions["sealed_results_excluded"] < 0
            or not isinstance(omissions["reason"], str)
            or len(ids) != len(result_rows)
            or len(result_rows) + omissions["sealed_results_excluded"] != summary["metrics"]["observations"]
            or not set(summary["metrics"]["critical_sample_ids"] + summary["metrics"]["flaky_sample_ids"])
            <= {row["sample_id"] for row in result_rows}
        ):
            raise Invalid("P-008 sanitized row counts or omission policy disagree")
        summary = {
            **summary,
            "evaluator": select(
                summary["evaluator"],
                "evaluator_id version tool tool_version adapter_version "
                "implementation_digest provider model model_version policy temperature network",
            ),
        }
    return dict(
        contract="p008-handoff-1.0",
        source_version="1.0",
        source_record_id=join["run_id"] or source["dataset"],
        schema_sha256=pin,
        validation="REFERENCE_ONLY",
        payload={"p010": target, "summary": summary, "dataset": source},
        limitations=[
            "Aggregate evaluation metrics can include sealed cases. Only exported non-sealed rows are available."
        ],
        omissions=[
            "Evaluator prompts and judge prompts, sealed sample results, label keys, raw outputs and traces"
        ],
    )


def p009(value: Any, events: Path | None) -> dict:
    document, pin = schema("p009", "p009-handoff-v1")
    check(value, document, "P-009 handoff")
    if (value.get("schema_version"), value.get("contract"), value.get("findings")) != (
        "1.0",
        "p009-handoff-v1",
        [],
    ):
        raise Invalid("Unsupported P-009 handoff version")
    projected = []
    if events:
        event_schema, _ = schema("p009", "normalized-event")
        allowed = {obj["sha256"]: obj["size"] for obj in value["objects"] if obj["kind"] == "event"}
        event_ids = set()
        for event in rows(load(events), "P-009 redacted events", limit=4096):
            check(event, event_schema, "P-009 event")
            # Match P-009's actual canonical event object bytes, including its newline.
            raw = (
                json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
                + "\n"
            ).encode()
            stamp = event["event_time"]
            timestamp(stamp)
            if (
                allowed.get(digest(raw)) != len(raw)
                or event.get("tenant_ref") != value["tenant_ref"]
                or event.get("redaction_status") != "metadata-only"
                or event["event_id"] in event_ids
            ):
                raise Invalid("P-009 event digest, tenant or redaction mismatch")
            event_ids.add(event["event_id"])
            projected.append(
                select(
                    event,
                    "event_id event_type event_category event_severity event_time observed_time source_id "
                    "source_type source_version service_id trace_id span_id test_id test_run_id evaluation_run_id "
                    "alert_id wazuh_rule_id outcome decision source_event_digest redaction_status redaction_policy provenance",
                )
            )
    return dict(
        contract="p009-handoff-v1",
        source_version="1.0",
        schema_sha256=pin,
        validation="REFERENCE_ONLY",
        payload={**value, "event_references": projected},
        omissions=["Full event objects and private archive contents"],
        limitations=[
            *value["limitations"],
            "P-009 objects and coverage are source references. P-010 did not replay telemetry or validate findings.",
        ],
    )
