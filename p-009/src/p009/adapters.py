"""Read-only actual sibling interfaces; imported metadata never authorizes execution."""

import re
from pathlib import Path

import jsonschema

from p009.config import Config
from p009.normalize import normalize
from p009.privacy import assert_safe
from p009.safety import REPO, Invalid, canonical, digest, load, parts, read, relative_read


def validate_actual(project: str, name: str, value):
    schema = load(REPO / project / "schemas" / name)
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except (jsonschema.ValidationError, jsonschema.SchemaError):
        raise Invalid("SIBLING-CONTRACT") from None


def import_p007(path: Path, run_root: Path | None = None) -> dict:
    report = load(path)
    validate_actual("p-007", "report-export.schema.json", report)
    if report.get("schema_version") != "1.0":
        raise Invalid("P007-VERSION")
    handoff = report["handoff"]
    if set(handoff) != {"contract", "p008", "p009", "p010"} or handoff["contract"] != "p007-handoff-v1":
        raise Invalid("P007-HANDOFF")
    target = handoff["p009"]
    if (
        set(target) != {"manifest_ref", "artifacts"}
        or target["manifest_ref"] != report["run_id"] + "/manifest.json"
    ):
        raise Invalid("P007-MANIFEST-REFERENCE")
    if not isinstance(target["artifacts"], list) or not 1 <= len(target["artifacts"]) <= 128:
        raise Invalid("P007-ARTIFACT-BOUND")
    names = set()
    for ref in target["artifacts"]:
        if set(ref) != {"path", "media_type", "schema_version", "sha256", "size"}:
            raise Invalid("P007-ARTIFACT-CONTRACT")
        parts(ref["path"])
        if ref["path"] in names or not re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]):
            raise Invalid("P007-ARTIFACT-COLLISION")
        if (
            type(ref["size"]) is not int
            or not 0 <= ref["size"] <= 1_048_576
            or ref["schema_version"] != "1.0"
        ):
            raise Invalid("P007-ARTIFACT-BOUND")
        names.add(ref["path"])
    status = "REFERENCE_ONLY"
    if run_root is not None:
        if run_root.name != report["run_id"] or load(run_root / "owner.json") != {
            "owner": "p007",
            "run_id": report["run_id"],
        }:
            raise Invalid("P007-RUN-OWNERSHIP")
        manifest_raw = read(run_root / "manifest.json")
        if digest(manifest_raw) != report["manifest_sha256"]:
            raise Invalid("P007-MANIFEST-DIGEST")
        manifest = load(run_root / "manifest.json")
        validate_actual("p-007", "evidence-manifest.schema.json", manifest)
        for field, expected in (
            ("run_id", report["run_id"]),
            ("results", report["results"]),
            ("provenance", report["provenance"]),
            ("artifacts", target["artifacts"]),
        ):
            if manifest[field] != expected:
                raise Invalid("P007-MANIFEST-REPORT-MISMATCH")
        for ref in target["artifacts"]:
            raw = relative_read(run_root, ref["path"])
            if len(raw) != ref["size"] or digest(raw) != ref["sha256"]:
                raise Invalid("P007-ARTIFACT-INTEGRITY")
        status = "PASS"
    # Preserve original report byte semantics and statuses; refuse unsafe metadata, never rewrite it.
    assert_safe(report)
    return {
        "contract": "p009-p007-import-v1",
        "status": status,
        "source_digest": digest(read(path)),
        "report": report,
        "limitations": [
            "Digests establish consistency, not source authenticity or trusted time.",
            "No P007 runner, comparator or reproduction workflow was executed.",
            "Missing run bytes remain REFERENCE_ONLY."
            if run_root is None
            else "Artifact bytes verified read-only.",
        ],
    }


def import_p008(path: Path) -> dict:
    value = load(path)
    if set(value) != {"schema_version", "contract", "p007", "p009", "p010", "summary"}:
        raise Invalid("P008-HANDOFF-FIELDS")
    if value["schema_version"] != "1.0" or value["contract"] != "p008-handoff-1.0":
        raise Invalid("P008-HANDOFF-VERSION")
    target = value["p009"]
    if (
        set(target) != {"kind", "run_id", "evidence_manifest_digest"}
        or target["kind"] != "evaluation-event-references"
    ):
        raise Invalid("P008-P009-CONTRACT")
    run_id, manifest = target["run_id"], target["evidence_manifest_digest"]
    if run_id is not None and (
        not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", run_id)
    ):
        raise Invalid("P008-RUN-ID")
    if manifest is not None and not re.fullmatch(r"[a-f0-9]{64}", manifest):
        raise Invalid("P008-MANIFEST-DIGEST")
    summary = value["summary"]
    if summary is not None:
        required = {
            "schema_version",
            "run_id",
            "status",
            "plan_digest",
            "dataset_manifest_digest",
            "dataset",
            "evaluator",
            "metrics",
            "results",
            "limitations",
            "provenance",
        }
        if not required <= set(summary) or set(summary) - required - {"omission_policy"}:
            raise Invalid("P008-SUMMARY-CONTRACT")
        if summary["run_id"] != run_id or summary["schema_version"] != "1.0":
            raise Invalid("P008-SUMMARY-RUN")
        for field in ("plan_digest", "dataset_manifest_digest"):
            if not re.fullmatch(r"[a-f0-9]{64}", summary[field]):
                raise Invalid("P008-SUMMARY-DIGEST")
        if not isinstance(summary["dataset"], list) or len(summary["dataset"]) != 2:
            raise Invalid("P008-DATASET")
        # Validate actual evaluator/metrics subcontracts without importing or running the evaluator.
        schema = load(REPO / "p-008/schemas/evaluation-run.schema.json")
        for name, key in (("Evaluator", "evaluator"), ("Metrics", "metrics")):
            definitions = schema.get("$defs", {})
            candidate = next((n for n in definitions if n.lower().startswith(name.lower())), None)
            if candidate:
                try:
                    jsonschema.Draft202012Validator(
                        {"$ref": "#/$defs/" + candidate, "$defs": definitions}
                    ).validate(summary[key])
                except jsonschema.ValidationError:
                    raise Invalid("P008-SUMMARY-SUBCONTRACT") from None
        summary = {k: summary[k] for k in required - {"results"}}
        # IDs of critical/flaky samples can reveal sealed sample-level information.
        summary["metrics"] = {
            k: v
            for k, v in summary["metrics"].items()
            if k not in {"critical_sample_ids", "flaky_sample_ids"}
        }
        summary["evaluator"] = {
            k: v
            for k, v in summary["evaluator"].items()
            if k
            in {
                "evaluator_id",
                "version",
                "provider",
                "model",
                "model_version",
                "tool",
                "tool_version",
                "adapter_version",
                "implementation_digest",
                "network",
                "schema_version",
            }
        }
    imported = {
        "contract": "p009-p008-import-v1",
        "status": "REFERENCE_ONLY",
        "run_id": run_id,
        "evidence_manifest_digest": manifest,
        "summary": summary,
        "source_digest": digest(read(path)),
        "excluded": ["all sample results", "raw prompts", "outputs", "traces", "sealed outcomes"],
        "limitations": ["Actual p008-handoff-1.0 metadata only; referenced telemetry is not supplied."],
    }
    assert_safe(imported)
    return imported


def p006_event(config: Config, payload: dict, source_time: str):
    """Consume actual PEP JSON shape; subject/tenant are mapped, never used as authority."""
    event_type = payload.get("event")
    if event_type == "authorization":
        if set(payload) != {
            "event",
            "decision_id",
            "policy_version",
            "reason",
            "subject",
            "tenant",
            "action",
            "model",
        }:
            raise Invalid("P006-AUTHORIZATION-SHAPE")
        if payload["tenant"] not in {"tenant-a", "tenant-b"}:
            raise Invalid("P006-TENANT-UNMAPPED")
        source = config.source("p006-" + payload["tenant"][-1])
        # Exact P006 reason values come from the inspected policy; do not invent an allow field.
        decision = (
            "allow"
            if payload["reason"] == "ALLOW"
            else "deny"
            if payload["reason"] in {"DEFAULT_DENY", "TENANT_DENIED", "ROLE_DENIED", "MODEL_DENIED"}
            else "unknown"
        )
        safe = {
            "event_id": "p006-" + payload["decision_id"],
            "event_type": "authorization",
            "event_time": source_time,
            "authorization_decision_id": payload["decision_id"],
            "policy_version": payload["policy_version"],
            "decision": decision,
            "operation": payload["action"],
            "model_ref": payload["model"],
        }
    elif event_type == "request_failed":
        if set(payload) != {"event", "request_id"}:
            raise Invalid("P006-FAILURE-SHAPE")
        # Failure record lacks tenant: caller must not guess it. Quarantine outside the archive.
        raise Invalid("P006-FAILURE-TENANT-UNAVAILABLE")
    else:
        raise Invalid("P006-EVENT-UNSUPPORTED")
    return normalize(source, safe, "source-adapter")


def wazuh_alert(config: Config, value: dict):
    """Project a controlled native alert; native severity must match our versioned rule."""
    from p009.detection import candidates
    from p009.models import Event

    data = dict(value.get("data", {}))
    if isinstance(data.get("count"), str) and re.fullmatch(r"[0-9]{1,7}", data["count"]):
        data["count"] = int(data["count"])
    matches = candidates(data)
    if len(matches) != 1 or str(matches[0].rule_id) != value.get("rule", {}).get("id"):
        raise Invalid("WAZUH-RULE-REFERENCE")
    rule = matches[0]
    if value["rule"].get("level") != rule.severity:
        raise Invalid("WAZUH-LEVEL-MISMATCH")
    payload = {
        "event_id": "wazuh-" + digest(value["id"].encode())[:24],
        "event_type": "alert",
        "event_time": value["timestamp"],
        "related_event_id": data["event_id"],
        "alert_id": value["id"],
        "wazuh_rule_id": str(rule.rule_id),
        "signal": rule.signal,
        "count": int(data["count"]),
        "artifact_ref": digest(canonical(data)),
    }
    for key in ("request_id", "trace_id"):
        if data.get(key):
            payload[key] = data[key]
    event = normalize(config.source("wazuh-a"), payload, "source-adapter")
    return Event.model_validate({**event.model_dump(mode="json"), "event_severity": rule.severity})
