"""One staged native case with preserved source identifiers and explicit provenance."""

import json
from uuid import uuid4

from p009.adapters import wazuh_alert
from p009.archive import Archive
from p009.config import config
from p009.correlate import timeline
from p009.exports import export
from p009.models import Event, Principal
from p009.normalize import normalize
from p009.safety import ROOT, Invalid, canonical, digest, load, read, write_new


def source_reference():
    files = sorted(
        (ROOT / ".runtime/live-artifacts").glob("langfuse-*.json"), key=lambda p: p.stat().st_mtime
    )
    if files:
        value = load(files[-1])
        return value["executed_source"], value
    from p009.live import synthetic

    return synthetic(), None


def preserve(alert, raw_event: str, source: dict, langfuse_record: dict | None):
    from p009.live import probe

    result = probe(
        "archive", "/timeline", method="POST", body={"trace_id": source["trace_id"]}, auth="operator"
    )
    if result["status"] != 200:
        raise Invalid("NATIVE-CASE-TRACE-UNAVAILABLE")
    core = json.loads(result["body"])
    if len(core.get("events", [])) < 6:
        raise Invalid("NATIVE-CASE-TRACE-INCOMPLETE")
    cfg = config()
    folder = ROOT / ".runtime/native-cases" / uuid4().hex
    archive = Archive(folder, digest(cfg), digest(read(ROOT / "compose.yaml")))
    producer = Principal(actor="native-collector", tenant="tenant-a", role="producer")
    operator = Principal(actor="native-custodian", tenant="tenant-a", role="custodian")
    for value in core["events"]:
        archive.put_event(Event.model_validate(value), producer)
    data = json.loads(raw_event)
    source_event = normalize(
        cfg.source("synthetic-a"),
        {
            "event_id": data["event_id"],
            "event_type": "security",
            "event_time": data["event_time"],
            "trace_id": source["trace_id"],
            "request_id": source["request_id"],
            "signal": data["signal"],
            "count": data["count"],
            "decision": "deny",
            "artifact_ref": digest(raw_event.encode()),
        },
        "synthetic-executed",
    )
    archive.put_event(source_event, producer)
    native_alert = wazuh_alert(cfg, alert)
    archive.put_event(native_alert, producer)
    if langfuse_record is not None:
        archive.put_import(
            {
                "contract": "p009-langfuse-observations-v2",
                "product_version": "4.80.0",
                "trace_id": source["trace_id"],
                "observations": langfuse_record["observations"],
            },
            "langfuse-api",
            producer,
            source_version="4.80.0",
        )
    events = [Event.model_validate(v) for v in archive.records(operator)]
    case = timeline(events, operator, case_id="p009-native-case", query={"trace_id": source["trace_id"]})
    if not any(link.key == "related_event_id" for link in case.links):
        raise Invalid("NATIVE-CASE-ALERT-LINK-ABSENT")
    write_new(folder / "timeline.json", canonical(case))
    exported = export(archive, operator)
    return {
        "archive": str(folder),
        "trace_id": source["trace_id"],
        "events": len(events),
        "langfuse_observations": len(langfuse_record["observations"]) if langfuse_record else 0,
        "native_wazuh_alert": native_alert.alert_id,
        "raw_synthetic_event_sha256": digest(raw_event.encode()),
        "integrity": archive.verify(),
        "export": exported,
        "interpretation": "controlled synthetic associations; no finding or confirmed incident",
    }
