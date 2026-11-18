"""Deterministic offline exercise. Does not claim live product or source execution."""

from pathlib import Path

from p009.adapters import import_p007, import_p008, p006_event
from p009.archive import Archive
from p009.config import config
from p009.correlate import timeline
from p009.exports import export
from p009.ingest import Pipeline
from p009.models import Event, Principal
from p009.safety import REPO, ROOT, Invalid, canonical, digest, read, write_new


def demo(path: Path):
    cfg = config()
    archive = Archive(path, digest(cfg), digest(read(ROOT / "compose.yaml")))
    producer = Principal(actor="fixture-a", tenant="tenant-a", role="producer")
    operator = Principal(actor="operator-a", tenant="tenant-a", role="custodian")
    pipeline = Pipeline(archive, cfg)
    types = ["request", "authorization", "tool", "completion"]
    for index, kind in enumerate(types):
        value = {
            "event_id": "demo-" + kind,
            "event_type": kind,
            "event_time": f"2026-11-16T12:00:0{index}Z",
            "request_id": "demo-request",
            "trace_id": "a" * 32,
            "span_id": f"{index + 1:016x}",
            "tool_call_id": "demo-tool",
            "authorization_decision_id": "demo-decision",
            "decision": "allow",
            "sequence": index,
            "prompt": "P009_PROMPT_CANARY",
            "cookie": "P009_COOKIE_CANARY",
        }
        if index == 3:
            value["event_time"] = "2026-11-16T11:59:59Z"
            value["sequence"] = 4
        pipeline.submit("synthetic-a", value, producer, "synthetic-fixture")
    pipeline.flush()
    pipeline.submit(
        "synthetic-a",
        {
            "event_id": "demo-request",
            "event_type": "request",
            "event_time": "2026-11-16T12:00:00Z",
            "request_id": "demo-request",
            "trace_id": "a" * 32,
            "span_id": "0000000000000001",
            "tool_call_id": "demo-tool",
            "authorization_decision_id": "demo-decision",
            "decision": "allow",
            "sequence": 0,
        },
        producer,
    )
    pipeline.flush()
    imported = import_p007(REPO / "p-007/examples/report-export.example.json")
    archive.put_import(imported, "p007-export", producer)
    imported8 = import_p008(ROOT / "fixtures/p008-handoff.json")
    archive.put_import(imported8, "p008-export", producer)
    p006 = p006_event(
        cfg,
        {
            "event": "authorization",
            "decision_id": "p006-decision",
            "policy_version": "p006-authz-v1",
            "reason": "ALLOW",
            "subject": "synthetic-subject",
            "tenant": "tenant-a",
            "action": "chat",
            "model": "local-basic",
        },
        "2026-11-16T12:00:00Z",
    )
    archive.put_event(p006, producer)
    rows = [Event.model_validate(v) for v in archive.records(operator)]
    result = timeline(rows, operator)
    write_new(path / "timeline.json", canonical(result))
    # A disposable separate archive proves detection without mutating the retained archive.
    disposable = Archive(path / "tamper-demo")
    ref = disposable.put_event(rows[0], producer)
    object_path = disposable.path / "objects" / (ref["sha256"] + ".json")
    object_path.write_bytes(b"{}\n")
    detected = False
    try:
        disposable.verify()
    except Invalid:
        detected = True
    return {
        "status": "PASS",
        "mode": "synthetic-fixtures-offline",
        "events": len(rows),
        "duplicates": pipeline.metrics["duplicate"],
        "out_of_order": len(result.out_of_order),
        "missing_sequences": result.missing_sequences,
        "tamper_detected": detected,
        "p006_authorization": p006.correlation_status,
        "p007": imported["status"],
        "p008": "labelled synthetic contract fixture; metadata only",
        "integrity": archive.verify(),
        "export": export(archive, operator),
    }
