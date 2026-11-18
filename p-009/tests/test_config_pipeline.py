import pytest

from p009.auth import Authenticator
from p009.config import Config
from p009.ingest import Pipeline
from p009.models import SourceEvent
from p009.safety import Denied, Invalid, canonical, parse, read, write_new


@pytest.mark.parametrize(
    "field,value",
    [
        ("capture_content", True),
        ("debug", True),
        ("exporter", "http://example.invalid"),
        ("langfuse_exporter", "http://127.0.0.1/admin"),
        ("queue_size", 65),
        ("max_batch", 33),
        ("max_events", 5001),
        ("max_payload", 65537),
        ("unknown_security_option", True),
    ],
)
def test_configuration_security_bounds(cfg, field, value):
    data = cfg.model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValueError):
        Config.model_validate(data)


def test_unknown_source_rejected(cfg, archive, producer):
    pipeline = Pipeline(archive, cfg)
    with pytest.raises(Invalid):
        pipeline.submit("forged", {}, producer)
    assert pipeline.metrics["rejected"] == 1 and not pipeline.queue


def test_source_credential_tenant_binding(cfg, archive, producer):
    pipeline = Pipeline(archive, cfg)
    with pytest.raises(Invalid):
        pipeline.submit("synthetic-b", {}, producer)


def test_payload_size_bound_before_queue(cfg, archive, producer):
    pipeline = Pipeline(archive, cfg)
    with pytest.raises(Invalid):
        pipeline.submit("synthetic-a", {"prompt": "x" * 65537}, producer)
    assert not pipeline.queue


def test_batch_bound(cfg, archive, producer):
    with pytest.raises(Invalid):
        Pipeline(archive, cfg).batch("synthetic-a", canonical([{}] * 33), producer)


def test_bad_batch_cannot_leave_partially_accepted_events(cfg, archive, producer):
    pipeline = Pipeline(archive, cfg)
    good = {"event_id": "one", "event_type": "request", "event_time": "2026-11-16T12:00:00Z"}
    with pytest.raises(Invalid):
        pipeline.batch("synthetic-a", canonical([good, {**good, "event_id": "P009_CANARY"}]), producer)
    assert not pipeline.queue and not archive.manifests()
    assert pipeline.metrics["accepted"] == 0


def test_queue_saturation_visible_and_sanitized(cfg, archive, producer):
    cfg = Config.model_validate({**cfg.model_dump(mode="json"), "queue_size": 1})
    pipeline = Pipeline(archive, cfg)
    row = {"event_id": "one", "event_type": "request", "event_time": "2026-11-16T12:00:00Z"}
    pipeline.submit("synthetic-a", row, producer)
    with pytest.raises(Invalid):
        pipeline.submit("synthetic-a", {**row, "event_id": "two"}, producer)
    assert pipeline.metrics["queue_full"] == 1 and len(pipeline.queue) == 1


def test_export_outage_retains_queue_for_retry(cfg, archive, producer, monkeypatch):
    pipeline = Pipeline(archive, cfg)
    pipeline.submit(
        "synthetic-a",
        {"event_id": "one", "event_type": "request", "event_time": "2026-11-16T12:00:00Z"},
        producer,
    )
    original = archive.put_event

    def fail(*_):
        raise OSError("untrusted provider detail")

    monkeypatch.setattr(archive, "put_event", fail)
    with pytest.raises(Invalid, match="ARCHIVE-EXPORT-FAILED"):
        pipeline.flush()
    assert len(pipeline.queue) == 1 and pipeline.metrics["export_failed"] == 1
    monkeypatch.setattr(archive, "put_event", original)
    assert pipeline.flush()[0]["status"] == "ACCEPTED" and not pipeline.queue


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"x":NaN}', b"[]garbage", b"\xff"])
def test_malformed_or_ambiguous_json_refused(raw):
    with pytest.raises(Invalid):
        parse(raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("trace_id", "0" * 32),
        ("span_id", "0" * 16),
        ("trace_id", "a" * 31),
        ("event_time", "2026-11-16T12:00:00"),
        ("event_time", "2026-11-16T12:00:00+01:00"),
        ("sequence", -1),
    ],
)
def test_source_semantic_constraints(field, value):
    with pytest.raises(ValueError):
        SourceEvent.model_validate(
            {"event_id": "one", "event_type": "request", "event_time": "2026-11-16T12:00:00Z", field: value}
        )


def test_authentication_returns_bound_identity(operator):
    auth = Authenticator({"synthetic-token": operator})
    assert auth.authenticate("Bearer synthetic-token") == operator
    assert "synthetic-token" not in auth.bindings


@pytest.mark.parametrize("header", ["", "Bearer forged-token", "Basic invalid"])
def test_invalid_authentication_denied(operator, header):
    with pytest.raises(Denied):
        Authenticator({"synthetic-token": operator}).authenticate(header)


def test_oversized_file_read_refused(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b"x" * 20)
    with pytest.raises(Invalid):
        read(path, limit=10)


def test_atomic_publish_leaves_single_link(tmp_path):
    path = tmp_path / "record.json"
    write_new(path, canonical({"record": 1}))
    assert path.stat().st_nlink == 1 and sorted(p.name for p in tmp_path.iterdir()) == ["record.json"]
