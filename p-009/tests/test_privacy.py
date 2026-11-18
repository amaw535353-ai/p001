import pytest

from p009.ingest import Pipeline
from p009.models import SourceEvent
from p009.privacy import assert_safe, metadata
from p009.safety import Invalid, canonical


@pytest.mark.parametrize(
    "field,marker",
    [
        ("authorization", "Bearer P009_TOKEN_CANARY"),
        ("cookie", "session=P009_COOKIE_CANARY"),
        ("api_key", "sk-P009_PROVIDER_CANARY"),
        ("vault_token", "hvs.P009_VAULT_CANARY"),
        ("prompt", "P009_PROMPT_CANARY"),
        ("completion", "P009_COMPLETION_CANARY"),
        ("email", "synthetic@example.invalid"),
        ("request_body", {"private": "P009_BODY_CANARY"}),
        ("response_body", "P009_OUTPUT_CANARY"),
        ("private_key", "BEGIN PRIVATE" + " KEY"),
    ],
)
def test_sensitive_classes_removed_before_queue(field, marker, archive, cfg, producer):
    pipeline = Pipeline(archive, cfg)
    value = {
        "event_id": "privacy",
        "event_type": "request",
        "event_time": "2026-11-16T12:00:00Z",
        field: marker,
    }
    pipeline.submit("synthetic-a", value, producer)
    assert marker if isinstance(marker, str) else True
    queued = canonical(pipeline.queue[0][0])
    assert b"CANARY" not in queued and b"example.invalid" not in queued
    pipeline.flush()
    for file in archive.path.rglob("*.json"):
        assert b"CANARY" not in file.read_bytes()


def test_secret_in_allowed_identifier_fails_closed(archive, cfg, producer):
    pipeline = Pipeline(archive, cfg)
    with pytest.raises(Invalid):
        pipeline.submit(
            "synthetic-a",
            {"event_id": "P009_SECRET_CANARY", "event_type": "request", "event_time": "2026-11-16T12:00:00Z"},
            producer,
        )
    assert not pipeline.queue and not archive.manifests()


def test_source_identity_is_trusted_mapping(event):
    value = event(tenant_ref="tenant-b", actor_ref="forged-user", source_id="forged", event_severity=15)
    assert value.tenant_ref == "tenant-a" and value.actor_ref == "synthetic-operator-a"
    assert value.source_id == "synthetic-a" and value.event_severity == 0
    assert value.redacted_fields == 4


def test_redaction_policy_and_counter_recorded(event):
    value = event(prompt="discard")
    assert value.redaction_policy == "p009-metadata-v1" and value.redaction_status == "metadata-only"
    assert value.redacted_fields == 1


def test_unknown_fields_strict_on_source_contract():
    with pytest.raises(ValueError):
        SourceEvent(event_id="one", event_type="request", event_time="2026-11-16T12:00:00Z", arbitrary="bad")


@pytest.mark.parametrize(
    "marker",
    [
        "Bearer tokenvalue",
        "sk-1234567890",
        "hvs.1234567890",
        "a@example.invalid",
        "P008_HOLDOUT_sample",
        "cookie=secret",
        "line\nforged",
    ],
)
def test_unsafe_import_or_allowed_metadata_is_refused(marker):
    with pytest.raises(Invalid):
        assert_safe({"arbitrary": marker})


def test_missing_event_id_not_invented():
    with pytest.raises(Invalid):
        metadata({"event_type": "request", "event_time": "2026-11-16T12:00:00Z"})
