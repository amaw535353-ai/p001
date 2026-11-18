import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from p009.archive import Archive
from p009.exports import export
from p009.models import Principal, Retention
from p009.safety import Denied, Invalid, canonical, digest, read, relative_read, write_new


def test_deterministic_object_digest(archive, event, producer):
    row = event()
    value = archive.put_event(row, producer)
    assert value["sha256"] == digest(row)


def test_manifest_exact_size_hash_and_provenance(archive, event, producer):
    row = event()
    archive.put_event(row, producer)
    hashed, manifest = archive.manifests()[0]
    assert manifest.object.size == len(canonical(row)) and manifest.object.sha256 == digest(row)
    assert manifest.source_id == row.source_id and manifest.redaction_policy == "p009-metadata-v1"
    assert len(hashed) == 64 and manifest.sequence == 1


def test_object_tamper_fails(archive, event, producer):
    value = archive.put_event(event(), producer)
    (archive.path / "objects" / (value["sha256"] + ".json")).write_bytes(b"{}\n")
    with pytest.raises(Invalid):
        archive.verify()


def test_manifest_tamper_fails(archive, event, producer):
    archive.put_event(event(), producer)
    path = next((archive.path / "manifests").iterdir())
    value = json.loads(path.read_bytes())
    value["source_id"] = "forged-source"
    path.write_bytes(canonical(value))
    with pytest.raises(Invalid):
        archive.verify()


def test_missing_middle_manifest_detected(archive, event, producer):
    for i in range(3):
        archive.put_event(event("event-" + str(i)), producer)
    sorted((archive.path / "manifests").iterdir())[1].unlink()
    with pytest.raises(Invalid):
        archive.verify()


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a/../../escape", "a//b", "a/./b"])
def test_traversal_refused(tmp_path, path):
    with pytest.raises(Invalid):
        relative_read(tmp_path, path)


def test_intermediate_symlink_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    write_new(target / "one.json", b"{}")
    (tmp_path / "link").symlink_to(target, target_is_directory=True)
    with pytest.raises(Invalid):
        read(tmp_path / "link/one.json")


def test_final_symlink_refused(tmp_path):
    write_new(tmp_path / "one.json", b"{}")
    (tmp_path / "link.json").symlink_to(tmp_path / "one.json")
    with pytest.raises(Invalid):
        read(tmp_path / "link.json")


def test_special_file_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(Invalid):
        read(tmp_path / "fifo")


def test_creation_collision_keeps_original(tmp_path):
    path = tmp_path / "one.json"
    write_new(path, b"original")
    with pytest.raises(Invalid):
        write_new(path, b"replacement")
    assert read(path) == b"original"


def test_duplicate_delivery_no_double_count(archive, event, producer):
    row = event()
    archive.put_event(row, producer)
    value = archive.put_event(row, producer)
    assert value["status"] == "DUPLICATE" and len(archive.manifests()) == 1
    assert any(
        json.loads(p.read_bytes())["outcome"] == "DUPLICATE" for p in (archive.path / "audit").iterdir()
    )


def test_same_event_id_changed_payload_rejected(archive, event, producer):
    archive.put_event(event(), producer)
    with pytest.raises(Invalid):
        archive.put_event(event(outcome="error"), producer)
    assert len(archive.manifests()) == 1


def test_concurrent_append_preserves_chain(archive, event, producer):
    rows = [event("parallel-" + str(i)) for i in range(8)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda e: archive.put_event(e, producer), rows))
    assert len(values) == 8 and archive.verify()["manifests_verified"] == 8


def test_tenant_read_filter(archive, event, producer):
    archive.put_event(event(), producer)
    other = Principal(actor="viewer-b", tenant="tenant-b", role="viewer")
    assert archive.records(other) == []


def test_producer_cannot_read_evidence(archive, producer):
    with pytest.raises(Denied):
        archive.records(producer)


def test_unauthorized_export_audited(archive):
    viewer = Principal(actor="viewer-a", tenant="tenant-a", role="viewer")
    with pytest.raises(Denied):
        export(archive, viewer)
    audit = [json.loads(p.read_bytes()) for p in (archive.path / "audit").iterdir()]
    assert any(x["action"] == "export" and x["outcome"] == "DENY" for x in audit)


def test_cross_tenant_ingest_denied(archive, event, producer):
    with pytest.raises(Denied):
        archive.put_event(event(source="synthetic-b"), producer)


def test_archive_capacity_failure(archive, event, producer):
    archive.max_events = 1
    archive.put_event(event(), producer)
    with pytest.raises(Invalid):
        archive.put_event(event("two"), producer)


def test_export_has_provenance_and_redaction(archive, event, producer, operator):
    archive.put_event(event(), producer)
    result = export(archive, operator)
    from pathlib import Path

    handoff = json.loads(read(Path(result["path"]) / "handoff.json"))
    assert handoff["source_provenance"]["synthetic-a"] == "1.0.0"
    assert handoff["redaction_policy"] == "p009-metadata-v1" and handoff["findings"] == []


def test_retention_dry_run_preserves_bytes(archive, event, producer, operator):
    archive.put_event(event(), producer)
    result = archive.retention(operator, Retention(), stamp="2030-01-01T00:00:00+00:00")
    assert result["candidate_objects"] == 1 and archive.verify()["objects_verified"] == 1


def test_retention_purges_scoped_objects_and_exports(archive, event, producer, operator):
    archive.put_event(event(), producer)
    export(archive, operator)
    other = Principal(actor="producer-b", tenant="tenant-b", role="producer")
    archive.put_event(event("two", source="synthetic-b"), other)
    result = archive.retention(operator, Retention(), True, "2030-01-01T00:00:00+00:00")
    assert result["candidate_objects"] == 1 and result["candidate_exports"] == 1
    assert archive.verify()["objects_verified"] == 1 and archive.verify()["deleted_objects"] == 1
    assert not list((archive.path / "exports").iterdir())


def test_future_source_time_cannot_prevent_collection_retention(archive, event, producer, operator):
    archive.put_event(event(event_time="2099-01-01T00:00:00Z"), producer)
    assert (
        archive.retention(operator, Retention(), stamp="2030-01-01T00:00:00+00:00")["candidate_objects"] == 1
    )


def test_unowned_archive_refused(tmp_path):
    folder = tmp_path / "foreign"
    folder.mkdir()
    (folder / "existing").write_text("preserve")
    with pytest.raises(Denied):
        Archive(folder)
    assert (folder / "existing").read_text() == "preserve"
