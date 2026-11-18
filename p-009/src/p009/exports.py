"""Scoped, verified local handoff. No P010 findings or downstream-consumer claim."""

from collections import Counter
from uuid import uuid4

from p009.archive import Archive
from p009.models import Handoff, Principal, now
from p009.privacy import assert_safe
from p009.safety import MAX_BYTES, Invalid, canonical, load, write_new


def export(archive: Archive, principal: Principal) -> dict:
    archive.authorize(principal, "export")
    with archive.lock():
        archive.verify()
        deleted = archive.deleted()
        manifests = [
            (d, m)
            for d, m in archive.manifests()
            if m.tenant_ref == principal.tenant and m.object.sha256 not in deleted
        ]
        events = [
            load(archive.path / "objects" / (m.object.sha256 + ".json"))
            for _, m in manifests
            if m.object.kind == "event"
        ]
        imports = [
            load(archive.path / "objects" / (m.object.sha256 + ".json"))
            for _, m in manifests
            if m.object.kind == "import"
        ]
        counts: Counter = Counter()
        for item in imports:
            if "report" in item:
                counts.update(r["status"] for r in item["report"]["results"])
            elif item.get("summary"):
                counts[item["summary"]["status"]] += 1
        handoff = Handoff(
            tenant_ref=principal.tenant,
            manifest_digests=[d for d, _ in manifests],
            objects=[m.object for _, m in manifests],
            status_counts=dict(counts),
            source_provenance={m.source_id: m.source_version for _, m in manifests},
            telemetry_coverage={
                "local_archive": "PASS",
                "langfuse": "NOT_TESTED",
                "wazuh": "NOT_TESTED",
                "p006-live": "NOT_TESTED",
            },
            limitations=[
                "Synthetic evidence; no independently verified client findings.",
                "Local digests do not authenticate source, time or privileged-host history.",
                "P007 artifact bytes absent unless an explicit run-root was verified.",
                "P008 is metadata-only; P010 consumption NOT_TESTED.",
            ],
        )
        assert_safe(handoff)
        folder = archive.path / "exports" / uuid4().hex
        files = {
            "owner.json": canonical({"owner": "p009", "tenant": principal.tenant, "time": now()}),
            "handoff.json": canonical(handoff),
            "events.json": canonical(events),
            "imports.json": canonical(imports),
            "timeline.md": (
                "# Synthetic telemetry evidence\n\n"
                + "\n".join(
                    f"- {e['event_time']} {e['source_id']} {e['event_type']} {e['event_id']}" for e in events
                )
                + "\n\nAssociations require exact shared identifiers; time order alone is not causality.\n"
            ).encode(),
        }
        if any(len(raw) > MAX_BYTES for raw in files.values()):
            raise Invalid("EXPORT-PAYLOAD-BOUND")
        for name, raw in files.items():
            write_new(folder / name, raw)
        archive.audit(principal, "export", "ALLOW", len(events))
        return {
            "status": "PASS",
            "path": str(folder),
            "events": len(events),
            "imports": len(imports),
            "consumer": "NOT_TESTED",
        }
