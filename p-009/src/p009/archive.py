"""Content-addressed objects and atomic chained manifests, under a trusted local custodian."""

import fcntl
import os
import re
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4
from typing import Literal

from p009.models import Event, Manifest, ObjectRef, Principal, Retention, now
from p009.privacy import assert_safe
from p009.safety import ROOT, Denied, Invalid, canonical, digest, directory, load, read, write_new


class Archive:
    def __init__(
        self,
        path: Path,
        config_digest: str = "0" * 64,
        deployment_digest: str = "0" * 64,
        max_events: int = 5000,
    ):
        self.path = path.absolute()
        if ROOT.parent in self.path.parents and ROOT not in self.path.parents:
            raise Denied("SIBLING-ARCHIVE-REFUSED")
        self.config_digest, self.deployment_digest, self.max_events = (
            config_digest,
            deployment_digest,
            max_events,
        )
        with directory(self.path, create=True) as fd:
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise Denied("ARCHIVE-PERMISSIONS")
            if not (self.path / "owner.json").exists():
                if os.listdir(fd):
                    raise Denied("UNOWNED-ARCHIVE")
                write_new(self.path / "owner.json", canonical({"owner": "p009", "version": "1.0"}))
        if load(self.path / "owner.json") != {"owner": "p009", "version": "1.0"}:
            raise Denied("UNOWNED-ARCHIVE")
        for folder in ("objects", "manifests", "audit", "deletions", "exports"):
            with directory(self.path / folder, create=True):
                pass

    @contextmanager
    def lock(self):
        with directory(self.path) as root:
            fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=root)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def audit(self, principal: Principal, action: str, outcome: str, count: int = 0):
        write_new(
            self.path / "audit" / (uuid4().hex + ".json"),
            canonical(
                {
                    "owner": "p009",
                    "time": now(),
                    "actor": principal.actor,
                    "tenant": principal.tenant,
                    "role": principal.role,
                    "action": action,
                    "outcome": outcome,
                    "count": count,
                }
            ),
        )

    def authorize(self, principal: Principal, action: str):
        permitted = {
            "read": {"viewer", "exporter", "custodian"},
            "export": {"exporter", "custodian"},
            "delete": {"custodian"},
            "ingest": {"producer", "custodian"},
        }[action]
        if principal.role not in permitted:
            self.audit(principal, action, "DENY")
            raise Denied("ACCESS-DENIED")

    def manifests(self) -> list[tuple[str, Manifest]]:
        with directory(self.path / "manifests") as fd:
            names = sorted(os.listdir(fd))
        if len(names) > self.max_events:
            raise Invalid("ARCHIVE-BOUND")
        result = []
        previous = None
        for number, name in enumerate(names, 1):
            if not re.fullmatch(r"\d{8}-[a-f0-9]{64}\.json", name):
                raise Invalid("MANIFEST-NAME")
            raw = read(self.path / "manifests" / name)
            try:
                item = Manifest.model_validate_json(raw)
            except ValueError:
                raise Invalid("MANIFEST-CONTRACT") from None
            hashed = digest(raw)
            if name != f"{number:08d}-{hashed}.json" or item.sequence != number or item.previous != previous:
                raise Invalid("MANIFEST-CHAIN-MISMATCH")
            previous = hashed
            result.append((hashed, item))
        return result

    def deleted(self) -> set[str]:
        removed: set[str] = set()
        with directory(self.path / "deletions") as fd:
            names = os.listdir(fd)
        for name in names:
            if not re.fullmatch(r"[a-f0-9]{64}\.json", name):
                raise Invalid("DELETION-NAME")
            item = load(self.path / "deletions" / name)
            if digest(item) != name[:-5] or set(item) != {"owner", "time", "tenant", "actor", "objects"}:
                raise Invalid("DELETION-INTEGRITY")
            if item["owner"] != "p009" or not all(re.fullmatch(r"[a-f0-9]{64}", d) for d in item["objects"]):
                raise Invalid("DELETION-CONTRACT")
            # Tombstones must refer only to existing manifests of their own tenant.
            owned = {m.object.sha256 for _, m in self.manifests() if m.tenant_ref == item["tenant"]}
            if not set(item["objects"]) <= owned:
                raise Invalid("DELETION-OWNERSHIP")
            removed.update(item["objects"])
        return removed

    def verify(self) -> dict:
        manifests = self.manifests()
        deleted = self.deleted()
        checked = 0
        for _, manifest in manifests:
            ref = manifest.object
            path = self.path / "objects" / (ref.sha256 + ".json")
            if ref.sha256 in deleted:
                # An interrupted purge may leave bytes; this is visible, never a deletion PASS.
                if path.exists():
                    raise Invalid("PURGE-INCOMPLETE")
                continue
            raw = read(path)
            if len(raw) != ref.size or digest(raw) != ref.sha256:
                raise Invalid("OBJECT-INTEGRITY-MISMATCH")
            if ref.kind == "event":
                event = Event.model_validate_json(raw)
                if event.tenant_ref != manifest.tenant_ref or event.source_id != manifest.source_id:
                    raise Invalid("OBJECT-MANIFEST-MISMATCH")
            assert_safe(load(path))
            checked += 1
        return {
            "status": "PASS",
            "objects_verified": checked,
            "manifests_verified": len(manifests),
            "deleted_objects": len(deleted),
            "assurance": "digest consistency; no source authenticity, trusted time or WORM",
        }

    def put_event(self, event: Event, principal: Principal) -> dict:
        self.authorize(principal, "ingest")
        if event.tenant_ref != principal.tenant:
            self.audit(principal, "ingest", "DENY")
            raise Denied("TENANT-DENIED")
        with self.lock():
            self.verify()
            for _, m in self.manifests():
                if m.object.kind != "event" or m.object.sha256 in self.deleted():
                    continue
                old = Event.model_validate_json(read(self.path / "objects" / (m.object.sha256 + ".json")))
                if (old.source_id, old.event_id, old.tenant_ref) == (
                    event.source_id,
                    event.event_id,
                    event.tenant_ref,
                ):
                    if old.source_event_digest != event.source_event_digest:
                        self.audit(principal, "replay", "CONFLICT")
                        raise Invalid("EVENT-ID-CONFLICT")
                    self.audit(principal, "replay", "DUPLICATE")
                    return {"status": "DUPLICATE", "sha256": m.object.sha256}
            return self._store(
                event.model_dump(mode="json"),
                "event",
                event.tenant_ref,
                event.source_id,
                event.source_version,
                event.event_time,
            )

    def put_import(
        self, value: dict, source_id: str, principal: Principal, source_version: str = "1.0"
    ) -> dict:
        self.authorize(principal, "ingest")
        with self.lock():
            self.verify()
            return self._store(value, "import", principal.tenant, source_id, source_version, now())

    def _store(
        self,
        value: dict,
        kind: Literal["event", "import"],
        tenant: Literal["tenant-a", "tenant-b"],
        source_id: str,
        version: str,
        stamp: str,
    ) -> dict:
        assert_safe(value)
        manifests = self.manifests()
        if len(manifests) >= self.max_events:
            raise Invalid("ARCHIVE-CAPACITY")
        raw = canonical(value)
        object_hash = digest(raw)
        write_new(self.path / "objects" / (object_hash + ".json"), raw)
        ref = ObjectRef(sha256=object_hash, size=len(raw), kind=kind)
        manifest = Manifest(
            sequence=len(manifests) + 1,
            previous=manifests[-1][0] if manifests else None,
            created_at=now(),
            tenant_ref=tenant,
            object=ref,
            source_id=source_id,
            source_version=version,
            source_event_time=stamp,
            config_digest=self.config_digest,
            deployment_digest=self.deployment_digest,
        )
        hashed = digest(manifest)
        write_new(self.path / "manifests" / f"{manifest.sequence:08d}-{hashed}.json", canonical(manifest))
        return {"status": "ACCEPTED", "sha256": object_hash, "manifest_sha256": hashed}

    def records(self, principal: Principal, kind: str = "event") -> list[dict]:
        self.authorize(principal, "read")
        with self.lock():
            self.verify()
            deleted = self.deleted()
            values = [
                load(self.path / "objects" / (m.object.sha256 + ".json"))
                for _, m in self.manifests()
                if m.tenant_ref == principal.tenant
                and m.object.kind == kind
                and m.object.sha256 not in deleted
            ]
            self.audit(principal, "read", "ALLOW", len(values))
            return values

    def retention(
        self, principal: Principal, policy: Retention, apply: bool = False, stamp: str | None = None
    ):
        self.authorize(principal, "delete" if apply else "read")
        current = datetime.fromisoformat(stamp or now())
        with self.lock():
            self.verify()
            removed = self.deleted()
            candidates = []
            for _, m in self.manifests():
                if m.tenant_ref != principal.tenant or m.object.sha256 in removed or m.object.kind != "event":
                    continue
                event = Event.model_validate_json(read(self.path / "objects" / (m.object.sha256 + ".json")))
                # Retention uses trusted collection time; a forged source time cannot force deletion.
                days = getattr(policy, event.event_category + "_days")
                if datetime.fromisoformat(m.created_at) + timedelta(days=days) < current:
                    candidates.append(m.object.sha256)
            exports = []
            for name in os.listdir(self.path / "exports"):
                if not re.fullmatch(r"[a-f0-9]{32}", name):
                    raise Invalid("EXPORT-NAME")
                folder = self.path / "exports" / name
                owner = load(folder / "owner.json")
                if owner["owner"] != "p009":
                    raise Invalid("EXPORT-OWNERSHIP")
                if (
                    owner["tenant"] == principal.tenant
                    and datetime.fromisoformat(owner["time"]) + timedelta(days=policy.export_days) < current
                ):
                    exports.append(folder)
            self.audit(principal, "retention", "APPLY" if apply else "AUDIT", len(candidates))
            if apply and candidates:
                deletion = {
                    "owner": "p009",
                    "time": now(),
                    "tenant": principal.tenant,
                    "actor": principal.actor,
                    "objects": sorted(candidates),
                }
                write_new(self.path / "deletions" / (digest(deletion) + ".json"), canonical(deletion))
                with directory(self.path / "objects") as fd:
                    for hashed in candidates:
                        os.unlink(hashed + ".json", dir_fd=fd)
            if apply:
                for folder in exports:
                    with directory(folder) as fd:
                        names = os.listdir(fd)
                        if set(names) != {
                            "owner.json",
                            "handoff.json",
                            "events.json",
                            "imports.json",
                            "timeline.md",
                        }:
                            raise Invalid("EXPORT-CLEANUP-REFUSED")
                        for name in names:
                            read(folder / name)
                        for name in names:
                            os.unlink(name, dir_fd=fd)
                    os.rmdir(folder)
            return {
                "candidate_objects": len(candidates),
                "candidate_exports": len(exports),
                "applied": apply,
                "downstream_deletion": "NOT_TESTED",
                "residual": "manifests, access audits, tombstones; downstream stores have separate lifecycle",
            }
