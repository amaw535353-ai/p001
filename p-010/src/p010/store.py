"""Private SQLite records and a transactional, hash-linked audit history."""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal, TypeVar

from pydantic import Field, ValidationError

from p010.models import ID, RECORDS, SHA, Actor, Link, RecordKind, Strict, UTCStamp
from p010.safety import MAX_RECORD, Invalid, canonical, checked_path, digest, now, parse, privacy_check

Model = TypeVar("Model", bound=Strict)
SYSTEM = Actor(ref="p010-local-system", role="CUSTODIAN")
OWNER = b"P-010 workspace v1\n"

_SCHEMA = """
CREATE TABLE records (
    kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
    engagement TEXT NOT NULL, hash TEXT NOT NULL, envelope BLOB NOT NULL,
    PRIMARY KEY (kind, id, version)
) WITHOUT ROWID;
CREATE INDEX by_engagement ON records (engagement, kind, id, version);
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY, hash TEXT NOT NULL, envelope BLOB NOT NULL
);
PRAGMA user_version = 1;
"""


class Envelope(Strict):
    schema_version: Literal["p010-record-version-1.0"] = "p010-record-version-1.0"
    kind: RecordKind
    id: ID
    version: int = Field(ge=1)
    engagement_id: ID
    created_at: UTCStamp
    actor: Actor
    classification: Literal["SYNTHETIC_INTERNAL", "SENSITIVE_SOURCE_REFERENCE"] = "SYNTHETIC_INTERNAL"
    data: dict[str, Any]


class AuditEvent(Strict):
    schema_version: Literal["p010-audit-event-1.0"] = "p010-audit-event-1.0"
    sequence: int = Field(ge=1)
    previous: SHA | None
    at: UTCStamp
    actor: Actor
    engagement_id: ID
    operation: ID
    records: list[Link] = Field(default_factory=list, max_length=4000)
    previous_version: Link | None = None
    rationale: str


def validate(model: type[Model], value: Any) -> Model:
    try:
        return model.model_validate(value)
    except ValidationError as error:
        # Pydantic error text includes raw inputs. Keep the model name only.
        raise Invalid(f"Invalid {model.__name__} ({error.error_count()} validation errors)") from None


class Version:
    def __init__(self, envelope: Envelope, sha256: str):
        self.envelope = envelope
        self.sha256 = sha256
        self.data = validate(RECORDS[envelope.kind], envelope.data)

    @property
    def link(self) -> Link:
        return Link(
            kind=self.envelope.kind, id=self.envelope.id, version=self.envelope.version, sha256=self.sha256
        )

    def as_type(self, model: type[Model]) -> Model:
        if not isinstance(self.data, model):
            raise Invalid(f"Expected a {model.__name__} reference")
        return self.data

    def export(self) -> dict:
        return {"record": self.envelope.model_dump(mode="json"), "sha256": self.sha256}


class Workspace:
    """The OS workspace owner is the trust boundary for the application and its role registry."""

    def __init__(self, root: Path):
        self.root = checked_path(root)
        self.path = self.root / "consultancy.sqlite3"

    def _private(self, path: Path, *, directory: bool = False) -> None:
        checked_path(path)
        mode = path.stat()
        if (
            mode.st_uid != os.getuid()
            or mode.st_mode & 0o077
            or (not path.is_dir() if directory else not path.is_file() or mode.st_nlink != 1)
        ):
            raise Invalid("Workspace paths must be private and owned by the local operator")

    def init(self) -> None:
        if not self.root.exists():
            self.root.mkdir(mode=0o700)
        self._private(self.root, directory=True)
        marker = self.root / "owner"
        if not marker.exists():
            if any(self.root.iterdir()):
                raise Invalid("Refusing to initialize a populated unowned workspace")
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(OWNER)
        self._owned()
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self._private(self.path)
        with sqlite3.connect(self.path) as connection:
            if connection.execute("PRAGMA user_version").fetchone()[0] == 0:
                connection.executescript("BEGIN EXCLUSIVE;\n" + _SCHEMA + "\nCOMMIT;")

    def _owned(self) -> None:
        marker = self.root / "owner"
        try:
            self._private(self.root, directory=True)
            self._private(marker)
            if marker.stat().st_size != len(OWNER) or marker.read_bytes() != OWNER:
                raise Invalid("Workspace ownership marker mismatch")
        except FileNotFoundError:
            raise Invalid("Workspace is unavailable. Initialize it first.") from None

    @contextmanager
    def session(self) -> Iterator["Store"]:
        self._owned()
        self._private(self.path)
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=10)
        try:
            if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise Invalid("Unsupported workspace database version")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("BEGIN IMMEDIATE")
            yield Store(connection)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


class Store:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    @staticmethod
    def _version(row: tuple[str, str, int, str, str, bytes]) -> Version:
        kind, id_, version, engagement_id, sha256, raw = row
        if sha256 != digest(raw):
            raise Invalid("Stored record digest mismatch")
        envelope = validate(Envelope, parse(raw, limit=MAX_RECORD))
        if (kind, id_, version, engagement_id) != (
            envelope.kind,
            envelope.id,
            envelope.version,
            envelope.engagement_id,
        ):
            raise Invalid("Stored record identity mismatch")
        return Version(envelope, sha256)

    def latest(self, kind: RecordKind, id_: str, *, required: bool = True) -> Version | None:
        row = self.connection.execute(
            "SELECT * FROM records WHERE kind=? AND id=? ORDER BY version DESC LIMIT 1", (kind, id_)
        ).fetchone()
        if row is not None:
            return self._version(row)
        if required:
            raise Invalid(f"No current {kind} record with that ID")
        return None

    def current(self, kind: RecordKind, id_: str) -> Version:
        version = self.latest(kind, id_)
        assert version is not None
        return version

    def resolve(self, link: Link, engagement: str | None = None) -> Version:
        version = self.get(link.kind, link.id, link.version, engagement)
        if version.sha256 != link.sha256:
            raise Invalid("Record reference digest mismatch")
        return version

    def get(self, kind: RecordKind, id_: str, version: int, engagement: str | None = None) -> Version:
        row = self.connection.execute(
            "SELECT * FROM records WHERE kind=? AND id=? AND version=?", (kind, id_, version)
        ).fetchone()
        if row is None:
            raise Invalid("Record version is unavailable")
        found = self._version(row)
        if engagement is not None and found.envelope.engagement_id != engagement:
            raise Invalid("Cross-engagement reference refused")
        return found

    def versions(self, engagement: str, *, current: bool = False) -> list[Version]:
        where = (
            " AND version=(SELECT MAX(r.version) FROM records r WHERE r.kind=records.kind AND r.id=records.id)"
            if current
            else ""
        )
        rows = self.connection.execute(
            "SELECT * FROM records WHERE engagement=?" + where + " ORDER BY kind,id,version LIMIT 4001",
            (engagement,),
        ).fetchall()
        if len(rows) > 4000:
            raise Invalid("Engagement exceeds the record count limit")
        return [self._version(row) for row in rows]

    def save(
        self,
        kind: RecordKind,
        id_: str,
        engagement: str,
        data: Strict,
        actor: Actor,
        *,
        previous: Link | None = None,
        action: str,
        rationale: str,
        at: str | None = None,
    ) -> Version:
        existing = self.latest(kind, id_, required=False)
        if existing is not None and (
            existing.link != previous or existing.envelope.engagement_id != engagement
        ):
            raise Invalid("Record changed or already exists")
        if existing is None and previous is not None:
            raise Invalid("Previous version is unavailable")
        if (
            existing is None
            and self.connection.execute(
                "SELECT 1 FROM audit WHERE json_extract(envelope, '$.operation')='retention-purge' "
                "AND json_extract(envelope, '$.engagement_id')=?",
                (engagement,),
            ).fetchone()
        ):
            raise Invalid("Engagement was purged")
        if not isinstance(data, RECORDS[kind]):
            raise Invalid("Record kind does not match its schema")
        when = at or now()
        envelope = Envelope(
            kind=kind,
            id=id_,
            version=(previous.version + 1 if previous else 1),
            engagement_id=engagement,
            actor=actor,
            created_at=when,
            classification="SENSITIVE_SOURCE_REFERENCE"
            if kind in ("source", "evidence")
            else "SYNTHETIC_INTERNAL",
            data=data.model_dump(mode="json"),
        )
        fields = envelope.model_dump(mode="json")
        privacy_check(fields)
        raw = canonical(fields)
        if len(raw) > MAX_RECORD:
            raise Invalid("Stored record exceeds the byte limit")
        version = Version(envelope, digest(raw))
        self.connection.execute(
            "INSERT INTO records VALUES (?,?,?,?,?,?)",
            (kind, id_, envelope.version, engagement, version.sha256, raw),
        )
        self.audit(engagement, actor, action, rationale, records=[version.link], previous=previous, at=when)
        return version

    def audit(
        self,
        engagement: str,
        actor: Actor,
        operation: str,
        rationale: str,
        *,
        records: list[Link] | None = None,
        previous: Link | None = None,
        at: str | None = None,
    ) -> AuditEvent:
        head = self.connection.execute("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        event = AuditEvent(
            sequence=head[0] + 1 if head else 1,
            previous=head[1] if head else None,
            at=at or now(),
            actor=actor,
            engagement_id=engagement,
            operation=operation,
            records=records or [],
            previous_version=previous,
            rationale=rationale,
        )
        fields = event.model_dump(mode="json")
        privacy_check(fields)
        raw = canonical(fields)
        if len(raw) > MAX_RECORD:
            raise Invalid("Audit event exceeds the byte limit")
        self.connection.execute("INSERT INTO audit VALUES (?,?,?)", (event.sequence, digest(raw), raw))
        return event

    def audit_events(self) -> Iterator[AuditEvent]:
        previous = None
        for expected_seq, (seq, sha256, raw) in enumerate(
            self.connection.execute("SELECT * FROM audit ORDER BY seq"), 1
        ):
            event = validate(AuditEvent, parse(raw, limit=MAX_RECORD))
            if (
                seq != expected_seq
                or event.sequence != seq
                or event.previous != previous
                or digest(raw) != sha256
            ):
                raise Invalid("Audit chain or sequence mismatch")
            previous = sha256
            yield event

    def verify(self) -> dict:
        """Check coverage as well as byte hashes so removal of a live record is detectable."""
        expected: dict[tuple[str, str, int], str] = {}
        count = 0
        for event in self.audit_events():
            count += 1
            for link in event.records:
                key = (link.kind, link.id, link.version)
                if event.operation == "retention-purge":
                    if expected.pop(key, None) != link.sha256:
                        raise Invalid("Invalid retention tombstone")
                elif key not in expected:
                    expected[key] = link.sha256
                elif expected[key] != link.sha256:
                    raise Invalid("Conflicting digest in audit history")
        for row in self.connection.execute("SELECT * FROM records"):
            version = self._version(row)
            link = version.link
            if expected.pop((link.kind, link.id, link.version), None) != link.sha256:
                raise Invalid("Stored record has no matching audit evidence")
        if expected:
            raise Invalid("Audited record is missing")
        return {
            "status": "PASS",
            "events": count,
            "limitations": "Privileged rewriting or whole-store rollback requires an independent checkpoint to detect.",
        }
