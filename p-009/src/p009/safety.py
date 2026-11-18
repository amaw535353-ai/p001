"""Bounded, no-follow filesystem operations. Never include input in error messages."""

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
MAX_BYTES = 1_048_576


class Invalid(ValueError):
    pass


class Denied(Invalid):
    pass


class Blocked(Invalid):
    pass


def canonical(value) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"
    ).encode()


def digest(value) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def parse(raw: bytes):
    if len(raw) > MAX_BYTES:
        raise Invalid("PAYLOAD-BOUND")

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise Invalid("DUPLICATE-JSON-KEY")
            out[k] = v
        return out

    try:
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid("NONFINITE-JSON")),
        )
    except (ValueError, RecursionError, UnicodeError):
        raise Invalid("JSON-INVALID") from None


def parts(relative: str) -> list[str]:
    value = relative.split("/")
    if not value or any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,150}", p) or p in {".", ".."} for p in value
    ):
        raise Invalid("PATH-INVALID")
    return value


@contextmanager
def directory(path: Path, create: bool = False):
    """Walk from / using directory FDs; intermediate symlinks are rejected too."""
    absolute = path.absolute()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:]:
            if component in {".", ".."}:
                raise Invalid("PATH-INVALID")
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        yield fd
    except OSError:
        raise Invalid("FILESYSTEM-REFUSED") from None
    finally:
        os.close(fd)


def read(path: Path, limit: int = MAX_BYTES) -> bytes:
    with directory(path.parent) as parent:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_nlink != 1:
                    raise Invalid("FILE-BOUND-OR-TYPE")
                raw = os.read(fd, limit + 1)
                if len(raw) > limit:
                    raise Invalid("FILE-BOUND")
                return raw
            finally:
                os.close(fd)
        except OSError:
            raise Invalid("FILE-REFUSED") from None


def load(path: Path):
    return parse(read(path))


def write_new(path: Path, raw: bytes) -> None:
    if len(raw) > MAX_BYTES:
        raise Invalid("FILE-BOUND")
    with directory(path.parent, create=True) as fd:
        # A temporary file is fully flushed before atomic, no-overwrite publication.
        import uuid

        temporary = ".publish-" + uuid.uuid4().hex
        temp = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(temp, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            except FileExistsError:
                raise Invalid("CREATION-COLLISION") from None
            os.fsync(fd)
        finally:
            os.unlink(temporary, dir_fd=fd)


def relative_read(root: Path, relative: str) -> bytes:
    return read(root.joinpath(*parts(relative)))
