"""Bounded data handling, redaction and symlink-aware local files."""

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

PROJECT = Path(__file__).resolve().parents[2]
REPO = PROJECT.parent
MAX_INPUT = 1_048_576


class Invalid(ValueError):
    """Structured operator error: messages never include untrusted payload values."""


class Blocked(Invalid):
    pass


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def safe_path(root: Path, relative: str = ".") -> Path:
    root = root.absolute()
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts:
        raise Invalid("PATH-TRAVERSAL")
    target = root / part
    if any(p.is_symlink() for p in (target, *target.parents)):
        raise Invalid("SYMLINK-FORBIDDEN")
    return target


def read_bytes(path: Path, limit: int = MAX_INPUT) -> bytes:
    safe_path(path.parent, path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise Invalid("INPUT-SIZE-LIMIT")
    return data


def load(path: Path) -> Any:
    try:
        return json.loads(read_bytes(path))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid("INVALID-JSON") from exc


def write_new(path: Path, data: bytes) -> None:
    """Publish a complete file atomically without replacing an existing artifact."""
    from uuid import uuid4

    safe_path(path.parent, path.name)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".tmp-" + uuid4().hex
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


SENSITIVE = re.compile(r"(?i)(authorization|cookie|token|password|api[_-]?key|secret|credential)")
MARKERS = re.compile(r"P007_(?:SECRET|TOKEN|COOKIE)_[A-Za-z0-9_-]+|Bearer\s+[A-Za-z0-9._-]+", re.I)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        # This measured boolean is safe cookie metadata, not a cookie value.
        return {
            k: v
            if k == "cookie_httponly" and type(v) is bool
            else "[REDACTED]"
            if SENSITIVE.search(str(k))
            else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return MARKERS.sub("[REDACTED]", value)
    return value
