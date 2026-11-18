"""Data boundaries, canonical serialization, and confined source reads."""

import hashlib
import html
import json
import os
import re
import stat
import unicodedata
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
MAX_INPUT = 4 * 1024 * 1024
MAX_RECORD = 8 * 1024 * 1024
PRIVACY_VERSION: Final = "p010-minimization-1.0"
HASH_LIMIT = "SHA-256 checks byte consistency. Source authenticity, trusted time and independent custody are unverified."

_SECRET = re.compile(
    r"P0(?:08|09|10)_(?:DUMMY_SECRET|HOLDOUT|SECRET|PII)[\w.-]*"
    r"|(?<![A-Za-z0-9._-])(?:gh[pousr]_|github_pat_|sk-(?:proj-)?|sk_lf_|pk_lf_|pk-lf-)[A-Za-z0-9_-]{12,}"
    r"|AKIA[A-Z0-9]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\b(?:bearer|basic)\s+[A-Za-z0-9._+/=-]{12,}"
    r"|\b(?:api[ _-]?key|password|cookie|secret[ _-]?key)\s*[:=]\s*['\"]?\S+"
    r"|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"
    r"|\b\d{3}-\d{2}-\d{4}\b",
    re.IGNORECASE,
)
_PROHIBITED_KEYS = {
    "apikey",
    "authorizationheader",
    "clientsecret",
    "cookie",
    "credentials",
    "labelkey",
    "password",
    "privatekey",
    "prompt",
    "judgeprompt",
    "completion",
    "rawarguments",
    "rawlog",
    "rawoutput",
    "rawpayload",
    "rawprompt",
    "rawtrace",
    "sealedholdout",
    "sealedresults",
    "token",
}
_PLACEHOLDER = re.compile(r"\b(?:TODO|TBD|UNFILLED|PLACEHOLDER|INSERT HERE)\b", re.IGNORECASE)
_SAFE_PATH_PART = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
_MARKDOWN = re.compile(r"""[\\\x60*_{}\[\]()#+!|~:./@=$]""")


class Invalid(ValueError):
    """An error carrying a short non-sensitive operator-facing reason."""


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)", value
    ):
        raise Invalid("Expected a UTC timestamp")
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise Invalid("Invalid UTC timestamp") from None


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("Duplicate JSON field")
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    raise Invalid("Nonfinite JSON number")


def parse(raw: bytes, *, limit: int = MAX_INPUT) -> Any:
    if len(raw) > limit:
        raise Invalid("Input exceeds the byte limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)
        _bound(value, 0)
        return value
    except (RecursionError, UnicodeError, json.JSONDecodeError):
        raise Invalid("Invalid or excessively nested UTF-8 JSON") from None


def _bound(value: Any, depth: int) -> None:
    if depth > 32:
        raise Invalid("Input exceeds the nesting limit")
    if isinstance(value, dict):
        if len(value) > 4_096 or any(len(k) > 256 for k in value):
            raise Invalid("Input fields exceed limits")
        for child in value.values():
            _bound(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 4_096:
            raise Invalid("Input list exceeds the limit")
        for child in value:
            _bound(child, depth + 1)
    elif isinstance(value, str) and len(value) > 256 * 1024:
        raise Invalid("Input text exceeds the limit")


def relative_parts(value: str) -> tuple[str, ...]:
    parts = PurePosixPath(value).parts
    if (
        not parts
        or len(parts) > 20
        or "/".join(parts) != value
        or any(_SAFE_PATH_PART.fullmatch(part) is None or part in {".", ".."} for part in parts)
    ):
        raise Invalid("Unsafe artifact path")
    return parts


def checked_path(path: Path) -> Path:
    if ".." in path.parts:
        raise Invalid("Parent traversal is refused")
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise Invalid("Symlinks are refused")
    return path


def read(path: Path, *, limit: int = MAX_INPUT, missing: bool = False) -> bytes | None:
    """Use directory descriptors so changing a parent to a symlink cannot redirect the read."""
    path = checked_path(path)
    parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise Invalid("Input must be a bounded regular file")
            raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise Invalid("Input exceeds the byte limit")
            return raw
    except FileNotFoundError:
        if missing:
            return None
        raise Invalid("Input file is unavailable") from None
    except OSError:
        raise Invalid("Input file cannot be safely opened") from None
    finally:
        os.close(parent_fd)


def load(path: Path, *, limit: int = MAX_INPUT) -> Any:
    raw = read(path, limit=limit)
    assert raw is not None
    return parse(raw, limit=limit)


def safe_text(value: str) -> str:
    if any(
        unicodedata.category(char).startswith("C") and char not in "\n\t" for char in value
    ) or _SECRET.search(unicodedata.normalize("NFKC", value)):
        raise Invalid("Privacy policy rejected sensitive or unsafe text")
    return value


def redact_text(value: str) -> str:
    redacted = _SECRET.sub("[REDACTED]", unicodedata.normalize("NFKC", value))
    return safe_text(redacted)


def privacy_check(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            safe_text(key)
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            if normalized in _PROHIBITED_KEYS:
                raise Invalid("Privacy policy rejected a prohibited field")
            privacy_check(child)
    elif isinstance(value, list):
        for child in value:
            privacy_check(child)
    elif isinstance(value, str):
        safe_text(value)


def report_text(value: str) -> str:
    safe_text(value)
    # Numeric entities and Markdown escaping stop autolinks, HTML, headings and tables.
    value = html.escape(value, quote=True).replace("\n", " ").replace("\t", " ")
    return _MARKDOWN.sub(lambda match: "&#" + str(ord(match[0])) + ";", value)


def is_placeholder(value: str) -> bool:
    return _PLACEHOLDER.search(value) is not None


def select(value: dict[str, Any], keys: str) -> dict[str, Any]:
    return {key: value[key] for key in keys.split() if key in value}
