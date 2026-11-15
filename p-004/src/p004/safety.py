"""Non-executing bounded inputs and deliberately lossy publication sanitization."""

import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import urlsplit

import yaml
from yaml.events import AliasEvent, CollectionStartEvent, CollectionEndEvent

MAX_BYTES = 2_000_000
MAX_NODES = 30_000
SENSITIVE = re.compile(
    r"token|secret|password|authorization|cookie|credential|private.?key|email|body|prompt|headers|session",
    re.I,
)
SECRET_VALUE = re.compile(
    r"(?i)bearer\s+[^\s\"<>]+|(?:sk-|ghp_|github_pat_)[a-z0-9_-]+|"
    r"(?:token|password|secret|api_key)\s*[=:]\s*[^\s,;]+|"
    r"-----BEGIN[^-]*PRIVATE KEY-----(?s:.*)",
)


class Invalid(ValueError):
    """Safe error code only; never echo untrusted input or secret-bearing exceptions."""


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def text(value: Any, limit=200) -> str:
    result = str(value)
    result = SECRET_VALUE.sub("[REDACTED]", result)
    result = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[REDACTED]@", result)
    result = re.sub(r"(?i)(https?://[^\s?#]+)[?#][^\s]*", r"\1", result)
    result = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[IDENTIFIER]", result)
    result = "".join(c for c in result if c.isascii() and 32 <= ord(c) < 127)
    return result[:limit]


def scrub(value: Any, depth=0) -> Any:
    if depth > 20:
        raise Invalid("DEPTH-LIMIT")
    if isinstance(value, dict):
        return {
            text(k): "[REDACTED]" if SENSITIVE.search(str(k)) else scrub(v, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [scrub(x, depth + 1) for x in value]
    if isinstance(value, str):
        return text(value, 2048)
    if value is None or type(value) in (bool, int, float):
        return value
    raise Invalid("UNSUPPORTED-DATA")


def markdown(value: str) -> str:
    return (
        html.escape(text(value))
        .replace("|", "&#124;")
        .replace("`", "&#96;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
    )


def diagram_label(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9 .:/_-]", "_", text(value))[:100]


def csv_cell(value: str) -> str:
    value = text(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def bounded_tree(value: Any) -> None:
    todo = [(value, 0)]
    count = 0
    while todo:
        item, depth = todo.pop()
        count += 1
        if count > MAX_NODES or depth > 20:
            raise Invalid("TREE-LIMIT")
        if isinstance(item, dict):
            if any(not isinstance(k, str) for k in item):
                raise Invalid("STRING-KEYS-REQUIRED")
            todo.extend((x, depth + 1) for x in item.values())
        elif isinstance(item, list):
            todo.extend((x, depth + 1) for x in item)


def unique_pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise Invalid("DUPLICATE-KEY")
        result[k] = v
    return result


class UniqueLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node):
    return unique_pairs(loader.construct_pairs(node))


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def decode(raw: bytes, suffix=".json") -> Any:
    if len(raw) > MAX_BYTES:
        raise Invalid("FILE-SIZE-LIMIT")
    try:
        if suffix in (".yaml", ".yml"):
            depth = count = 0
            for event in yaml.parse(raw):
                count += 1
                if isinstance(event, AliasEvent) or getattr(event, "anchor", None):
                    raise Invalid("YAML-ALIASES-FORBIDDEN")
                if isinstance(event, CollectionStartEvent):
                    depth += 1
                if isinstance(event, CollectionEndEvent):
                    depth -= 1
                if count > MAX_NODES or depth > 20:
                    raise Invalid("TREE-LIMIT")
            value = yaml.load(raw, Loader=UniqueLoader)
        else:
            value = json.loads(raw, object_pairs_hook=unique_pairs)
        bounded_tree(value)
        canonical(value)  # rejects NaN and non-JSON YAML types
        return value
    except (ValueError, TypeError, yaml.YAMLError, RecursionError, UnicodeError) as exc:
        raise Invalid("MALFORMED-OR-UNSAFE-INPUT") from exc


def contained(root: Path, relative: str | Path) -> Path:
    root = root.absolute()
    if any(p.is_symlink() for p in [root, *root.parents]):
        raise Invalid("SYMLINK-FORBIDDEN")
    rel = Path(relative)
    if len(str(relative)) > 512 or not str(relative).isascii() or any(ord(c) < 32 for c in str(relative)):
        raise Invalid("UNSUPPORTED-PATH-ENCODING")
    if rel.is_absolute() or ".." in rel.parts:
        raise Invalid("PATH-OUTSIDE-ROOT")
    target = root / rel
    if any(p.is_symlink() for p in [target, *target.parents]):
        raise Invalid("SYMLINK-FORBIDDEN")
    if not target.resolve().is_relative_to(root.resolve()):
        raise Invalid("PATH-OUTSIDE-ROOT")
    return target


def read_bytes(root: Path, relative: str | Path) -> bytes:
    path = contained(root, relative)
    # O_NOFOLLOW supplements the path checks; parents are trusted local boundaries.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Invalid("REGULAR-FILE-REQUIRED")
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise Invalid("FILE-SIZE-LIMIT")
    return raw


def load(root: Path, relative: str | Path) -> Any:
    return decode(read_bytes(root, relative), Path(relative).suffix)


def route(path: str) -> str:
    if len(path) > 512 or not re.fullmatch(r"/[A-Za-z0-9_~./:{}-]*", path):
        raise Invalid("INVALID-ROUTE")
    if "//" in path or any(x in (".", "..") for x in path.split("/")):
        raise Invalid("AMBIGUOUS-ROUTE")
    return path


def address(value: str) -> str:
    p = urlsplit(value)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise Invalid("INVALID-ADDRESS")
    if any(c in value for c in ("%", "\\")) or not value.isascii():
        raise Invalid("AMBIGUOUS-ADDRESS")
    host = p.hostname.lower()
    if not re.fullmatch(r"[a-z0-9.-]+|[0-9a-f:]+", host):
        raise Invalid("INVALID-HOST")
    port = p.port or (80 if p.scheme == "http" else 443)
    if not 1 <= port <= 65535:
        raise Invalid("INVALID-PORT")
    host = "[" + host + "]" if ":" in host else host
    return f"{p.scheme}://{host}:{port}{route(p.path or '/')}"
