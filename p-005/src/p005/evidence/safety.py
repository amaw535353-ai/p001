"""Bounded, non-executable data and no-follow filesystem operations."""

import hashlib
import json
import math
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any

import yaml

PROJECT = Path(__file__).resolve().parents[3]
REPO = PROJECT.parent
DATA = Path(__file__).resolve().parents[1] / "data"
MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 32
MAX_ITEMS = 120_000


class Invalid(ValueError):
    """A safe public error. Never include imported values in the message."""


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode()


def digest(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def stable(kind: str, *parts: Any) -> str:
    # Full SHA-256, with tenant/rule/edge/precondition inputs, avoids name disclosure.
    return kind + "-" + digest(parts)


def bounded(value: Any) -> Any:
    todo = [(value, 0)]
    count = 0
    while todo:
        item, depth = todo.pop()
        count += 1
        if count > MAX_ITEMS or depth > MAX_DEPTH:
            raise Invalid("DOCUMENT-BUDGET-EXCEEDED")
        if isinstance(item, dict):
            if any(not isinstance(k, str) for k in item):
                raise Invalid("STRING-KEYS-REQUIRED")
            todo.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            todo.extend((v, depth + 1) for v in item)
        elif item is not None and not isinstance(item, (str, bool, int, float)):
            raise Invalid("NON-JSON-DATA")
        if isinstance(item, float) and not math.isfinite(item):
            raise Invalid("NONFINITE-NUMBER")
        if isinstance(item, str) and len(item) > 32768:
            raise Invalid("TEXT-BUDGET-EXCEEDED")
    return value


def unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Invalid("DUPLICATE-MAPPING-KEY")
        obj[key] = value
    return obj


class DataLoader(yaml.SafeLoader):
    pass


# Never create datetime/date objects from imported YAML scalars.
DataLoader.yaml_implicit_resolvers = {
    key: [(tag, regex) for tag, regex in values if tag != "tag:yaml.org,2002:timestamp"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def yaml_map(loader, node):
    return unique_pairs(loader.construct_pairs(node, deep=True))


DataLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_map)


def parse(raw: bytes) -> Any:
    if len(raw) > MAX_BYTES:
        raise Invalid("FILE-SIZE-LIMIT")
    try:
        text = raw.decode("utf-8")
        if text.lstrip().startswith(("{", "[")):
            value = json.loads(
                text,
                object_pairs_hook=unique_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(Invalid("NONFINITE-NUMBER")),
            )
        else:
            depth = 0
            count = 0
            for event in yaml.parse(text, Loader=DataLoader):
                count += 1
                if getattr(event, "anchor", None) or isinstance(event, yaml.AliasEvent):
                    raise Invalid("YAML-ALIASES-ANCHORS-FORBIDDEN")
                if getattr(event, "tag", None):
                    raise Invalid("YAML-TAGS-FORBIDDEN")
                if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                    depth += 1
                if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                    depth -= 1
                if depth > MAX_DEPTH or count > MAX_ITEMS * 3:
                    raise Invalid("DOCUMENT-BUDGET-EXCEEDED")
            # YAML timestamps are strings, not Python datetime objects.
            value = yaml.load(text, Loader=DataLoader)
        return bounded(value)
    except (UnicodeError, yaml.YAMLError, json.JSONDecodeError, RecursionError) as exc:
        raise Invalid("INVALID-BOUNDED-JSON-OR-YAML") from exc


def _rooted(path: Path, roots: tuple[Path, ...]) -> tuple[Path, tuple[str, ...]]:
    # Do not resolve symlinks before validating the lexical path.
    if ".." in path.parts:
        raise Invalid("PATH-TRAVERSAL")
    full = path if path.is_absolute() else Path.cwd() / path
    for root in roots:
        try:
            parts = full.relative_to(root).parts
        except ValueError:
            continue
        if not parts or any(p in ("", ".", "..") for p in parts):
            raise Invalid("FILE-PATH-REQUIRED")
        if len(parts) > 16 or len(str(full)) > 2048:
            raise Invalid("PATH-BUDGET-EXCEEDED")
        return root, parts
    raise Invalid("PATH-OUTSIDE-APPROVED-ROOT")


def _parent_fd(root: Path, parts: tuple[str, ...], create: bool) -> int:
    # Walk *every* component with O_NOFOLLOW; refuse symlinks including parents.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in root.parts[1:] + parts[:-1]:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except OSError as exc:
        os.close(fd)
        raise Invalid("UNSAFE-OR-MISSING-PATH") from exc


def read(path: Path, roots: tuple[Path, ...] | None = None) -> bytes:
    root, parts = _rooted(path, roots or (REPO,))
    fd = _parent_fd(root, parts, False)
    try:
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise Invalid("REGULAR-FILE-REQUIRED")
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise Invalid("FILE-SIZE-LIMIT")
        return raw
    except OSError as exc:
        raise Invalid("UNSAFE-OR-MISSING-FILE") from exc
    finally:
        os.close(fd)


def load(path: Path) -> Any:
    return parse(read(path))


def write(path: Path, raw: bytes, *, replace: bool = True) -> None:
    root, parts = _rooted(path, (PROJECT / "generated", PROJECT / "evidence"))
    if len(raw) > MAX_BYTES:
        raise Invalid("EXPORT-SIZE-LIMIT")
    fd = _parent_fd(root, parts, True)
    temporary = None
    try:
        try:
            previous = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            previous = None
        if previous and not stat.S_ISREG(previous.st_mode):
            raise Invalid("REGULAR-OUTPUT-FILE-REQUIRED")
        if replace:
            temporary = ".p005-tmp-" + uuid.uuid4().hex
        name = temporary or parts[-1]
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_EXCL, 0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as stream:
            stream.write(raw)
        if temporary:
            os.replace(temporary, parts[-1], src_dir_fd=fd, dst_dir_fd=fd)
            temporary = None
    except OSError as exc:
        raise Invalid("UNSAFE-OUTPUT-OR-OUTPUT-EXISTS") from exc
    finally:
        if temporary:
            os.unlink(temporary, dir_fd=fd)
        os.close(fd)


SECRET = re.compile(
    r"(?i)(?:\b(?:sk-[a-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b|"
    r"Bearer\s+[a-z0-9._~+/-]{8,}|"
    r"(?:password|secret|api[_-]?key|token)\s*[:=]\s*[\"']?[^\s\"',;]{4,}|"
    r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|"
    r"https?://[^\s/@:]+:[^\s/@]+@[^\s]+)"
)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        value = re.sub(
            r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
            "REDACTED",
            value,
            flags=re.S,
        )
        return SECRET.sub("REDACTED", value)
    if isinstance(value, dict):
        if any(SECRET.search(k) for k in value):
            raise Invalid("SENSITIVE-MAPPING-KEY")
        sensitive = {"password", "secret", "api_key", "api-key", "token", "private_key"}
        return {
            k: "REDACTED"
            if k.lower() in sensitive
            or (k.lower() == "authorization" and v not in ("CONTROL_DECLARED", "UNKNOWN", "DISABLED"))
            else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
