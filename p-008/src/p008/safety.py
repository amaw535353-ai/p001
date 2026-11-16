"""Bounded data I/O and local resource policy. No data-driven execution."""

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

import yaml

PROJECT = Path(__file__).resolve().parents[2]
REPO = PROJECT.parent
MAX_BYTES = 4194304


class Invalid(ValueError):
    """A structured validation/integrity failure."""


class Blocked(Invalid):
    """A required capability is unavailable; never a passing check."""


def canonical(value: Any) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def bounded(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [120000]
    budget[0] -= 1
    if depth > 24 or budget[0] < 0:
        raise Invalid("STRUCTURE-LIMIT")
    if isinstance(value, dict):
        if len(value) > 2048:
            raise Invalid("OBJECT-LIMIT")
        for k, v in value.items():
            if not isinstance(k, str) or len(k) > 256:
                raise Invalid("INVALID-OBJECT-KEY")
            bounded(v, depth + 1, budget)
    elif isinstance(value, list):
        if len(value) > 1280:
            raise Invalid("ARRAY-LIMIT")
        for v in value:
            bounded(v, depth + 1, budget)
    elif isinstance(value, str) and len(value) > 8192:
        raise Invalid("CONTENT-LIMIT")


def safe_path(base: Path, *parts: str) -> Path:
    base = base.absolute()
    for part in parts:
        if Path(part).is_absolute() or ".." in Path(part).parts:
            raise Invalid("PATH-TRAVERSAL")
    path = base.joinpath(*parts)
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise Invalid("SYMLINK-REFUSED")
    if not path.is_relative_to(base):
        raise Invalid("PATH-OUTSIDE-OWNED-ROOT")
    return path


def identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", value):
        raise Invalid("INVALID-ID")
    return value


def read_bytes(path: Path) -> bytes:
    safe_path(path.parent, path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if os.fstat(stream.fileno()).st_size > MAX_BYTES:
            raise Invalid("FILE-LIMIT")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise Invalid("FILE-LIMIT")
    return data


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("DUPLICATE-JSON-KEY")
        result[key] = value
    return result


def load(path: Path):
    raw = read_bytes(path).decode("utf-8", errors="strict")
    try:
        if path.suffix in (".yaml", ".yml"):
            # Anchors/aliases can construct exponentially shared graphs even with SafeLoader.
            if any(isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for t in yaml.scan(raw)):
                raise Invalid("YAML-ALIASES-REFUSED")
            value = yaml.safe_load(raw)
        elif path.suffix == ".json":
            value = json.loads(
                raw,
                object_pairs_hook=unique_pairs,
                parse_constant=lambda x: (_ for _ in ()).throw(Invalid("NONFINITE-JSON")),
            )
        else:
            raise Invalid("ONLY-JSON-OR-SAFE-YAML")
        bounded(value)
    except (RecursionError, yaml.YAMLError, json.JSONDecodeError) as exc:
        raise Invalid("MALFORMED-OR-OVERSIZED-DATA") from exc
    return value


def write_new(path: Path, data: bytes) -> None:
    safe_path(path.parent, path.name)
    if len(data) > MAX_BYTES:
        raise Invalid("OUTPUT-LIMIT")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def source_hashes() -> dict[str, str]:
    hashes = {
        str(p.relative_to(PROJECT)): digest(read_bytes(p))
        for p in sorted((PROJECT / "src/p008").rglob("*"))
        if p.is_file() and p.suffix in (".py", ".cjs")
    }
    for path in sorted((PROJECT / "config").rglob("*.yaml")):
        hashes[str(path.relative_to(PROJECT))] = digest(read_bytes(path))
    return hashes


def implementation(name: str) -> str:
    return digest(read_bytes(PROJECT / "src/p008" / name))
