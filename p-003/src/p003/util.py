"""Bounded serialization, canonical hashes and conservative output handling."""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import yaml

_checkout = Path(__file__).resolve().parents[2]
ROOT = _checkout if (_checkout / "scripts/p003").is_file() else Path.cwd()
MAX_BYTES = 2 * 1024 * 1024
SENSITIVE = re.compile(
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?i:bearer\s+[A-Za-z0-9._-]{12,}|(?:password|api[_-]?key|secret[_-]?key)\s*[:=]\s*\S+)"
)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8", errors="strict")


def digest(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def uid(value: str) -> str:
    return str(uuid5(NAMESPACE_URL, "p003-synthetic:" + value))


def clock(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise ValueError("clock must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe(value: Any) -> None:
    text = canonical(value).decode()
    if SENSITIVE.search(text) or any(ord(c) < 32 for c in text):
        raise ValueError("unsafe content rejected; values omitted")


def unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate mapping key")
        out[key] = value
    return out


class UniqueLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node):
    return unique_pairs([(loader.construct_object(k), loader.construct_object(v)) for k, v in node.value])


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def load(path: Path) -> Any:
    if any(p.is_symlink() for p in [path, *path.parents]) or path.stat().st_size > MAX_BYTES:
        raise ValueError("symlink or oversized input")
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="strict")
    if path.suffix.lower() in (".yaml", ".yml"):
        tokens = list(yaml.scan(text))
        if len(tokens) > 100000 or any(isinstance(t, (yaml.AliasToken, yaml.AnchorToken)) for t in tokens):
            raise ValueError("YAML aliases/anchors are not accepted")
        value = yaml.load(text, Loader=UniqueLoader)
    else:
        value = json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
        )
    safe(value)
    return value


def write_output(path: Path, value: Any) -> None:
    """User-facing exports stay inside this component's generated directory."""
    root = ROOT / "generated"
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.resolve().is_relative_to(root.resolve()) or any(
        p.is_symlink() for p in [path, *path.parents]
    ):
        raise ValueError("export path must be under p-003/generated")
    safe(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ValueError("output exists; choose a new output path")
    path.write_text(
        value if isinstance(value, str) else json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    )
