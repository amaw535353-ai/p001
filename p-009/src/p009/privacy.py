"""Positive metadata allowlist before any queue or persistence; failures are closed."""

import re

from p009.models import SourceEvent
from p009.safety import Invalid, canonical

POLICY = "p009-metadata-v1"
PATTERNS = [
    r"(?i)bearer\s+\S+",
    r"(?i)(?:sk-|hvs\.|ghp_)[A-Za-z0-9_-]{8,}",
    r"(?i)(?:DUMMY_SECRET|CANARY|HOLDOUT_|PRIVATE.KEY|@|cookie[=:]|password[=:])",
    r"(?i)eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
]


def assert_safe(value) -> None:
    raw = canonical(value).decode()
    if any(re.search(pattern, raw) for pattern in PATTERNS) or "\\n" in raw.replace('\\n"', ""):
        # Newlines in arbitrary text are not part of the metadata contract.
        raise Invalid("PRIVACY-REFUSED")


def metadata(value: dict) -> tuple[SourceEvent, int]:
    if not isinstance(value, dict) or len(value) > 128:
        raise Invalid("SOURCE-BOUND")
    allowed = {k: v for k, v in value.items() if k in SourceEvent.model_fields}
    assert_safe(allowed)
    try:
        event = SourceEvent.model_validate(allowed)
    except ValueError:
        raise Invalid("SOURCE-CONTRACT") from None
    return event, len(value) - len(allowed)
