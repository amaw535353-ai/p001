"""Bounded synthetic preconditions, shared with actual Wazuh local rules."""

from typing import Literal

from pydantic import Field

from p009.models import Ref, Strict
from p009.safety import ROOT, Invalid, load


class Rule(Strict):
    rule_id: int = Field(ge=110900, le=110919)
    version: Literal["1.0"] = "1.0"
    signal: Ref
    minimum_count: int = Field(ge=1, le=100)
    severity: int = Field(ge=1, le=15)
    rationale: str


def rules() -> list[Rule]:
    return [Rule.model_validate(v) for v in load(ROOT / "config/detection-rules.json")]


def candidates(event: dict) -> list[Rule]:
    """Offline precheck only. An actual Wazuh alert requires native rule execution."""
    if set(event) - {
        "p009",
        "signal",
        "count",
        "event_id",
        "request_id",
        "trace_id",
        "severity",
        "event_time",
    }:
        raise Invalid("DETECTION-EVENT-CONTRACT")
    if (
        event.get("p009") != "v1"
        or type(event.get("count")) is not int
        or not 0 <= event["count"] <= 1_000_000
    ):
        raise Invalid("DETECTION-PRECONDITION")
    return [r for r in rules() if event["signal"] == r.signal and event["count"] >= r.minimum_count]
