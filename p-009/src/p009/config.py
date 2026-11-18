"""Fixed local destinations and trusted source/tenant mappings."""

from typing import Literal

from pydantic import Field

from p009.models import Retention, Source, Strict
from p009.safety import ROOT, Invalid, load


class Config(Strict):
    schema_version: Literal["p009-config-1.0"] = "p009-config-1.0"
    capture_content: Literal[False] = False
    debug: Literal[False] = False
    exporter: Literal["http://collector:4318"] = "http://collector:4318"
    langfuse_exporter: Literal["http://langfuse-web:3000/api/public/otel"] = (
        "http://langfuse-web:3000/api/public/otel"
    )
    queue_size: int = Field(default=64, ge=1, le=64)
    max_batch: int = Field(default=32, ge=1, le=32)
    max_events: int = Field(default=5000, ge=1, le=5000)
    max_payload: int = Field(default=65536, ge=1024, le=65536)
    sources: list[Source] = Field(min_length=1, max_length=16)
    retention: Retention = Field(default_factory=Retention)

    def source(self, source_id: str) -> Source:
        matches = [s for s in self.sources if s.source_id == source_id]
        if len(matches) != 1:
            raise Invalid("UNKNOWN-OR-AMBIGUOUS-SOURCE")
        return matches[0]


def config() -> Config:
    return Config.model_validate(load(ROOT / "config/defaults.json"))
