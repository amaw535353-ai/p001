"""Accept only IDs actually supported by the supplied source."""

from pydantic import Field

from p005.domain.schemas import Strict
from p005.evidence.safety import DATA, Invalid, load


class Risk(Strict):
    id: str
    description: str | None
    source: str
    available: bool


class RiskCatalog(Strict):
    schema_version: str
    source_status: str
    source_sha256: str
    entries: list[Risk] = Field(min_length=37, max_length=37)


def catalog() -> RiskCatalog:
    return RiskCatalog.model_validate(load(DATA / "risks.json"))


def validate_ids(ids: list[str]) -> None:
    entries = {r.id: r for r in catalog().entries}
    for rid in ids:
        if rid not in entries or not entries[rid].available:
            raise Invalid("RISK-ID-UNVERIFIED: see docs/source-attribution.md and the missing 37-risk source")
