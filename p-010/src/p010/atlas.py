"""Offline lookup of the actual MITRE ATLAS v6 distribution already pinned in P-005."""

from functools import lru_cache

import yaml

from p010.models import AtlasInput, AtlasMapping, Authorship, Finding
from p010.safety import REPO, Invalid, digest, read
from p010.workflow import Workflow

CATALOG_VERSION = "2026.10"
CATALOG_COMMIT = "f56c1468731d6428e5bf875263b4643b46d67437"
CATALOG_SHA256 = "ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d"
CATALOG_URL = (
    f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/{CATALOG_COMMIT}/dist/v6/ATLAS-2026.10.yaml"
)


@lru_cache(maxsize=1)
def techniques() -> dict:
    raw = read(REPO / "p-005/catalogs/ATLAS-pinned.yaml")
    assert raw is not None
    if digest(raw) != CATALOG_SHA256:
        raise Invalid("ATLAS pin mismatch")
    source = yaml.safe_load(raw)
    if source["format-version"] != "6.1.0" or source["collection"]["version"] != CATALOG_VERSION:
        raise Invalid("ATLAS catalog format or version mismatch")
    return {
        key: {
            "id": key,
            "title": row["name"],
            "description": row["description"],
            "url": f"https://atlas.mitre.org/techniques/{key}",
        }
        for key, row in source["techniques"].items()
        if row["id"] == key and row["object-type"] == "technique"
    }


def record(
    flow: Workflow, id_: str, finding_id: str, data: AtlasInput, rationale: str, authorship: Authorship
):
    flow.require("AUTHOR" if data.state == "CANDIDATE" else "REVIEWER")
    version = flow.current("finding", finding_id)
    finding = version.as_type(Finding)
    if finding.validation_status != "CONFIRMED":
        raise Invalid("ATLAS mappings require a confirmed finding")
    prior = flow.store.latest("atlas", id_, required=False)
    if prior:
        old = flow.current("atlas", id_).as_type(AtlasMapping)
        if old.finding.id != finding_id or old.technique_id != data.technique_id:
            raise Invalid("Use a new mapping ID for a different technique or finding")
        if old.state == "ACCEPTED":
            raise Invalid("Use a new review record to reassess a previously accepted mapping")
    elif data.state == "ACCEPTED":
        raise Invalid("Record a candidate or reviewed mapping before acceptance")
    decision = flow.decision(
        rationale, authorship, independent_of=finding.author_ref if data.state != "CANDIDATE" else None
    )
    technique = techniques().get(data.technique_id)
    for related in data.evidence_refs:
        flow.resolve(related)
    if data.state == "ACCEPTED" and (
        not technique
        or data.confidence == "UNKNOWN"
        or not data.evidence_refs
        or not set(data.evidence_refs) <= set(finding.validation.inspected_evidence)
    ):
        raise Invalid("ATLAS acceptance requires a pinned ID and evidence inspected for this finding")
    mapping = AtlasMapping(
        **data.model_dump(),
        finding=version.link,
        title=technique["title"] if technique else None,
        catalog_version=CATALOG_VERSION,
        catalog_commit=CATALOG_COMMIT,
        catalog_sha256=CATALOG_SHA256,
        catalog_url=CATALOG_URL,
        technique_url=technique["url"] if technique else None,
        review=decision,
    )
    return flow.save("atlas", id_, mapping, "atlas-review", rationale, prior.link if prior else None)


def catalog_status(mapping: AtlasMapping) -> str:
    current = techniques().get(mapping.technique_id)
    if current is None:
        return "UNRESOLVED_HISTORICAL"
    if mapping.title is not None and current["title"] != mapping.title:
        return "RENAMED_SINCE_REVIEW"
    return "PINNED"
