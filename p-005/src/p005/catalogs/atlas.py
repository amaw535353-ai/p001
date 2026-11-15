"""Pinned official ATLAS v6 distribution; updates are explicit local-file operations."""

import re
from pathlib import Path

from p005.evidence.safety import DATA, Invalid, canonical, digest, load, parse, read, write


def validate(path: Path, metadata: dict | None = None) -> dict:
    meta = metadata or load(DATA / "atlas-pin.json")
    raw = read(path)
    if digest(raw) != meta["sha256"]:
        raise Invalid("ATLAS-CHECKSUM-MISMATCH")
    data = parse(raw)
    if not isinstance(data, dict) or data.get("format-version") != "6.1.0":
        raise Invalid("ATLAS-UNSUPPORTED-FORMAT")
    if (
        data["format-version"] != meta["format_version"]
        or data.get("collection", {}).get("version") != meta["content_version"]
    ):
        raise Invalid("ATLAS-VERSION-MISMATCH")
    required = {
        "format-version",
        "collection",
        "matrix",
        "tactics",
        "techniques",
        "mitigations",
        "case-studies",
        "entities",
        "software",
        "relationships",
    }
    if set(data) != required or not isinstance(data["techniques"], dict):
        raise Invalid("ATLAS-DISTRIBUTION-STRUCTURE")
    techniques = []
    for tid, row in data["techniques"].items():
        if (
            not re.fullmatch(r"AML\.T\d{4}(?:\.\d{3})?", tid)
            or row.get("id") != tid
            or row.get("object-type") != "technique"
            or not isinstance(row.get("name"), str)
            or not isinstance(row.get("description"), str)
        ):
            raise Invalid("ATLAS-INVALID-TECHNIQUE")
        techniques.append(dict(id=tid, name=row["name"]))
    return dict(
        schema_version="p005-atlas-index-1.0",
        content_version=meta["content_version"],
        format_version=meta["format_version"],
        source_sha256=meta["sha256"],
        techniques=sorted(techniques, key=lambda t: t["id"]),
    )


def index() -> dict:
    data = load(DATA / "atlas-index.json")
    pin = load(DATA / "atlas-pin.json")
    if digest(data) != pin["index_sha256"] or data["source_sha256"] != pin["sha256"]:
        raise Invalid("ATLAS-INDEX-INTEGRITY")
    if data["content_version"] != pin["content_version"] or data["format_version"] != pin["format_version"]:
        raise Invalid("ATLAS-INDEX-VERSION")
    return data


def validate_technique(tid: str) -> None:
    if tid not in {t["id"] for t in index()["techniques"]}:
        raise Invalid("ATLAS-UNVERIFIED-ID")


def mapping(threats: list[dict]) -> dict:
    pin = load(DATA / "atlas-pin.json")
    curated = load(DATA / "atlas-mappings.json")
    rows = []
    for threat in threats:
        entries = []
        for rid in threat["risk_ids"]:
            for match in curated.get(rid, []):
                validate_technique(match["technique_id"])
                entries.append(dict(risk_id=rid, **match, state="CANDIDATE_REVIEW"))
        rows.append(
            dict(
                threat_id=threat["threat_id"],
                status="CANDIDATE_REVIEW" if entries else "UNMAPPED",
                entries=entries,
                rationale="Human review required; catalog references are not attacks or findings",
            )
        )
    return dict(schema_version="p005-atlas-mapping-1.0", catalog=pin, mappings=rows)


def update_local(path: Path, metadata_path: Path, output: Path) -> dict:
    metadata = load(metadata_path)
    needed = {
        "source_url",
        "source_commit",
        "content_version",
        "format_version",
        "license",
        "sha256",
        "imported_utc",
    }
    if not needed <= set(metadata) or metadata["license"] != "Apache-2.0":
        raise Invalid("ATLAS-SOURCE-METADATA-REQUIRED")
    if not metadata["source_url"].startswith("https://raw.githubusercontent.com/mitre-atlas/atlas-data/"):
        raise Invalid("ATLAS-OFFICIAL-SOURCE-REFERENCE-REQUIRED")
    result = validate(path, metadata)
    write(output, canonical(dict(metadata=metadata, index=result)))
    return dict(
        status="VALIDATED_LOCAL_CANDIDATE",
        activated=False,
        reason="No network; bundled catalog unchanged. Review and pin in a separate source change",
    )
