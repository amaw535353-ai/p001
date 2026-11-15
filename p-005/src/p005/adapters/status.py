"""Fail-closed native integration capability reporting. No imported code execution."""

import importlib.metadata
import shutil

from p005.domain.schemas import AdapterResult
from p005.evidence.safety import Invalid


def statuses(source_digest=None) -> list[dict]:
    rows = []
    for name in ("threat-dragon", "pytm", "threagile"):
        version = None
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pass
        present = bool(version or shutil.which(name))
        rows.append(
            AdapterResult(
                tool=name,
                version=version,
                source_digest=source_digest,
                warnings=[
                    "Installed candidate lacks reviewed version/schema/sandbox"
                    if present
                    else "Tool not installed",
                    "No native export or execution claimed; use canonical JSON, Mermaid and DOT",
                ],
                unsupported_fields=["All canonical fields pending verified version-specific mapping"],
                evidence_ref="docs/tool-adapter-compatibility.md",
            ).model_dump()
        )
    return rows


def refuse_native() -> None:
    raise Invalid(
        "NATIVE-ADAPTER-BLOCKED: no reviewed compatible schema and execution sandbox; no Python executed"
    )
