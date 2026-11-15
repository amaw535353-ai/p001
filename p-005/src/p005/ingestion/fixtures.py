"""Offline fixture intake. No references are fetched or executed."""

from pathlib import Path

from p005 import __version__
from p005.domain.schemas import Model
from p005.evidence.safety import Invalid, digest, load, redact
from p005.modeling.graph import boundaries


def version(data) -> None:
    if not isinstance(data, dict):
        raise Invalid("MODEL-OBJECT-REQUIRED")
    if "schema_version" not in data:
        raise Invalid("MISSING-SCHEMA-VERSION")
    if data["schema_version"] != "p005-model-1.0":
        raise Invalid("INCOMPATIBLE-SCHEMA-VERSION")


def build(path: Path) -> Model:
    data = redact(load(path))
    version(data)
    source_hash = digest(data)
    # Validate BEFORE defaults/normalization; missing versions are never filled in.
    Model.model_validate(data)
    data["source_snapshot_hash"] = source_hash
    data["snapshot_source"] = path.name
    data["review_state"] = "DRAFT"
    data["tool_versions"]["p005"] = __version__
    for node in data["nodes"]:
        node["source_snapshot"] = source_hash
    for evidence in data["evidence"]:
        if evidence["source"] == "synthetic-fixture":
            evidence["sanitized_sha256"] = source_hash
    model = Model.model_validate(data)
    data["boundaries"] = [b.model_dump() for b in boundaries(model)]
    return Model.model_validate(data)


def read_model(path: Path) -> Model:
    data = redact(load(path))
    version(data)
    model = Model.model_validate(data)
    provided = {b.id: b for b in model.boundaries}
    for boundary in boundaries(model):
        if boundary.id not in provided:
            raise Invalid("MISSING-CANDIDATE-TRUST-BOUNDARY: rebuild model from source")
        actual = provided[boundary.id]
        if any(
            getattr(actual, key) != getattr(boundary, key)
            for key in ("zone_pair", "edge_ids", "reasons", "actor_ids")
        ):
            raise Invalid("INCONSISTENT-CANDIDATE-TRUST-BOUNDARY")
    return model
