"""Pinned exact AISVS references and explicitly nonconformant OSCAL mapping."""

import json
import re
from pathlib import Path

import jsonschema
import regex

from p003 import NOTICE
from p003.util import digest, uid

DATA = Path(__file__).parent / "data"


def sources():
    value = json.loads((DATA / "sources.json").read_text())
    for item in value.values():
        for path, expected in item["sha256"].items():
            if digest((DATA / path).read_bytes()) != expected:
                raise ValueError("pinned framework source checksum mismatch")
    return value


def catalog() -> dict:
    sources()
    rows = {}
    for line in (DATA / "aisvs/C05.md").read_text().splitlines():
        m = re.fullmatch(r"\| \*\*(5\.\d+\.\d+)\*\* \| (.*?) \| ([123]) \|", line)
        if m:
            key = "v1.01-C" + m[1]
            rows[key] = {
                "requirement_id": key,
                "exact_text": m[2],
                "level": int(m[3]),
                "source": "OWASP AISVS",
                "version": "1.01",
            }
    if not rows:
        raise ValueError("pinned AISVS source format changed")
    return rows


def verify_requirement(req):
    actual = catalog().get(req.requirement_id)
    if actual is None or any(getattr(req, key) != value for key, value in actual.items()):
        raise ValueError("unknown or altered pinned AISVS requirement")


def oscal_errors(value) -> list[str]:
    sources()
    schema = json.loads((DATA / "oscal/assessment-plan-1.2.3.schema.json").read_text())
    checker = jsonschema.FormatChecker()

    @checker.checks("regex", raises=regex.error)
    def unicode_pattern(value):
        return not isinstance(value, str) or bool(regex.compile(value))

    def pattern(validator, expression, instance, schema):
        if isinstance(instance, str) and regex.search(expression, instance) is None:
            yield jsonschema.ValidationError("value fails official OSCAL pattern")

    # NIST uses Unicode properties (\\p{L}, \\p{N}); Python re does not support them.
    # Preserve the official schema bytes and validate with a Unicode-aware engine.
    jsonschema.Draft7Validator.check_schema(schema, format_checker=checker)
    cls = jsonschema.validators.extend(jsonschema.Draft7Validator, {"pattern": pattern})
    validator = cls(schema, format_checker=checker)
    return sorted(
        {str(e.validator) + ": " + "/".join(map(str, e.absolute_path)) for e in validator.iter_errors(value)}
    )


def oscal_draft(spec):
    """No SSP/control catalog is fabricated to satisfy superficial AP validation."""
    from p003.models import Artifact, sealed

    metadata = sealed(
        Artifact,
        id=uid(spec.content_digest + ":oscal"),
        source="p003 oscal mapping",
        author=spec.author,
        reviewer=None,
        created_at=spec.created_at,
    ).model_dump(mode="json")
    value = {
        **metadata,
        "kind": "oscal-mapping-draft",
        "conformance": "NOT VALID OSCAL",
        "official_schema_version": sources()["oscal"]["version"],
        "engagement_id": spec.engagement_id,
        "engagement_version": spec.version,
        "policy_digest": spec.content_digest,
        "coverage": [
            {"source": "goals, window", "oscal_field": "metadata, tasks", "status": "partial"},
            {"source": "asset inventory", "oscal_field": "assessment-subjects", "status": "partial"},
            {"source": "requirements", "oscal_field": "reviewed-controls", "status": "unmapped"},
            {"source": "none", "oscal_field": "import-ssp.href", "status": "UNSUPPORTED: no validated SSP"},
            {"source": "approvals", "oscal_field": "legal authority", "status": "not established"},
        ],
        "planned_requirements": [r.model_dump(mode="json") for r in spec.requirements],
        "missing_prerequisites": [
            "validated synthetic SSP",
            "referenced OSCAL control catalog",
            "assessment-subject and task semantic mapping",
        ],
        "validation": {"expected": "REJECT by official AP schema", "observed": "NOT RUN"},
    }
    errors = oscal_errors(value)
    value["validation"].update(observed="REJECT" if errors else "UNEXPECTED ACCEPT", errors=errors)
    value["content_digest"] = digest({k: v for k, v in value.items() if k != "content_digest"})
    return value


def framework_report():
    return {
        "notice": NOTICE,
        "sources": sources(),
        "aisvs": list(catalog().values()),
        "oscal_mode": "oscal-mapping-draft; NOT VALID OSCAL",
    }
