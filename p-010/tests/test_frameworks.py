"""Pinned framework semantics and Langfuse metadata-only contract behavior."""

import os
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid5

import pytest

from p010 import atlas, langfuse, oscal
from p010.demo import FINDING, REPORT, SIMULATED
from p010.models import AtlasInput, AtlasMapping, Finding, TraceReference
from p010.safety import ROOT, Invalid, canonical, digest, report_text
from p010.store import validate
from test_workflow import REASON, actors


def uuid(name):
    return str(uuid5(UUID("6d02e58c-3383-4a64-844b-83398a00ae2d"), "p010-testing-" + name))


@pytest.fixture
def context(tmp_path):
    folder = tmp_path / "oscal-context"
    folder.mkdir()
    control = "DEMO-C-CLASSIFICATION"
    meta = {
        "title": "Test-only synthetic input",
        "last-modified": "2026-11-15T08:00:00Z",
        "version": "1.0",
        "oscal-version": "1.2.3",
    }
    documents = {
        "catalog": {
            "catalog": {
                "uuid": uuid("catalog"),
                "metadata": meta,
                "controls": [
                    {
                        "id": control,
                        "title": "Synthetic metadata classification",
                        "parts": [
                            {
                                "id": "DEMO-REQ-CLASSIFICATION",
                                "name": "statement",
                                "prose": "Every row has a label.",
                            }
                        ],
                    }
                ],
            }
        },
        "ssp": {
            "system-security-plan": {
                "uuid": uuid("ssp"),
                "metadata": meta,
                "import-profile": {"href": "catalog.json"},
                "system-characteristics": {
                    "system-ids": [{"id": "TEST-1"}],
                    "system-name": "Synthetic fixture inventory",
                    "description": "Inert schema-validation fixture.",
                    "system-information": {
                        "information-types": [
                            {
                                "uuid": uuid("type"),
                                "title": "Synthetic row",
                                "description": "Synthetic data fixture.",
                                "confidentiality-impact": {"base": "low"},
                                "integrity-impact": {"base": "low"},
                                "availability-impact": {"base": "low"},
                            }
                        ]
                    },
                    "status": {"state": "operational"},
                    "authorization-boundary": {"description": "Fixture only."},
                },
                "system-implementation": {
                    "components": [
                        {
                            "uuid": uuid("component"),
                            "type": "software",
                            "title": "Synthetic static fixture",
                            "description": "No target access.",
                            "status": {"state": "operational"},
                        }
                    ]
                },
                "control-implementation": {
                    "description": "Synthetic local-only review.",
                    "implemented-requirements": [
                        {"uuid": uuid("requirement"), "control-id": control},
                    ],
                },
            }
        },
        "assessment-plan": {
            "assessment-plan": {
                "uuid": uuid("plan"),
                "metadata": meta,
                "import-ssp": {"href": "ssp.json"},
                "reviewed-controls": {
                    "control-selections": [
                        {
                            "include-controls": [
                                {
                                    "control-id": control,
                                    "statement-ids": ["DEMO-REQ-CLASSIFICATION"],
                                }
                            ]
                        }
                    ]
                },
                "tasks": [{"uuid": uuid("task"), "type": "action", "title": "Inspect the fixture"}],
            }
        },
    }
    for model, value in documents.items():
        (folder / f"{model}.json").write_bytes(canonical(value))
    return folder


@pytest.mark.parametrize("model", sorted(oscal.PIN))
def test_O01_official_schema_bytes_and_version(model):
    document, pin = oscal.official_schema(model)
    assert document["$id"] == pin["schema_id"]
    assert pin["sha256"] == digest((ROOT / "data/oscal" / (model + ".json")).read_bytes())
    assert pin["commit"] == "e061961c7702afeabffdf5e59894d35e748dade1"
    assert pin["version"] == "1.2.3"


def test_O02_pinned_schema_export_and_exact_references(example, context):
    with example.session() as store:
        author, _ = actors(store)
        report = store.current("report", REPORT)
        result = oscal.export(author, report, context)
        assert result.get("manifest", result)["conformance"] == "VALIDATED_LOCAL_SUBSET", result.get(
            "missing"
        )
        document = result["document"]
        actual = document["assessment-results"]["results"][0]
        assert actual["findings"][0]["target"]["target-id"] == "DEMO-REQ-CLASSIFICATION"
        assert (
            actual["findings"][0]["related-observations"][0]["observation-uuid"]
            == actual["observations"][0]["uuid"]
        )
        actual["findings"][0]["related-observations"][0]["observation-uuid"] = uuid("invalid-reference")
        assert (
            oscal.validate_document("assessment-results", document, context)["conformance"]
            == "NOT VALID OSCAL"
        )
        assert (
            oscal.validate_document("assessment-results", result["document"], None)["conformance"]
            == "SCHEMA_VALID_ONLY"
        )


def test_O03_O05_O10_missing_oscal_context_is_explicit(example):
    with example.session() as store:
        author, _ = actors(store)
        value = oscal.export(author, store.current("report", REPORT), None)
    assert value["kind"] == "oscal-mapping-draft" and value["conformance"] == "NOT VALID OSCAL"
    assert len(value["missing"]) == 2
    assert "POA&M generation" in value["unsupported"]
    assert any("certification" in limitation for limitation in value["limitations"])


def test_O06_atlas_pin_and_exact_identifiers():
    catalog = atlas.techniques()
    assert len(catalog) > 50 and len(atlas.CATALOG_COMMIT) == 40
    row = catalog["AML.T0051"]
    assert row["id"] == "AML.T0051" and row["title"] and row["description"]
    assert row["url"].endswith(row["id"])


def mapping(evidence, **changes) -> AtlasInput:
    return AtlasInput(
        **{
            "technique_id": "AML.T0051",
            "state": "CANDIDATE",
            "confidence": "LOW",
            "evidence_refs": evidence,
            "limitations": ["Training mapping workflow test. Technique relevance is hypothetical."],
            **changes,
        }
    )


def test_O07_O08_atlas_review_does_not_alter_finding(example):
    with example.session() as store:
        author, reviewer = actors(store)
        original = store.current("finding", FINDING)
        item = mapping(original.as_type(Finding).validation.inspected_evidence)
        with pytest.raises(Invalid):
            atlas.record(
                reviewer,
                "MAP-TEST",
                FINDING,
                item.model_copy(update={"state": "ACCEPTED"}),
                REASON,
                SIMULATED,
            )
        atlas.record(author, "MAP-TEST", FINDING, item, REASON, SIMULATED)
        atlas.record(
            reviewer, "MAP-TEST", FINDING, item.model_copy(update={"state": "REVIEWED"}), REASON, SIMULATED
        )
        accepted = atlas.record(
            reviewer, "MAP-TEST", FINDING, item.model_copy(update={"state": "ACCEPTED"}), REASON, SIMULATED
        )
        assert accepted.as_type(AtlasMapping).title == atlas.techniques()["AML.T0051"]["title"]
        assert store.current("finding", FINDING).link == original.link


def test_O09_historical_atlas_unknown_is_resolvable_as_unresolved(example):
    with example.session() as store:
        author, reviewer = actors(store)
        item = mapping([], technique_id="AML.T9999")
        old = atlas.record(author, "MAP-UNKNOWN", FINDING, item, REASON, SIMULATED).as_type(AtlasMapping)
        assert old.title is None and atlas.catalog_status(old) == "UNRESOLVED_HISTORICAL"
        with pytest.raises(Invalid):
            atlas.record(
                reviewer,
                "MAP-UNKNOWN",
                FINDING,
                item.model_copy(update={"state": "ACCEPTED"}),
                REASON,
                SIMULATED,
            )


def _trace(**changes):
    return validate(
        TraceReference,
        {
            "trace_id": "1" * 32,
            "observation_id": "2" * 16,
            "source_time": "2026-11-15T10:00:00Z",
            "project_ref": "demo-local",
            "source": "operator-provided",
            **changes,
        },
    )


def _binding(**changes):
    return langfuse.Binding(**{"project_ref": "demo-local", "project_id": "project-synthetic", **changes})


def test_L02_reference_only_default_and_blocked_api(monkeypatch):
    ref = _trace()
    result = langfuse.show(ref)
    assert result["status"] == "REFERENCE_ONLY" and result["live_api"] == "NOT_TESTED"
    with pytest.raises(Invalid, match="project binding"):
        langfuse.show(ref, port=3009)
    monkeypatch.setattr(
        langfuse, "_inspect", lambda *_: (_ for _ in ()).throw(Invalid("Service unavailable"))
    )
    result = langfuse.show(ref, port=3009, binding=_binding())
    assert result["live_api"] == "BLOCKED" and "local_link" not in result


def test_L03_L04_langfuse_response_projection(monkeypatch):
    monkeypatch.setenv("P010_LANGFUSE_PUBLIC_KEY", "pk-lf-fixture0123456789")
    monkeypatch.setenv("P010_LANGFUSE_SECRET_KEY", "sk-lf-fixtureABCDEFGHIJ")
    ref = _trace()
    calls = []

    def request(port, target, auth=None):
        calls.append((port, target, bool(auth)))
        if target.endswith("/health"):
            return {"version": langfuse.VERSION}
        return {
            "data": [
                {
                    "traceId": ref.trace_id,
                    "id": ref.observation_id,
                    "projectId": "project-synthetic",
                    "startTime": ref.source_time,
                    "input": "P010_SECRET_INPUT",
                    "output": "P010_PII_RESULT",
                    "metadata": {"token": "P010_SECRET_TRACE"},
                }
            ],
            "meta": {},
        }

    result = langfuse._inspect(ref, 3009, _binding(), request)
    assert result["status"] == "OBSERVED_REFERENCE"
    assert calls[0] == (3009, "/api/public/health", False)
    query = parse_qs(urlsplit(calls[1][1]).query)
    assert query["fields"] == ["time"] and query["traceId"] == [ref.trace_id]
    assert set(result["observations"][0]) == {"observation_id", "source_time"}
    assert b"P010_SECRET" not in canonical(result) and b"P010_PII" not in canonical(result)
    assert os.environ["P010_LANGFUSE_SECRET_KEY"].encode() not in canonical(result)


@pytest.mark.parametrize("mode", ["trace", "project", "time", "version", "metadata"])
def test_L03_langfuse_rejects_incompatible_response(mode, monkeypatch):
    monkeypatch.setenv("P010_LANGFUSE_PUBLIC_KEY", "pk-lf-fixture0123456789")
    monkeypatch.setenv("P010_LANGFUSE_SECRET_KEY", "sk-lf-fixtureABCDEFGHIJ")
    ref = _trace()
    row = {
        "traceId": ref.trace_id,
        "id": ref.observation_id,
        "projectId": "project-synthetic",
        "startTime": ref.source_time,
    }
    alteration = {
        "trace": {"traceId": "3" * 32},
        "project": {"projectId": "other"},
        "time": {"startTime": "2026-11-15T10:30:00Z"},
        "version": {},
        "metadata": {},
    }
    row.update(alteration[mode])

    def request(port, target, auth=None):
        if target.endswith("health"):
            return {"version": "4.0.0" if mode == "version" else langfuse.VERSION}
        return {"data": [row], "meta": None if mode == "metadata" else {}}

    with pytest.raises(Invalid):
        langfuse._inspect(ref, 3009, _binding(), request)


@pytest.mark.parametrize(
    "unsafe",
    [
        "<script>synthetic</script>",
        "[label](https://example.invalid)",
        "https://example.invalid",
        "# forged heading\n| injected row |",
        "![picture](x)",
        "{{ template }}",
    ],
)
def test_L07_report_markdown_does_not_create_active_markup(unsafe):
    rendered = report_text(unsafe)
    assert "\n" not in rendered and "<" not in rendered and "[" not in rendered and "https://" not in rendered
    assert not rendered.startswith("#") and "|" not in rendered and "{" not in rendered
