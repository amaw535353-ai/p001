from copy import deepcopy

from hypothesis import given, settings, strategies as st
import jsonschema
import pytest
from pydantic import ValidationError

from p005.domain.schemas import Model, ThreatPath
from p005.evidence.safety import PROJECT, Invalid, canonical, digest, load, parse, read, write
from p005.ingestion.fixtures import build, read_model
from p005.modeling.graph import boundaries, path_for, validate_path
from p005.modeling.rule_engine import analyze


def regraph(data):
    data["boundaries"] = []
    model = Model.model_validate(data)
    data["boundaries"] = [b.model_dump() for b in boundaries(model)]
    return Model.model_validate(data)


def test_fixture_schema(model):
    jsonschema.Draft202012Validator(Model.model_json_schema()).validate(model.model_dump())
    assert len(model.nodes) == 37 and len(model.flows) == 39
    assert all(n.epistemic_status == "DECLARED" for n in model.nodes)


def test_two_builds_are_deterministic(model):
    other = build(PROJECT / "fixtures/baseline/architecture.yaml")
    assert canonical(model.model_dump()) == canonical(other.model_dump())
    assert canonical(analyze(model)) == canonical(analyze(other))


@pytest.mark.parametrize("value", [None, "p005-model-9.0", "1.0"])
def test_missing_unsupported_schema_rejected(model, value):
    data = model.model_dump()
    if value is None:
        del data["schema_version"]
    else:
        data["schema_version"] = value
    with pytest.raises(ValidationError):
        Model.model_validate(data)


@pytest.mark.parametrize("table", ["nodes", "flows", "evidence", "zones", "boundaries"])
def test_duplicate_graph_ids(model, table):
    data = model.model_dump()
    data[table].append(deepcopy(data[table][0]))
    with pytest.raises(ValidationError):
        Model.model_validate(data)


@pytest.mark.parametrize(
    "table,field,value",
    [
        ("flows", "source", "missing-source"),
        ("flows", "target", "missing-target"),
        ("nodes", "zone_id", "missing-zone"),
        ("nodes", "tenant_id", "missing-tenant"),
        ("zones", "trust_level", "FULLY_TRUSTED"),
        ("nodes", "sensitivity", "TOP SECRET"),
        ("flows", "principal_id", "missing-principal"),
        ("flows", "authorization_point_id", "tenant-a-human"),
        ("flows", "encryption", "OBSERVED_TLS"),
        ("flows", "enforcement_result", "PASS"),
    ],
)
def test_invalid_metadata_or_references(model, table, field, value):
    data = model.model_dump()
    data[table][0][field] = value
    with pytest.raises(ValidationError):
        Model.model_validate(data)


def test_cycle_paths_are_bounded(model):
    data = model.model_dump()
    edge = deepcopy(data["flows"][0])
    edge.update(id="fixture-cycle", source=edge["target"], target=edge["source"])
    data["flows"].append(edge)
    m = regraph(data)
    for e in m.flows:
        path = path_for(m, e.id)
        assert len(path.edge_ids) <= 4
        assert len(path.node_ids) == len(set(path.node_ids))


def test_huge_deep_inputs_rejected():
    with pytest.raises(Invalid):
        parse(b" " * (4 * 1024 * 1024 + 1))
    with pytest.raises(Invalid):
        parse(("[" * 64 + "0" + "]" * 64).encode())
    with pytest.raises(Invalid):
        parse(b'a: "' + b"x" * 32769 + b'"')


@pytest.mark.parametrize(
    "raw",
    [
        b"!!python/object/apply:os.system ['touch should-not-exist']",
        b"root: &shared [one]\nother: *shared\n",
        b"key: !include https://invalid.example/model.yaml",
        b"key: !!str value",
        b"a: 1\na: 2",
        b'{"a":1,"a":2}',
        b'{"n":NaN}',
    ],
)
def test_untrusted_yaml_json_never_executes(tmp_path, raw):
    with pytest.raises(Invalid):
        parse(raw)
    assert not (tmp_path / "should-not-exist").exists()


def test_path_traversal_and_symlink(tmp_path):
    with pytest.raises(Invalid):
        write(PROJECT / "generated/../escape.json", b"no")
    with pytest.raises(Invalid):
        write(PROJECT / "outside.json", b"no")
    link = tmp_path / "outside-link"
    link.symlink_to("/tmp", target_is_directory=True)
    with pytest.raises(Invalid):
        read(link / "anything")
    with pytest.raises(Invalid):
        write(link / "anything", b"no")
    file_link = tmp_path / "file-link"
    file_link.symlink_to(PROJECT / "README.md")
    with pytest.raises(Invalid):
        read(file_link)
    with pytest.raises(Invalid):
        write(file_link, b"no")


def test_tenants_and_principals_remain_distinct(model):
    humans = [n for n in model.nodes if n.kind == "HumanIdentity"]
    workloads = [n for n in model.nodes if n.kind == "WorkloadIdentity"]
    assert len(humans) == len(workloads) == 2
    assert {n.id for n in humans}.isdisjoint(n.id for n in workloads)
    assert {n.tenant_id for n in humans} == {"tenant-a", "tenant-b"}


def test_actor_and_agent_tool_crossings(model):
    edge = next(e for e in model.flows if e.id == "tenant-a-agent-mcp")
    boundary = next(b for b in model.boundaries if edge.id in b.edge_ids)
    assert "AGENT_TOOL" in boundary.reasons and edge.principal_id in boundary.actor_ids


def test_unknown_authorization_never_tested(model):
    assert any(e.authorization == "UNKNOWN" for e in model.flows)
    assert all(e.enforcement_result == "NOT_TESTED" for e in model.flows)
    assert not any(e.encryption == "OBSERVED_TLS" for e in model.flows)


def test_observation_requires_evidence(model):
    data = model.model_dump()
    data["nodes"][0]["epistemic_status"] = "OBSERVED"
    with pytest.raises(ValidationError):
        Model.model_validate(data)


def test_unknown_trust_not_silently_trusted(model):
    data = model.model_dump()
    data["zones"][0]["trust_level"] = "UNKNOWN"
    m = regraph(data)
    assert any("UNKNOWN_TRUST" in b.reasons for b in m.boundaries)


def test_missing_boundaries_rejected_at_canonical_intake(model, tmp_path):
    data = model.model_dump()
    data["boundaries"] = []
    path = tmp_path / "canonical.json"
    path.write_bytes(canonical(data))
    with pytest.raises(Invalid, match="MISSING-CANDIDATE"):
        read_model(path)


def test_fabricated_path_rejected(model):
    path = path_for(model, "tenant-a-agent-mcp").model_dump()
    path["edge_ids"][0] = "unmodeled-hop"
    with pytest.raises(Invalid):
        validate_path(model, ThreatPath.model_validate(path))


@given(st.text(max_size=100))
@settings(max_examples=30)
def test_stable_hash_labels_do_not_leak(value):
    from p005.evidence.safety import stable

    identifier = stable("threat", "tenant-a", value)
    assert len(identifier) == 71
    assert identifier == stable("threat", "tenant-a", value)
    assert identifier != stable("threat", "tenant-b", value)


def test_source_hash_after_redaction(model, tmp_path):
    data = load(PROJECT / "fixtures/baseline/architecture.yaml")
    data["nodes"][0]["label"] = "password=synthetic-canary-123"
    path = tmp_path / "redact.yaml"
    path.write_bytes(canonical(data))
    m = build(path)
    assert m.nodes[0].label == "REDACTED"
    data["nodes"][0]["label"] = "REDACTED"
    assert m.source_snapshot_hash == digest(data)


def test_self_loop_handled_without_invented_onward_hop(model):
    data = model.model_dump()
    edge = deepcopy(next(e for e in data["flows"] if e["id"] == "tenant-a-agent-mcp"))
    edge.update(id="synthetic-self-loop", target=edge["source"])
    data["flows"].append(edge)
    m = regraph(data)
    path = path_for(m, "synthetic-self-loop")
    assert path.edge_ids == ["synthetic-self-loop"]
    assert path.node_ids == ["tenant-a-agent", "tenant-a-agent"]
    assert analyze(m)["threats"]


def test_cli_reports_incompatible_schema_distinctly(tmp_path, py):
    import subprocess

    path = tmp_path / "incompatible.json"
    path.write_text('{"schema_version":"p005-model-99"}')
    child = subprocess.run(
        [py, "-m", "p005", "model", "build", "--input", str(path), "--out", str(tmp_path / "no-output")],
        capture_output=True,
        text=True,
    )
    assert child.returncode == 2 and "INCOMPATIBLE-SCHEMA-VERSION" in child.stderr
    assert not (tmp_path / "no-output").exists()
