import json
from pathlib import Path

from hypothesis import given, strategies as st
import jsonschema
import pytest

from p002.generators import generate
from p004.graph import Graph, architecture, diff
from p004.models import Context, Snapshot
from p004.parsers import (
    compose,
    inventory,
    kubernetes,
    openapi,
    p001,
    p002,
    policy_context,
    python_routes,
    reference,
)
from p004.reporting import memo, mermaid, read_snapshot, write_run
from p004.safety import Invalid, address, contained, decode, digest, load, read_bytes, route

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def test_actual_p001_components_endpoints_identities_boundaries(graph):
    p001(graph, REPO)
    snap = graph.snapshot()
    assert {
        "api-service",
        "cluster",
        "namespace",
        "object-store",
        "service-account",
        "model-endpoint",
        "telemetry",
    } <= {x.kind for x in snap.assets}
    assert len(snap.endpoints) == 10
    assert {"/infer", "/objects/{key}", "/readyz", "/healthz"} == {e.path for e in snap.endpoints}
    assert len(snap.trust_boundaries) >= 10
    assert all(x.status == "DECLARED" for x in snap.assets)
    assert all(x.status == "INFERRED" for x in snap.trust_boundaries)
    diagram = mermaid(snap)
    assert "invokes DECLARED" in diagram and "authenticates DECLARED" in diagram
    api_assets = [a for a in snap.assets if a.label.startswith("P001 tenant-")]
    assert all("scripts/lab-up" in {r.path for r in a.source_refs} for a in api_assets)
    for row in [*snap.assets, *snap.endpoints, *snap.flows]:
        for ref in row.source_refs:
            assert digest(read_bytes(REPO, ref.path)) == ref.sha256


def test_openapi_templates_and_methods_no_phantom_endpoints(graph, ref):
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "synthetic", "version": "v1"},
        "paths": {"/items/{item_id}": {"get": {"responses": {}}, "put": {"responses": {}}, "parameters": []}},
    }
    assert openapi(graph, spec, ref) == 2
    assert {(x.path, x.method) for x in graph.endpoints.values()} == {
        ("/items/{item_id}", "GET"),
        ("/items/{item_id}", "PUT"),
    }


def test_remote_openapi_ref_not_fetched(graph, ref):
    openapi(
        graph,
        {"openapi": "3.0.0", "info": {}, "paths": {"/hidden": {"$ref": "https://example.invalid/spec"}}},
        ref,
    )
    assert not graph.endpoints
    assert any("not dereferenced" in x.summary for x in graph.observations.values())


def test_real_p002_two_tenants_and_oracle_not_authorization(graph, ref):
    data = generate(2026, "tiny", "fixtures")
    p002(graph, data.model_dump(mode="json"), ref)
    assert {"p002:tenant-a", "p002:tenant-b"} == {x.tenant_id for x in graph.assets.values()}
    assert all(x.status == "DECLARED" for x in graph.flows.values())
    assert all(x.kind != "api-service" for x in graph.assets.values())
    assert any("never grants" in x.summary for x in graph.observations.values())
    assert any(a.attributes["source_record_type"] == "Department" for a in graph.assets.values())
    assert any(a.attributes["source_record_type"] == "Group" for a in graph.assets.values())


def test_identical_service_keys_never_merge_tenants(graph, ref):
    a = graph.asset("same", "api-service", "tenant-a", ref)
    b = graph.asset("same", "api-service", "tenant-b", ref)
    assert a != b and len(graph.assets) == 2


def test_unknown_relation_remains_unverified(graph, ref):
    a = graph.asset("a", "application", "tenant-a", ref)
    b = graph.asset("b", "database", "tenant-a", ref)
    graph.flow(a, b, "retrieves", ref, status="UNVERIFIED", boundary="possible retrieval")
    assert next(iter(graph.flows.values())).status == "UNVERIFIED"
    assert next(iter(graph.boundaries.values())).status == "INFERRED"


def test_runtime_static_conflict_retained(graph, ref):
    id = graph.asset("svc", "api-service", "tenant-a", ref)
    e = graph.endpoint(id, "/health", "GET", ref, origin="http://127.0.0.1:8764", auth="declared")
    graph.endpoint(
        id,
        "/health",
        "GET",
        ref.model_copy(update={"pointer": "/request-1"}),
        "guarded-http",
        origin="http://127.0.0.1:8764",
        status="OBSERVED",
        response_codes=[403],
        auth="observed-rejection",
    )
    assert len(graph.endpoints) == 1
    assert graph.endpoints[e].status == "OBSERVED" and graph.endpoints[e].response_codes == [403]
    assert len(graph.endpoints[e].source_refs) == 2
    assert {x.status for x in graph.endpoints[e].evidence_claims} == {"OBSERVED", "DECLARED"}
    assert any(x.category == "discrepancy" and "auth" in x.details for x in graph.observations.values())


def test_repeatable_semantic_snapshot_and_diagram(graph):
    p001(graph, REPO)
    one = graph.snapshot()
    g2 = Graph(Context(run_id="second-run", timestamp_utc="2026-11-16T12:00:00Z", git_commit="test"))
    p001(g2, REPO)
    two = g2.snapshot()
    assert one.snapshot_digest == two.snapshot_digest
    assert mermaid(one) == mermaid(two)
    assert all(not any(group.values()) for group in diff(one, two)["changes"].values())


@pytest.mark.parametrize(
    "raw,suffix",
    [
        (b"{bad", ".json"),
        (b'{"a":1,"a":2}', ".json"),
        (b"a: &x [*x]", ".yaml"),
        (b"!!python/object/apply:os.system ['touch /tmp/NEVER']", ".yaml"),
        (b"a: 1\na: 2", ".yaml"),
        (b'{"x":NaN}', ".json"),
        (b"a: 2026-11-15", ".yaml"),
    ],
)
def test_unsafe_serialization_rejected(raw, suffix):
    with pytest.raises(Invalid):
        decode(raw, suffix)


def test_size_depth_resource_limits():
    for raw in (b" " * 2_000_001, b"[" * 100 + b"0" + b"]" * 100, b"[" + b"0," * 30_001 + b"0]"):
        with pytest.raises(Invalid):
            decode(raw)


@pytest.mark.parametrize("relative", ["../escape", "/etc/passwd", "nested/../../escape"])
def test_path_traversal_rejected(tmp_path, relative):
    with pytest.raises(Invalid):
        contained(tmp_path, relative)


def test_symlink_even_inside_root_rejected(tmp_path):
    (tmp_path / "source").write_text("{}")
    (tmp_path / "link").symlink_to(tmp_path / "source")
    with pytest.raises(Invalid):
        read_bytes(tmp_path, "link")
    (tmp_path / "dir").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(Invalid):
        contained(tmp_path, "dir/source")


def test_hostile_labels_do_not_inject_exports(graph, ref, tmp_path):
    graph.asset(
        "hostile",
        "other",
        "tenant-a",
        ref,
        label='=HYPERLINK("https://example.invalid") <script> ``` ] --> X',
    )
    snap = graph.snapshot()
    result = write_run(snap, tmp_path / "report", ["synthetic-test"])
    report = Path(result["output"])
    assert "<script>" not in (report / "report.md").read_text()
    assert "<script>" not in (report / "architecture.mmd").read_text()
    assert "'" + "=HYPERLINK" in (report / "assets.csv").read_text()


def test_secret_iac_attributes_redacted_all_exports(graph, ref, tmp_path):
    graph.asset(
        "sdk",
        "workload-identity",
        "tenant-a",
        ref,
        label="Bearer SYNTHETIC-TOP-SECRET",
        attributes={
            "password": "SECRET-CANARY-123",
            "headers": {"Authorization": "Bearer NEVER-ARCHIVE"},
            "description": "token=NEVER-KEEP",
            # Construct the inert marker in memory; no key marker/material is committed.
            "pem_description": "-----BEGIN "
            + "PRIVATE KEY-----\nPEM-CANARY-MATERIAL\n-----END "
            + "PRIVATE KEY-----",
            "url_description": "https://USER-CANARY:PASS-CANARY@example.invalid/path?q=QUERY-CANARY",
        },
    )
    graph.note("UNVERIFIED", "coverage", "Bearer DO-NOT-RETAIN", details={"body": "DO-NOT-RETAIN"})
    write_run(graph.snapshot(), tmp_path / "out", ["synthetic-test"])
    exported = b"".join(p.read_bytes() for p in (tmp_path / "out").iterdir())
    for secret in (
        b"SECRET-CANARY-123",
        b"SYNTHETIC-TOP-SECRET",
        b"NEVER-ARCHIVE",
        b"NEVER-KEEP",
        b"DO-NOT-RETAIN",
        b"PEM-CANARY-MATERIAL",
        b"USER-CANARY",
        b"PASS-CANARY",
        b"QUERY-CANARY",
    ):
        assert secret not in exported


def test_raw_iac_state_rejected_and_partial_report(tmp_path, graph):
    (tmp_path / "state.json").write_text(json.dumps({"version": 4, "outputs": {"secret": "NEVER-EXPORT"}}))
    (tmp_path / "config.json").write_text(
        json.dumps(
            {"schema_version": "p004-input-v1", "inputs": [{"kind": "iac-reviewed", "path": "state.json"}]}
        )
    )
    snap = inventory(tmp_path, "config.json", graph)
    assert snap.context.outcome == "PARTIAL" and not snap.assets
    assert snap.coverage[0].status == "error" and snap.coverage[0].processed == 0
    assert "NEVER-EXPORT" not in memo(snap)


def test_input_failure_rolls_back_partial_claims(tmp_path, graph):
    data = {
        "schema_version": "p004-architecture-v1",
        "assets": [
            {"key": "valid", "kind": "application", "tenant_id": "tenant-a"},
            {"key": "bad", "kind": "database", "tenant_id": "tenant-a", "address": "bad address"},
        ],
        "flows": [],
    }
    (tmp_path / "bad.json").write_text(json.dumps(data))
    (tmp_path / "cfg.json").write_text(
        json.dumps(
            {"schema_version": "p004-input-v1", "inputs": [{"kind": "architecture", "path": "bad.json"}]}
        )
    )
    snap = inventory(tmp_path, "cfg.json", graph)
    assert not snap.assets and snap.context.outcome == "PARTIAL"


def test_strict_schema_rejects_unknown_fields(graph):
    raw = graph.snapshot().model_dump(mode="json")
    raw["pretend_vulnerable"] = True
    with pytest.raises(ValueError):
        Snapshot.model_validate(raw)
    schema = json.loads((ROOT / "schemas/snapshot.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(raw, schema)


def test_generated_exports_schema_validate_and_evidence_links(graph, tmp_path):
    p001(graph, REPO)
    write_run(graph.snapshot(), tmp_path / "out", ["test-offline"])
    for name in ["snapshot", "assets", "endpoints", "flows", "trust_boundaries", "identities", "coverage"]:
        jsonschema.validate(
            load(tmp_path / "out", name + ".json"), load(ROOT, "schemas/" + name + ".schema.json")
        )
    assert read_snapshot(tmp_path / "out").snapshot_digest == digest(architecture(graph.snapshot()))


def test_source_parsing_never_executes_code(graph, ref, tmp_path):
    marker = tmp_path / "MUST-NOT-EXIST"
    source = f'open({str(marker)!r}, "w").write("BAD")\n@app.get("/safe")\ndef f(): pass\n'.encode()
    assert python_routes(graph, source, ref) == 1
    assert not marker.exists()
    assert next(iter(graph.endpoints.values())).status == "UNVERIFIED"


def test_compose_external_includes_refused(graph, ref):
    with pytest.raises(Invalid):
        compose(graph, {"include": ["https://example.invalid/x"], "services": {}}, ref)


def test_kubernetes_drops_secrets_and_records_grants(graph, ref):
    resources = [
        {"kind": "Secret", "metadata": {"name": "private"}, "data": {"token": "NEVER"}},
        {
            "kind": "Role",
            "metadata": {"name": "reader", "namespace": "tenant-a"},
            "rules": [{"verbs": ["get"]}],
        },
    ]
    kubernetes(graph, resources, ref)
    assert len(graph.assets) == 1
    assert "grant_digest" in next(iter(graph.assets.values())).attributes
    assert "NEVER" not in graph.snapshot().model_dump_json()


def test_real_p003_document_context_not_approval(graph):
    path = "p-003/examples/engagement-draft-a.json"
    policy_context(graph, load(REPO, path), reference(REPO, path))
    assert graph.context.engagement_id is None
    assert all(a.attributes["live_authority"] == "NOT VERIFIED" for a in graph.assets.values())
    assert all(
        a.attributes["excluded_resources"] and a.attributes["utc_window"] for a in graph.assets.values()
    )


def test_controlled_diff_added_removed_changed_and_policy(graph, ref):
    a = graph.asset("old", "application", "tenant-a", ref)
    b = graph.asset("changed", "workload-identity", "tenant-a", ref, attributes={"grant": "read"})
    before = graph.snapshot()
    del graph.assets[a]
    graph.assets[b] = graph.assets[b].model_copy(update={"attributes": {"grant": "write"}})
    graph.asset("new", "telemetry", "tenant-a", ref)
    graph.context.policy_digest = "a" * 64
    # Copy the before context: mutable builder context is not the comparison snapshot.
    before = before.model_copy(update={"context": before.context.model_copy(update={"policy_digest": None})})
    delta = diff(before, graph.snapshot())
    assert len(delta["changes"]["assets"]["added"]) == 1
    assert len(delta["changes"]["assets"]["removed"]) == 1
    assert len(delta["changes"]["assets"]["changed"]) == 1
    assert delta["policy_changed"]


@given(st.text(alphabet="abcXYZ0123456789_-", min_size=1, max_size=50))
def test_route_and_address_normalization_properties(segment):
    assert route("/" + segment) == "/" + segment
    assert (
        address("http://127.0.0.1:8764/" + segment + "?token=discard") == "http://127.0.0.1:8764/" + segment
    )


@pytest.mark.parametrize(
    "bad", [{}, {"openapi": "2.0", "paths": {}}, {"openapi": "3.1.0", "info": {}, "paths": []}]
)
def test_malformed_openapi_rejected(graph, ref, bad):
    with pytest.raises(Invalid):
        openapi(graph, bad, ref)
