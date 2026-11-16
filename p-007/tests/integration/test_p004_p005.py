from p007.integrations import import_contract
from p007.safety import REPO, canonical, write_new


def test_p004_actual_inventory_and_snapshot_integrity(tmp_path):
    from p004.graph import Graph
    from p004.models import Context
    from p004.parsers import inventory

    graph = Graph(
        Context(
            run_id="p007-contract-test", timestamp_utc="2026-11-16T00:00:00Z", git_commit="test-synthetic"
        )
    )
    inventory(REPO, "p-004/config/offline.example.json", graph)
    path = tmp_path / "snapshot.json"
    write_new(path, canonical(graph.snapshot().model_dump(mode="json")))
    result = import_contract("P-004", path)
    assert result["status"] == "PASS" and result["endpoint_refs"]


def test_p005_actual_threats_keep_hypothesis_status(tmp_path):
    from p005.ingestion.fixtures import build
    from p007.safety import PROJECT
    from pathlib import Path
    from tempfile import TemporaryDirectory

    model = build(REPO / "p-005/fixtures/baseline/architecture.yaml")
    # P005 intentionally permits source intake only below the repository root.
    (PROJECT / ".runtime").mkdir(mode=0o700, exist_ok=True)
    with TemporaryDirectory(prefix="p005-contract-", dir=PROJECT / ".runtime") as directory:
        path = Path(directory) / "model.json"
        write_new(path, canonical(model.model_dump(mode="json")))
        result = import_contract("P-005", path)
    assert result["hypotheses"] and all(h["status"] == "MODELLED_THREAT" for h in result["hypotheses"])
    assert any(h["control_ids"] for h in result["hypotheses"])
