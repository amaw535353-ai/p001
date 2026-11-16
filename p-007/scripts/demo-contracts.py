#!/usr/bin/env python3
"""Exercise actual P001-P005 exports, preserving their epistemic limitations."""

from uuid import uuid4

from p002.generators import generate
from p004.graph import Graph
from p004.models import Context
from p004.parsers import inventory
from p005.ingestion.fixtures import build

from p007.integrations import import_contract
from p007.evidence import repository_identity
from p007.safety import PROJECT, REPO, canonical, write_new

folder = PROJECT / ".runtime" / ("contracts-" + uuid4().hex)
folder.mkdir(parents=True, mode=0o700)
dataset = folder / "p002-dataset.json"
write_new(dataset, canonical(generate(seed=7, profile="tiny", mode="fixtures").model_dump(mode="json")))
config = folder / "p004-input.json"
write_new(
    config,
    canonical(
        {
            "schema_version": "p004-input-v1",
            "inputs": [
                {"kind": "p001"},
                {"kind": "architecture", "path": "p-004/fixtures/static/architecture.json"},
                {"kind": "p002", "path": str(dataset.relative_to(REPO))},
            ],
        }
    ),
)
graph = Graph(
    Context(
        run_id="p007-contract-import",
        timestamp_utc="2026-11-16T00:00:00Z",
        git_commit=repository_identity()["commit_sha"],
    )
)
inventory(REPO, str(config.relative_to(REPO)), graph)
snapshot = folder / "p004-snapshot.json"
write_new(snapshot, canonical(graph.snapshot().model_dump(mode="json")))
model = folder / "p005-model.json"
write_new(model, canonical(build(REPO / "p-005/fixtures/baseline/architecture.yaml").model_dump(mode="json")))
paths = {
    "P-001": REPO / "infra/kubernetes/resources.json",
    "P-002": dataset,
    "P-003": REPO / "p-003/examples/engagement-draft-a.json",
    "P-004": snapshot,
    "P-005": model,
}
results = [import_contract(project, path) for project, path in paths.items()]
results.append(
    {
        "project": "P-006",
        "status": "BLOCKED",
        "reason": "No p-006 directory or committed implementation at inspected base 24e9d65",
    }
)
out = folder / "integration-results.json"
write_new(out, canonical(results))
print(canonical({"mode": "OFFLINE-METADATA-CONTRACTS", "results": results, "artifact": str(out)}).decode())
