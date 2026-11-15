#!/usr/bin/env python3
"""Exercise actual sibling offline contracts; never query targets or a cluster."""

import subprocess

from p002.generators import generate
from p004.graph import Graph
from p004.models import Context
from p004.parsers import inventory

from p005.evidence.safety import PROJECT, REPO, canonical, digest, write
from p005.export.run import export_run
from p005.ingestion.predecessors import p001, p002, p003_context, p004
from p005.modeling.rule_engine import analyze

out = PROJECT / "generated/integrations"
dataset_path = out / "p002-dataset.json"
dataset = generate(seed=2026, profile="tiny", mode="fixtures")
write(dataset_path, canonical(dataset.model_dump(mode="json")))
config = dict(
    schema_version="p004-input-v1",
    inputs=[
        dict(kind="p001"),
        dict(kind="architecture", path="p-004/fixtures/static/architecture.json"),
        dict(kind="p002", path="p-005/generated/integrations/p002-dataset.json"),
        dict(kind="p003", path="p-003/examples/engagement-draft-a.json"),
    ],
)
write(out / "p004-input.json", canonical(config))
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
graph = Graph(
    Context(run_id="p005-predecessor-import", timestamp_utc="2026-11-15T00:00:00Z", git_commit=commit)
)
inventory(REPO, "p-005/generated/integrations/p004-input.json", graph)
snapshot_path = out / "p004-snapshot.json"
snapshot = graph.snapshot()
write(snapshot_path, canonical(snapshot.model_dump(mode="json")))
models = dict(
    p001=p001(REPO / "infra/kubernetes/resources.json"), p002=p002(dataset_path), p004=p004(snapshot_path)
)
models["p004"] = p003_context(models["p004"], REPO / "p-003/examples/engagement-draft-a.json")
statuses = []
run_paths = {}
for name, model in models.items():
    analysis = analyze(model)
    run_path = out / (name + "-" + digest(model.model_dump())[:12])
    export_run(run_path, model, analysis)
    run_paths[name] = str(run_path.relative_to(PROJECT))
    statuses.extend(i.model_dump() for i in model.integrations)
write(
    out / "integration-results.json",
    canonical(
        dict(
            status="PASS",
            mode="OFFLINE_METADATA_IMPORT_ONLY",
            integrations=statuses,
            run_paths=run_paths,
            source_snapshot_sha256=digest(snapshot.model_dump(mode="json")),
            target_testing="NOT_TESTED",
        )
    ),
)
print(
    "PASS: actual P001 declarations, P002 generator, P003 sealed context, P004 inventory and Snapshot adapters"
)
