"""Read-only sibling source/data adapters. Discovery never expands approved scope."""

import json
from pathlib import Path
import re
import subprocess

from p003.demo import CREATED, header
from p003.models import Artifact, Asset, sealed
from p003.util import digest, load, uid


def proposal(source, assets, provenance, **extra):
    value = sealed(
        Artifact,
        **header("proposal:" + digest(provenance), "p003-importer"),
    ).model_dump(mode="json")
    value.update(
        kind="proposed-inventory",
        source=source,
        assets=assets,
        provenance=provenance,
        scope_effect="NONE: explicit amendment and fresh approval required",
        **extra,
    )
    value["content_digest"] = digest({k: v for k, v in value.items() if k != "content_digest"})
    return value


def p001_inventory(root: Path):
    resources = load(root / "infra/kubernetes/resources.json")
    script = (root / "scripts/lab-up").read_text()
    commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    provenance = {
        "repository_commit": commit,
        "inventory_sha256": digest(resources),
        "lab_up_sha256": digest(script.encode()),
        "schema_version": "p001-kubernetes-v1",
        "runtime": "NOT TESTED: no cluster query; declarative source only",
    }
    services = {
        (r["metadata"]["namespace"], r["metadata"]["name"])
        for r in resources
        if r["kind"] == "Service"
        and r["metadata"].get("labels", {}).get("project") == "p001"
        and r["spec"]["type"] == "ClusterIP"
    }
    assets = []
    for tenant, name, port in re.findall(r"^forward (tenant-[ab]) (api) (\d+) \d+$", script, re.M):
        if (tenant, name) not in services:
            raise ValueError("P-001 forward missing owned service declaration")
        asset_id = f"p001:{tenant}:{name}"
        asset = sealed(
            Asset,
            id=uid(asset_id),
            source="P-001 inspected versioned source inventory",
            author="p003-importer",
            created_at=CREATED,
            asset_id=asset_id,
            tenant=tenant,
            owner="p001-lab-owner",
            service=name,
            environment="local-lab",
            selector={"kind": "url", "value": f"http://127.0.0.1:{port}/readyz"},
            methods=["GET"],
            ownership="synthetic-owned",
            included=False,
            third_party_restrictions=[],
            trust_boundaries=["source declaration -> proposed target; runtime not verified"],
        )
        assets.append(asset.model_dump(mode="json"))
    if len(assets) != 2:
        raise ValueError("P-001 inventory contract changed; no inferred endpoints")
    return proposal("P-001 actual source adapter", assets, provenance)


def p002_inventory(root: Path, dataset: Path):
    """Use the sibling's real validator including graph/provenance/file hashes."""
    python = root / ".venv/bin/python"
    if not python.exists():
        raise ValueError("P-002 validator unavailable; initialize its documented environment separately")
    program = """
import json,sys
from pathlib import Path
from p002.scenarios import load_dataset, verify_files
d=load_dataset(Path(sys.argv[1])); m=verify_files(Path(sys.argv[1]))
assert d.schema_version=='1.0' and d.mode=='fixtures'
assert all(x.origin=='generated oracle' and x.observed_result is None for x in d.decisions)
print(json.dumps({'schema_version':d.schema_version,'notice':d.notice,'dataset_sha256':m['dataset_sha256'],
 'tenants':[{'id':x.id,'name':x.name} for x in d.tenants],
 'actors':[{'ref':x.id,'tenant':x.tenant_id,'synthetic_role':x.role,'p003_role':'UNASSIGNED'} for x in d.humans],
 'assets':[{'asset_id':x.id,'tenant':x.tenant_id,'classification':x.classification.value,'kind':x.kind,'included':False} for x in d.resources],
 'scenarios':[{'id':x.id,'status':x.status} for x in d.scenarios],
 'oracle':'ExpectedDecision is application permission oracle ONLY; never imported as authorization'}))
"""
    run = subprocess.run(
        [str(python), "-c", program, str(dataset.resolve())],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if run.returncode:
        raise ValueError("P-002 validation failed; raw dataset/diagnostics omitted")
    result = json.loads(run.stdout)
    return proposal(
        "P-002 actual validated synthetic dataset",
        result.pop("assets"),
        {
            "schema_version": result["schema_version"],
            "dataset_sha256": result["dataset_sha256"],
            "validator_sha256": digest((root / "src/p002/validation/__init__.py").read_bytes()),
        },
        imported_context=result,
    )
