"""Validated metadata contracts; imports never confer authorization or findings."""

from pathlib import Path

from p007.safety import REPO, Blocked, digest, load


def import_contract(project: str, path: Path) -> dict:
    if not path.exists():
        raise Blocked(project + "-CONTRACT-ABSENT")
    if project == "P-001":
        if path.absolute() not in (
            REPO / "infra/kubernetes/resources.json",
            REPO / "infra/kubernetes/bootstrap.json",
        ):
            raise Blocked("P001-METADATA-ALLOWLIST-ONLY")
        rows = load(path)
        selected = [
            {
                "kind": x["kind"],
                "name": x["metadata"]["name"],
                "labels": {k: v for k, v in x["metadata"].get("labels", {}).items() if k.startswith("p001")},
            }
            for x in rows
            if x["kind"] in ("Namespace", "Service", "NetworkPolicy", "Deployment")
        ]
        return {
            "project": project,
            "status": "PASS",
            "contract": "p001-resources-metadata",
            "count": len(selected),
            "source_hash": digest(selected),
            "limit": "Declarations only; kind/cgroup and runtime controls NOT_TESTED",
        }
    if project == "P-002":
        from p002.models import Dataset

        data = load(path)
        if data.get("schema_version") != "1.0":
            raise Blocked("P002-INCOMPATIBLE-VERSION")
        dataset = Dataset.model_validate(data)
        if dataset.mode != "fixtures":
            raise Blocked("P002-SYNTHETIC-FIXTURES-REQUIRED")
        return {
            "project": project,
            "status": "PASS",
            "contract": "Dataset-1.0",
            "source_hash": digest(data),
            "identities": [x.id for x in dataset.humans],
            "tenants": [x.id for x in dataset.tenants],
            "scenario_refs": [x.id for x in dataset.scenarios],
            "limit": "Generated policy oracles are not native enforcement",
        }
    if project == "P-003":
        from p003.models import Engagement, verified

        data = load(path)
        spec = Engagement.model_validate(data)
        verified(spec)
        return {
            "project": project,
            "status": "PASS",
            "contract": "sealed-Engagement-1.0",
            "source_hash": spec.content_digest,
            "limit": "Metadata validation only; network actions separately use actual fresh Store replay and evaluate",
        }
    if project == "P-004":
        from p004.models import Snapshot
        from p004.graph import architecture

        value = Snapshot.model_validate(load(path))
        from p004.safety import digest as p004_digest

        if p004_digest(architecture(value)) != value.snapshot_digest:
            raise Blocked("P004-SNAPSHOT-INTEGRITY")
        return {
            "project": project,
            "status": "PASS",
            "contract": "Snapshot-1.0",
            "source_hash": digest(value.model_dump(mode="json")),
            "endpoint_refs": [
                {"asset_id": e.asset_id, "method": e.method, "path": e.path} for e in value.endpoints
            ],
            "limit": "Discovered/declarative endpoints do not grant execution authority",
        }
    if project == "P-005":
        from p005.ingestion.fixtures import read_model
        from p005.modeling.rule_engine import analyze

        model = read_model(path)
        result = analyze(model)
        return {
            "project": project,
            "status": "PASS",
            "contract": "p005-model-1.0",
            "source_hash": digest(model.model_dump(mode="json")),
            "hypotheses": [
                {
                    "id": c["threat_id"],
                    "status": c.get("status", "MODELLED_THREAT"),
                    "risk_ids": c["risk_ids"],
                    "control_ids": c["control_ids"],
                }
                for c in result.get("threats", [])
            ],
            "limit": "Candidate threats and suggested controls remain hypotheses; no confirmed finding",
        }
    if project == "P-006":
        raise Blocked("P006-NO-IMPLEMENTED-VERIFIED-TARGET")
    raise Blocked("UNKNOWN-SIBLING-CONTRACT")
