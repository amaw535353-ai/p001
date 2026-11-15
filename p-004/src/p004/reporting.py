"""Repeatable sanitized exports, evidence integrity and ownership-scoped cleanup."""

import csv
import importlib.metadata
import io
import json
from pathlib import Path

from p004 import TITLE
from p004.graph import architecture, diff
from p004.models import Snapshot
from p004.safety import (
    MAX_BYTES,
    Invalid,
    canonical,
    contained,
    csv_cell,
    diagram_label,
    digest,
    load,
    markdown,
    scrub,
)


def mermaid(snapshot: Snapshot) -> str:
    rows = ["flowchart LR"]
    for a in snapshot.assets:
        rows.append(f'  {a.id}["{diagram_label(a.label)} | {diagram_label(a.tenant_id)} | {a.status}"]')
    for f in snapshot.flows:
        rows.append(f"  {f.source_id} -->|{f.kind} {f.status}| {f.target_id}")
    return "\n".join(rows) + "\n"


def memo(snapshot: Snapshot) -> str:
    c = snapshot.context
    rows = [
        f"# {TITLE}",
        "",
        "Synthetic discovery memo — not a completed client assessment.",
        "",
        f"Run: `{c.run_id}`. Mode: {c.mode}. Outcome: {c.outcome}. Timestamp UTC: {c.timestamp_utc}.",
        f"Architecture digest: `{snapshot.snapshot_digest}`.",
        "",
        f"Known inventory: {len(snapshot.assets)} assets, {len(snapshot.endpoints)} endpoint method keys, "
        f"{len(snapshot.flows)} relations, {len(snapshot.trust_boundaries)} candidate crossings.",
        "Unknown attack surface has no known denominator. A declaration is not proof of reachability or enforcement.",
        "",
        "## Scope and coverage",
        "",
        "| Source | Target | Status | Processed / known | Reason |",
        "|---|---|---|---|---|",
    ]
    for cov in snapshot.coverage:
        denom = str(cov.known_denominator) if cov.known_denominator is not None else "unknown"
        rows.append(
            f"| {markdown(cov.source)} | {markdown(cov.target)} | {cov.status} | {cov.processed} / {denom} | {markdown(cov.reason)} |"
        )
    rows += [
        "",
        "## Confidence and provenance",
        "",
        "Confidence describes evidence specificity, not exploitability: "
        "0.9 direct bounded observation; 0.6 explicit declaration; 0.3 inference/unverified.",
        "",
        "| Reviewed | Asset | Tenant | Kind | Status | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for asset in snapshot.assets:
        refs = "; ".join(
            markdown(f"{r.path}:{r.line or r.pointer} sha256={r.sha256[:12]}") for r in asset.source_refs
        )
        rows.append(
            f"| [ ] | {markdown(asset.label)} | {markdown(asset.tenant_id)} | {asset.kind} | {asset.status} | {refs} |"
        )
    rows += [
        "",
        "## API inventory",
        "",
        "| Method | Origin | Path | Status | Authentication |",
        "|---|---|---|---|---|",
    ]
    for e in snapshot.endpoints:
        rows.append(
            f"| {e.method} | {markdown(e.origin or 'unknown')} | {markdown(e.path)} | {e.status} | {e.auth} |"
        )
    rows += ["", "## Review candidates and unknowns", ""]
    for o in snapshot.observations:
        rows.append(f"- {o.status}: {markdown(o.summary)} (reference: {o.id}).")
    rows += [
        "",
        "## Prioritized assessor questions",
        "",
        "1. Which tenant/workload identity actually enforces each declared access requirement?",
        "2. Which candidate trust crossings require independent observation before a threat model?",
        "3. Which unobserved connectors, external origins or changed grants need an explicit scope amendment?",
        "",
        "## Limits",
        "",
        "No confirmed vulnerability, CVSS, compliance result, control effectiveness or legal authority is asserted.",
        "Browser, vendor APIs and Kubernetes controls remain unverified unless separately evidenced. "
        "Source/API mismatches and scanner alerts are candidates for human review, with false positives possible.",
        "G1–G4: NOT DEMONSTRATED. Outputs are inputs to P-005/P-007/P-009/P-010, not their completion.",
    ]
    return "\n".join(rows) + "\n"


def json_bytes(data) -> bytes:
    raw = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False).encode() + b"\n"
    if len(raw) > MAX_BYTES:
        raise Invalid("EXPORT-SIZE-LIMIT")
    return raw


def envelope(snapshot, records):
    return dict(
        schema_version="1.0",
        context=snapshot.context.model_dump(mode="json"),
        snapshot_digest=snapshot.snapshot_digest,
        records=records,
    )


def versions():
    return {name: importlib.metadata.version(name) for name in ("pydantic", "PyYAML", "jsonschema")}


def write_run(snapshot: Snapshot, output: Path, invocation: list[str], baseline: Snapshot | None = None):
    if digest(architecture(snapshot)) != snapshot.snapshot_digest:
        raise Invalid("SNAPSHOT-DIGEST-MISMATCH")
    if output.exists():
        raise Invalid("OUTPUT-EXISTS-REFUSING-OVERWRITE")
    contained(output.parent, output.name)
    files = {}
    files["snapshot.json"] = json_bytes(snapshot.model_dump(mode="json"))
    identities = [
        a.model_dump(mode="json")
        for a in snapshot.assets
        if a.kind in ("human-identity", "workload-identity", "service-account", "tenant")
    ]
    for name in ("assets", "endpoints", "flows", "trust_boundaries"):
        files[name + ".json"] = json_bytes(
            envelope(snapshot, [x.model_dump(mode="json") for x in getattr(snapshot, name)])
        )
    files["identities.json"] = json_bytes(envelope(snapshot, identities))
    files["coverage.json"] = json_bytes(envelope(snapshot, [x.model_dump() for x in snapshot.coverage]))
    files["observations.jsonl"] = b"".join(
        canonical(
            dict(schema_version="1.0", run_id=snapshot.context.run_id, observation=o.model_dump(mode="json"))
        )
        + b"\n"
        for o in snapshot.observations
    )
    files["inventory-diff.json"] = json_bytes(
        diff(baseline, snapshot)
        if baseline
        else dict(
            schema_version="1.0", status="NOT_APPLICABLE", reason="No baseline supplied; no change claim"
        )
    )
    files["architecture.mmd"] = mermaid(snapshot).encode()
    files["report.md"] = memo(snapshot).encode()
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["asset_id", "tenant_id", "kind", "label", "status"])
    writer.writerows(
        [[a.id, csv_cell(a.tenant_id), a.kind, csv_cell(a.label), a.status] for a in snapshot.assets]
    )
    files["assets.csv"] = stream.getvalue().encode()
    used = {x.discovery_method for x in snapshot.assets} | {x.discovery_method for x in snapshot.endpoints}
    risks = []
    if snapshot.coverage:
        risks.append(
            dict(id=17, source="user prompt; taxonomy unavailable", status="candidate parsing hypothesis")
        )
    if len({a.tenant_id for a in snapshot.assets if a.tenant_id != "unassigned"}) > 1:
        risks.append(
            dict(id=35, source="user prompt; taxonomy unavailable", status="candidate tenant hypothesis")
        )
    evaluated = any(o.category == "policy-decision" for o in snapshot.observations)
    assessment = dict(
        schema_version="1.0",
        context=snapshot.context.model_dump(mode="json"),
        project="P-004",
        future_consumers=["P-005", "P-007", "P-009", "P-010"],
        risk_linkage=risks,
        requirements=[
            dict(id="P004-PROPOSED-01", check="offline zero egress", state="proposed internal check"),
            dict(
                id="P004-PROPOSED-02",
                check="per-request P003 and transport ceiling",
                state="proposed internal check",
            ),
        ],
        tool_linkage={
            "1 Onyx": "NOT TESTED; optional local manifests only",
            "2 OpenHands": "NOT TESTED; optional local manifests only",
            "62 ZAP": "provided passive alert artifact only; scanner NOT TESTED"
            if any(o.category == "passive-alert" for o in snapshot.observations)
            else "not used in this run; live NOT TESTED",
            "145 Playwright": "BLOCKED; no independent egress sandbox",
            "P001": "static source imported" if "p001" in used else "not used",
            "P002": "actual model-validated synthetic input" if "p002" in used else "not used",
            "P003": "real evaluator; permitted decision recorded"
            if evaluated
            else "BLOCKED; no permitted operation"
            if snapshot.context.mode != "offline"
            else "static context imported"
            if "p003" in used
            else "not used",
        },
        dependency_versions=versions(),
        classification="inventory; review candidates only",
        legal_authority="NOT VERIFIED",
        publication="private synthetic artifacts; human review required",
        learner_gates={f"G{i}": "NOT DEMONSTRATED" for i in range(1, 5)},
    )
    files["assessment-record.json"] = json_bytes(assessment)
    if any(len(raw) > MAX_BYTES for raw in files.values()) or sum(map(len, files.values())) > 16_000_000:
        raise Invalid("EXPORT-SIZE-LIMIT")
    manifest = dict(
        schema_version="p004-evidence-v1",
        context=snapshot.context.model_dump(mode="json"),
        snapshot_digest=snapshot.snapshot_digest,
        invocation=scrub(invocation),
        dependency_versions=versions(),
        sources=[
            json.loads(item)
            for item in sorted(
                {
                    canonical(r.model_dump()).decode()
                    for group in (snapshot.assets, snapshot.endpoints, snapshot.flows)
                    for item in group
                    for r in item.source_refs
                }
            )
        ],
        files={name: digest(raw) for name, raw in sorted(files.items())},
        assertions={
            "snapshot_validated": True,
            "hashes_verified": True,
            "no_vulnerability_claim": True,
            "human_publication_review": "REQUIRED",
        },
    )
    files["evidence-manifest.json"] = json_bytes(manifest)
    owner = dict(
        owner="p004-run-v1",
        run_id=snapshot.context.run_id,
        files={name: digest(raw) for name, raw in sorted(files.items())},
    )
    output.mkdir(parents=True, mode=0o700)
    for name, raw in files.items():
        dest = output / name
        dest.write_bytes(raw)
        dest.chmod(0o600)
    (output / "owner.json").write_bytes(json_bytes(owner))
    verify_run(output)
    return dict(
        run_id=snapshot.context.run_id,
        outcome=snapshot.context.outcome,
        snapshot_digest=snapshot.snapshot_digest,
        assets=len(snapshot.assets),
        endpoints=len(snapshot.endpoints),
        flows=len(snapshot.flows),
        output=str(output),
    )


def read_snapshot(path: Path) -> Snapshot:
    data = load(path, "snapshot.json")
    snap = Snapshot.model_validate(data)
    if snap.snapshot_digest != digest(architecture(snap)):
        raise Invalid("SNAPSHOT-DIGEST-MISMATCH")
    return snap


def verify_run(path: Path):
    owner = load(path, "owner.json")
    if owner.get("owner") != "p004-run-v1" or set(owner) != {"owner", "run_id", "files"}:
        raise Invalid("OWNERSHIP-MANIFEST-REQUIRED")
    for name, sha in owner["files"].items():
        from p004.safety import read_bytes

        if digest(read_bytes(path, name)) != sha:
            raise Invalid("EVIDENCE-HASH-MISMATCH")
    read_snapshot(path)
    return {"status": "PASS", "hashed_files": len(owner["files"])}


def reset_owned(path: Path, confirmation: str | None, delete_evidence=False):
    if confirmation != "p004-local":
        raise Invalid("EXPLICIT-OWNED-CONFIRMATION-REQUIRED")
    verify_run(path)
    if not delete_evidence:
        return {"status": "RETAINED", "reason": "Evidence retained; deletion needs --delete-evidence"}
    owner = load(path, "owner.json")
    # Verify all entries before deleting any; unknown files are always preserved.
    for name in [*owner["files"], "owner.json"]:
        contained(path, name).unlink()
    if not any(path.iterdir()):
        path.rmdir()
    return {"status": "REMOVED-OWNED-FILES-ONLY"}
