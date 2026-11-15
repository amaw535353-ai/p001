"""Deterministic portable outputs. Credentials never belong in export plans."""

import csv
import io
import json
import html
from pathlib import Path
from p002 import NOTICE
from p002.validation import digest
from p002.models import Dataset


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def csv_safe(value):
    text = (
        json.dumps(value, sort_keys=True, ensure_ascii=False)
        if isinstance(value, (dict, list))
        else str(value if value is not None else "")
    )
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")) or text.startswith(
        ("\t", "\r", "\n")
    ):
        text = "'" + text
    return text


def markdown_safe(text):
    # HTML is escaped; code blocks/backticks and link syntax cannot become active markup.
    return html.escape(text).replace("`", "&#96;").replace("[", "&#91;").replace("]", "&#93;")


def code_hash():
    root = Path(__file__).resolve().parents[3]
    return digest(
        {
            str(p.relative_to(root)): digest(p.read_bytes())
            for base in ["src", "config"]
            for p in sorted((root / base).rglob("*"))
            if p.is_file() and p.suffix in [".py", ".json"]
        }
    )


def build_files(d):
    obj = d.model_dump(mode="json")
    files = {"dataset.json": canonical(obj)}
    for table, rows in d.tables().items():
        values = [x.model_dump(mode="json") for x in rows]
        files[f"tables/{table}.jsonl"] = "".join(
            json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in values
        ).encode()
        if values:
            s = io.StringIO(newline="")
            w = csv.writer(s, lineterminator="\n")
            fields = sorted(values[0])
            w.writerow(fields)
            w.writerows([csv_safe(row[k]) for k in fields] for row in values)
            files[f"csv/{table}.csv"] = s.getvalue().encode()
    resources = {r.id: r for r in d.resources}
    for doc in d.documents:
        stem = doc.id.replace(":", "_")
        files["documents/" + stem + ".md"] = doc.body.encode()
        files["documents/" + stem + ".metadata.json"] = canonical(
            {
                **resources[doc.resource_id].model_dump(mode="json"),
                "document_id": doc.id,
                "origin": "self-created-template",
                "content_sha256": doc.content_sha256,
                "trust": doc.trust,
            }
        )
    counts = {k: len(v) for k, v in d.tables().items()}
    allow = sum(x.expected == "ALLOW" for x in d.decisions)
    files["summary.json"] = canonical(
        {
            "notice": NOTICE,
            "counts": counts,
            "scenarios": len(d.scenarios),
            "oracle": {
                "ALLOW": allow,
                "DENY": len(d.decisions) - allow,
                "denominator": len(d.decisions),
                "origin": "generated oracle",
            },
            "labels": {
                c: sum(r.classification.value == c for r in d.resources)
                for c in ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
            },
            "orphan_references": 0,
            "cross_tenant_grants": sum(g.cross_tenant for g in d.grants),
            "platform_enforcement": "NOT TESTED",
            "human_assessment": "NOT DEMONSTRATED",
        }
    )
    files["SUMMARY.md"] = (
        f"# Fictional enterprise inventory\n\n{NOTICE}\n\n"
        + "\n".join(f"- {k}: {v}" for k, v in counts.items())
        + f"\n\nOracle ALLOW {allow}/{len(d.decisions)}; DENY {len(d.decisions) - allow}/{len(d.decisions)}.\n"
        + "These are generated expectations. Observed platform results are separate immutable run records.\n"
    ).encode()
    files["scenario-manifest.json"] = canonical(
        {"notice": NOTICE, "scenarios": [x.model_dump(mode="json") for x in d.scenarios]}
    )
    timeline = sorted(
        [x.model_dump(mode="json") for x in [*d.lifecycle_events, *d.business_events]],
        key=lambda x: (x["effective_at"], x["id"]),
    )
    files["event-timeline.json"] = canonical(
        {"notice": NOTICE, "baseline_mutated": False, "events": timeline}
    )
    files["provenance-manifest.json"] = canonical(
        {
            "notice": NOTICE,
            "sources": [x.model_dump(mode="json") for x in d.provenance],
            "documents": {x.id: x.content_sha256 for x in d.documents},
        }
    )
    files["data-dictionary.json"] = canonical({"notice": NOTICE, "schema": Dataset.model_json_schema()})
    actual_subsets = {
        "nextcloud": [x for x in d.documents if x.resource_id.endswith((":doc0", ":doc3"))],
        "redmine": d.issues,
        "label-studio": [t for t in d.tasks if t.document_id.endswith(":doc0:body")],
        "p001": [],
    }
    for name, table in actual_subsets.items():
        objects = [
            {"canonical_id": x.id, "external_key": x.id.replace(":", "-"), "ownership": "p002-only"}
            for x in table
        ]
        if name == "p001":
            objects = [
                {
                    "canonical_id": "p002:marker-contract",
                    "external_key": "fixture-p002-" + digest(files["dataset.json"])[:12],
                    "ownership": "p002-only",
                }
            ]
        files[f"imports/{name}.json"] = canonical(
            {
                "notice": NOTICE,
                "target": name,
                "dry_run": True,
                "policy": "fixed loopback endpoint; separate --target lab required",
                "external_ids": {},
                "objects": objects,
                "planned_objects": len(objects),
                "scope": "representative subset, not full ACL equivalence",
                "p001_payload": {"marker": "P001-SYNTHETIC-ONLY"} if name == "p001" else None,
                "credential_placeholder": "NONFUNCTIONAL-DO-NOT-AUTHENTICATE",
            }
        )
    trace = []
    for scenario in d.scenarios:
        # A design links to its real lifecycle test; it does not invent an observed
        # platform decision or associate unrelated baseline cases with every risk.
        rid = scenario.assets[0]
        resource = resources[rid]
        actor = (
            "p002:tenant-b:hr:u0"
            if scenario.id in ["S02", "S10", "S11"]
            else "p002:tenant-a:finance:u1"
            if scenario.id == "S07"
            else "p002:tenant-a:hr:service"
            if scenario.id == "S06"
            else "p002:tenant-a:hr:u1"
        )
        grants = [
            g.id
            for g in d.grants
            if g.tenant_id == resource.tenant_id
            and (g.resource_id == rid or g.resource_id == resource.parent_id)
        ]
        trace.append(
            {
                "notice": NOTICE,
                "engagement": "p002:enterprise",
                "tenant": resource.tenant_id,
                "asset": rid,
                "actor": actor,
                "grants": grants,
                "policy": "temporal-reference-evaluator-v1",
                "operation": scenario.steps[0].operation,
                "risk_ids": scenario.hypothesis.risk_ids,
                "risk_taxonomy_status": scenario.hypothesis.taxonomy_status,
                "p_id": "P-002",
                "scenario_id": scenario.id,
                "test_id": f"tests/lifecycle/test_scenarios.py::test_seed_diff_reset_repeat[{scenario.id}]",
                "expected": scenario.test_oracle,
                "origin": "GENERATED_EXPECTED_RESULT",
                "observed_result": None,
                "evidence": None,
                "limitation": "Native semantics require separate adapter observations",
                "remediation": None,
                "retest": None,
                "human_verifier": None,
            }
        )
    for decision in d.decisions:
        trace.append(
            {
                "notice": NOTICE,
                "engagement": "p002:enterprise",
                "tenant": decision.tenant_id,
                "asset": decision.resource_id,
                "actor": decision.actor_id,
                "policy": decision.rule_ids,
                "operation": decision.action,
                "risk_ids": [],
                "p_id": "P-002",
                "scenario_id": None,
                "test_id": "tests/unit/test_core.py::test_oracle_denominators_and_independent_policy_cases",
                "expected": decision.expected,
                "oracle_id": decision.id,
                "origin": "generated oracle",
                "observed_result": None,
                "evidence": None,
                "limitation": "Reference-model result only",
                "remediation": None,
                "retest": None,
                "human_verifier": None,
            }
        )
    files["traceability.jsonl"] = "".join(json.dumps(x, sort_keys=True) + "\n" for x in trace).encode()
    hashes = {k: digest(v) for k, v in sorted(files.items())}
    files["reproducibility.json"] = canonical(
        {
            "notice": NOTICE,
            "seed": d.seed,
            "logical_time": d.logical_time,
            "schema_version": d.schema_version,
            "generator_version": d.generator_version,
            "code_sha256": code_hash(),
            "python": "3.12",
            "pydantic": __import__("pydantic").__version__,
            "lock_sha256": digest((Path(__file__).resolve().parents[3] / "requirements.lock").read_bytes()),
            "profile": d.profile,
            "mode": d.mode,
            "dataset_sha256": digest(files["dataset.json"]),
            "content_root_sha256": digest(hashes),
            "files": hashes,
            "precision": "byte-for-byte in pinned environment"
            if d.mode == "fixtures"
            else "schema/statistical consistency; bytes not guaranteed",
        }
    )
    return files
