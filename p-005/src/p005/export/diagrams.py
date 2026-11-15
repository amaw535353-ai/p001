"""Dependency-free text diagrams; imported labels cannot create syntax."""

import json
import re

from p005.domain.schemas import Model
from p005.evidence.safety import digest


def label(value: str) -> str:
    # Deliberately lossy publication label: no HTML, quotes, brackets, comments,
    # newlines, Mermaid directives, URLs or executable link/click syntax.
    return re.sub(r"[^a-zA-Z0-9 ._-]", "_", value)[:160]


def alias(value: str) -> str:
    return "n" + digest(value)[:24]


def render(model: Model, format: str = "mermaid", boundaries_only: bool = False) -> str:
    selected = {e for b in model.boundaries for e in b.edge_ids}
    edges = [e for e in model.flows if not boundaries_only or e.id in selected]
    if format == "dot":
        rows = ["digraph p005 {", "  rankdir=LR;"]
        for node in model.nodes:
            rows.append(f"  {alias(node.id)} [label={json.dumps(label(node.label + ' | ' + node.kind))}];")
        for edge in edges:
            rows.append(
                f"  {alias(edge.source)} -> {alias(edge.target)} [label={json.dumps(label(edge.kind))}];"
            )
        return "\n".join([*rows, "}", ""])
    rows = ["flowchart LR"]
    for zone in model.zones:
        rows.append(f'  subgraph {alias(zone.id)}["{label(zone.label)} - {zone.trust_level}"]')
        for node in model.nodes:
            if node.zone_id == zone.id:
                rows.append(
                    f'    {alias(node.id)}["{label(node.label)} - {node.kind} - {node.epistemic_status}"]'
                )
        rows.append("  end")
    reasons = {eid: ",".join(b.reasons) for b in model.boundaries for eid in b.edge_ids}
    for edge in edges:
        text = label(
            edge.kind + " " + (reasons.get(edge.id, "") if boundaries_only else edge.epistemic_status)
        )
        rows.append(f"  {alias(edge.source)} -->|{text}| {alias(edge.target)}")
    return "\n".join(rows) + "\n"
