"""Synthetic consultancy handover with unfilled signatures and explicit uncertainty."""

import html

from p005 import NOTICE, TITLE


def md(value) -> str:
    text = html.escape(str(value), quote=True)
    for char in "`[]()!*_|\\:#":
        text = text.replace(char, f"&#{ord(char)};")
    return text.replace("\n", " ").replace("\r", " ")


def report(model, analysis, reviews) -> str:
    latest = {r["threat_id"]: r for r in reviews if r["model_digest"] == analysis["model_digest"]}
    rows = [
        f"# {TITLE}",
        "",
        NOTICE,
        "",
        "## Synthetic client and scope",
        "",
        f"Client/system: {md(model.system_id)}. Engagement: {md(model.engagement_id)} v{model.engagement_version}.",
        f"Scope source: {md(model.model_scope.source)}. Model review state: {model.review_state}.",
        "Static modeling context does not authorize target testing. Real legal authority: NOT_VERIFIED.",
        "",
        "## System objective and architecture",
        "",
        "Synthetic two-tenant AI assistance, retrieval and governed mock actions. Imported architectures may differ.",
        f"{len(model.nodes)} nodes; {len(model.flows)} directed flows; {len(model.boundaries)} candidate boundaries.",
        "",
        "## Key assets, entry points and attack surfaces",
        "",
        "| Asset | Kind | Tenant | Surface | Source status | Owner role |",
        "|---|---|---|---|---|---|",
    ]
    for n in model.nodes:
        rows.append(
            f"| {md(n.label)} | {n.kind} | {md(n.tenant_id)} | {md(', '.join(n.surface))} | {n.epistemic_status} | {md(n.owner_role)} |"
        )
    rows += [
        "",
        "## Trust boundaries",
        "",
        "Derived crossings require human confirmation; UNKNOWN is never trusted.",
        "",
        "| Boundary | Modeled edges | Reasons | Principal |",
        "|---|---|---|---|",
    ]
    for b in model.boundaries:
        rows.append(
            f"| {b.id} | {md(', '.join(b.edge_ids))} | {md(', '.join(b.reasons))} | {md(', '.join(b.actor_ids) or 'UNKNOWN')} |"
        )
    rows += [
        "",
        "## Candidate threat register and ranked test hypotheses",
        "",
        "Review priorities are ordinal triage assumptions. No finding severity or empirical likelihood is assigned.",
        "",
        "| Threat | Title | Risks | Review priority | Editorial decision | Owner |",
        "|---|---|---|---|---|---|",
    ]
    for t in sorted(
        analysis["threats"], key=lambda t: (t["triage"]["human_review_priority"], t["threat_id"])
    ):
        decision = latest.get(t["threat_id"], {}).get("decision", "PROPOSED")
        priority = (
            latest.get(t["threat_id"], {}).get("priority_override") or t["triage"]["human_review_priority"]
        )
        rows.append(
            f"| {t['threat_id']} | {md(t['title'])} | {md(', '.join(t['risk_ids']))} | {priority} | {decision} | {md(t['owner_role'])} |"
        )
    rows += [
        "",
        "## Proposed controls and verification",
        "",
        "All controls are CONTROL_PROPOSED; all validation plans are NOT_TESTED and non-executable.",
        "| Control | Owner | Security objective | Acceptance criteria |",
        "|---|---|---|---|",
    ]
    for c in analysis["controls"]:
        rows.append(
            f"| {c['id']} | {md(c['owner_role'])} | {md(c['objective'])} | {md('; '.join(c['acceptance_criteria']))} |"
        )
    rows += [
        "",
        "Verification-plan.json records permitted/forbidden actors, positive/negative paths, evidence and fresh ROE prerequisites.",
        "",
        "## Assumption and confidence ledger",
        "",
        "DIRECT_METADATA means bounded source observation, DECLARATION a stated design, INFERENCE a derived relation, UNKNOWN a gap.",
        "None measures exploitability or effectiveness.",
    ]
    rows += ["- " + md(a) for a in model.assumptions]
    rows += ["", "## Exclusions and blind spots", ""] + ["- " + md(x) for x in model.exclusions]
    rows += [
        "- Full 37-risk source unavailable; only explicitly supplied prompt entries are mapped.",
        "- Native tools are BLOCKED; no independent confirmation from repeated model transforms.",
        "- No target requests, vulnerability validation, legal review or authenticated signoff.",
        "",
        "## Source references",
        "",
    ]
    rows += [
        f"- {md(e.source)} {md(e.pointer)}; sanitized SHA-256 {e.sanitized_sha256}; {e.status}; {md(e.measured_scope)}"
        for e in model.evidence
    ]
    rows += [
        "",
        "## Handover and review signatures",
        "",
        "Model reviewer role: __________",
        "Review date/evidence: __________",
        "Scope owner: __________",
        "Assessor acceptance: __________",
        "Learner G1–G4: UNVERIFIED.",
        "",
        "threat-model hypotheses; no vulnerabilities confirmed by this document.",
        "",
    ]
    return "\n".join(rows)


def gaps(model) -> str:
    return (
        "# Assumptions and gaps\n\n"
        + NOTICE
        + "\n\n"
        + "\n".join(
            "- " + md(x)
            for x in [
                *model.assumptions,
                *model.exclusions,
                "Source confidence is claim-specific, not proof of controls.",
                "Authoritative 37-risk catalog missing; remaining mappings BLOCKED.",
                "Human acceptance, applicability and residual risk decisions pending.",
            ]
        )
        + "\n"
    )
