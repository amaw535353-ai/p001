"""Small safe boolean DSL: no eval, templates, code plugins or network."""

from typing import Any, Literal

from pydantic import Field, model_validator

from p005.domain.schemas import (
    ControlRequirement,
    Mitigation,
    Model,
    Strict,
    ScopeState,
    ThreatScenario,
    Triage,
    VerificationCase,
)
from p005.evidence.safety import DATA, Invalid, digest, load, stable, redact
from p005.modeling.graph import path_for, validate_path
from p005.modeling.risk_catalog import validate_ids

FIELDS = {
    "edge.kind",
    "edge.authorization",
    "edge.delegation",
    "edge.token_audience",
    "edge.approval_binding",
    "edge.encryption",
    "edge.classification",
    "edge.expected_decision",
    "edge.grants_freshness",
    "source.kind",
    "target.kind",
    "source.features.untrusted_content",
    "target.features.privileged_actions",
    "source.features.autonomous",
    "source.features.generates_content",
    "target.features.persistent_memory",
    "target.features.coding_workspace",
    "target.features.egress",
    "target.features.logging",
    "target.features.budget",
    "target.features.retention",
    "target.features.dependency_provenance",
    "source.tenant_id",
    "target.tenant_id",
    "cross_tenant",
}


class Predicate(Strict):
    field: str
    op: Literal["eq", "ne", "in"]
    value: str | bool | list[str]

    @model_validator(mode="after")
    def valid(self):
        if self.field not in FIELDS or (self.op == "in" and not isinstance(self.value, list)):
            raise ValueError("UNSUPPORTED-RULE-PREDICATE")
        return self


class Rule(Strict):
    id: str
    version: Literal["1.0"]
    title: str
    method: str
    risk_ids: list[str]
    all: list[Predicate] = Field(min_length=1, max_length=12)
    any: list[Predicate] = Field(default_factory=list, max_length=12)
    exclude: list[Predicate] = Field(default_factory=list, max_length=12)
    required_evidence: Literal["modeled-flow-with-provenance"]
    preconditions: list[str] = Field(min_length=1)
    attacker_capability: str
    target_behavior: str
    trust_assumption: str
    property: str
    impact: str
    mitigation: str
    positive: str
    negative: str
    falsifier: str
    impact_level: Literal["HIGH", "MEDIUM", "LOW"]


def rules(path=None) -> list[Rule]:
    data = redact(load(path or DATA / "rules.json"))
    if data.get("schema_version") != "p005-rules-1.0" or set(data) != {"schema_version", "rules"}:
        raise Invalid("INCOMPATIBLE-RULE-DSL")
    result = [Rule.model_validate(r) for r in data["rules"]]
    if len(result) > 64 or len({r.id for r in result}) != len(result):
        raise Invalid("RULE-COUNT-OR-ID")
    for rule in result:
        validate_ids(rule.risk_ids)
    return result


def matches(p: Predicate, facts: dict) -> bool:
    actual = facts[p.field]
    if p.op == "eq":
        return actual == p.value
    if p.op == "ne":
        return actual != p.value
    if not isinstance(p.value, list):
        raise Invalid("RULE-IN-REQUIRES-LIST")
    return actual in p.value


def analyze(model: Model, *, rule_path=None, suppressions: dict[str, str] | None = None) -> dict:
    loaded = rules(rule_path)
    suppressions = suppressions or {}
    if any(k not in {r.id for r in loaded} or len(v.strip()) < 8 for k, v in suppressions.items()):
        raise Invalid("SUPPRESSION-REQUIRES-KNOWN-RULE-AND-REASON")
    nodes = {n.id: n for n in model.nodes}
    threats: list[dict[str, Any]] = []
    paths, controls, mitigations, tests, traces = {}, [], [], [], []
    applicable_risks = set()
    for edge in sorted(model.flows, key=lambda e: e.id):
        source, target = nodes[edge.source], nodes[edge.target]
        facts: dict[str, Any] = {}
        for field in FIELDS:
            if field == "cross_tenant":
                facts[field] = source.tenant_id != target.tenant_id and "shared" not in (
                    source.tenant_id,
                    target.tenant_id,
                )
                continue
            root, *parts = field.split(".")
            value = {"edge": edge, "source": source, "target": target}[root]
            for part in parts:
                value = getattr(value, part)
            facts[field] = value
        for rule in loaded:
            fired = (
                all(matches(p, facts) for p in rule.all)
                and (not rule.any or any(matches(p, facts) for p in rule.any))
                and not any(matches(p, facts) for p in rule.exclude)
            )
            if not fired:
                continue
            if len(threats) >= 512:
                raise Invalid("THREAT-CANDIDATE-BUDGET-EXCEEDED")
            if rule.id in suppressions:
                traces.append(
                    dict(rule=rule.id, edge_id=edge.id, state="SUPPRESSED", reason=suppressions[rule.id])
                )
                continue
            key = [rule.id, rule.version, edge.id, edge.tenant_id, target.owner_role, rule.preconditions]
            tid, cid, mid, vid = [stable(k, key) for k in ("threat", "control", "mitigation", "test")]
            path = path_for(model, edge.id)
            paths[path.id] = path.model_dump()
            bids = sorted(b.id for b in model.boundaries if edge.id in b.edge_ids)
            criteria = [
                rule.positive,
                rule.negative,
                "Record deterministic enforcement evidence, not model prose",
            ]
            control = ControlRequirement(
                id=cid,
                threat_id=tid,
                requirement=rule.mitigation,
                owner_role=target.owner_role,
                objective=rule.property,
                acceptance_criteria=criteria,
            )
            mitigation = Mitigation(
                id=mid,
                threat_id=tid,
                control_id=cid,
                owner_role=target.owner_role,
                objective=rule.property,
                functions=["prevent", "detect", "respond", "recover"],
                acceptance_criteria=criteria,
                expected_functionality=rule.mitigation,
                test_ids=[vid],
                residual_unknowns=[
                    "Runtime effectiveness NOT_TESTED",
                    "Alerting, rollback and recovery NOT_TESTED",
                ],
            )
            scope = model.model_scope
            scope_state: ScopeState
            if {source.id, target.id} & set(scope.out_of_scope_node_ids):
                scope_state = "OUT_OF_SCOPE"
            elif {source.id, target.id} <= set(scope.in_scope_node_ids):
                scope_state = "IN_SCOPE_MODEL_ONLY"
            else:
                scope_state = "REQUIRES_NEW_AUTHORIZATION"
            case = VerificationCase(
                test_id=vid,
                threat_id=tid,
                boundary_ids=bids,
                setup_assumptions=rule.preconditions,
                permitted_actor=edge.principal_id or "UNSPECIFIED_REQUIRES_REVIEW",
                forbidden_actor="Different-tenant-or-unapproved-principal",
                positive_path=rule.positive,
                negative_path=rule.negative,
                expected_result="Permit documented positive behavior; deny negative behavior with safe audit evidence",
                required_evidence=[
                    "Human-reviewed authorization",
                    "Sanitized request/decision/audit correlation",
                ],
                prerequisites=[
                    "Independent human acceptance",
                    "Fresh P-003 scope and ROE decision",
                    "Isolated synthetic target; separate authorized execution project",
                ],
                scope_state=scope_state,
                roe_check_state="OUT_OF_SCOPE"
                if scope_state == "OUT_OF_SCOPE"
                else "REQUIRES_NEW_AUTHORIZATION",
            )
            selected = sorted({p.field for p in [*rule.all, *rule.any, *rule.exclude]})
            trace: dict[str, str | list[str]] = {
                "rule_id": rule.id,
                "rule_version": rule.version,
                "rule_digest": digest(rule.model_dump()),
                "input_facts": [f"{f}={facts[f]}" for f in selected],
                "required_evidence": rule.required_evidence,
                "assumptions": rule.preconditions,
                "falsifier": rule.falsifier,
            }
            threat = ThreatScenario(
                threat_id=tid,
                title=rule.title,
                node_ids=[source.id, target.id],
                edge_ids=[edge.id],
                boundary_ids=bids,
                tenant_id=edge.tenant_id,
                risk_ids=rule.risk_ids,
                risk_source="User P-005 prompt, section 5; PROMPT_SUBSET; full taxonomy unavailable",
                analysis_method=[rule.method, "AI-specific"],
                preconditions=rule.preconditions,
                attacker_capability=rule.attacker_capability,
                target_behavior=rule.target_behavior,
                trust_assumption=rule.trust_assumption,
                abuse_path_id=path.id,
                security_property=rule.property,
                business_impact_hypothesis=rule.impact,
                plausibility_rationale="Rule predicates match explicit graph facts; plausibility requires human review",
                confidence=edge.confidence,
                evidence_refs=edge.evidence_refs,
                mitigation_ids=[mid],
                control_ids=[cid],
                test_ids=[vid],
                owner_role=target.owner_role,
                rule_trace=trace,
                revision_history=["Generated candidate; no editorial decision"],
                triage=Triage(
                    potential_impact=rule.impact_level,
                    exposure=edge.epistemic_status,
                    attacker_preconditions=rule.preconditions,
                    evidence_quality=edge.confidence,
                    uncertainty="Connectivity, business impact and enforcement require independent verification",
                    human_review_priority="HIGH" if rule.impact_level == "HIGH" else "MEDIUM",
                    rationale=f"{rule.impact_level} modeled impact assumption; {edge.epistemic_status} source. "
                    "Ordinal review triage, not empirical likelihood or finding severity",
                ),
            )
            threats.append(threat.model_dump())
            controls.append(control.model_dump())
            mitigations.append(mitigation.model_dump())
            tests.append(case.model_dump())
            applicable_risks.update(rule.risk_ids)
    result = dict(
        schema_version="p005-analysis-1.0",
        model_digest=digest(model.model_dump()),
        threats=threats,
        attack_paths=list(paths.values()),
        controls=controls,
        mitigations=mitigations,
        verification_plan=tests,
        suppressions=traces,
        risk_applicability=[
            dict(
                risk_id=rid,
                status="PROPOSED" if rid in applicable_risks else "NOT_APPLICABLE",
                rationale="Matching rule features present"
                if rid in applicable_risks
                else "No matching modeled feature; not a security conclusion",
            )
            for rid in sorted({rid for r in loaded for rid in r.risk_ids})
        ],
    )
    validate_analysis(model, result)
    return result


def validate_analysis(model: Model, result: dict) -> None:
    if result["model_digest"] != digest(model.model_dump()):
        raise Invalid("STALE-ANALYSIS")
    threats = [ThreatScenario.model_validate(t) for t in result["threats"]]
    ids = [t.threat_id for t in threats]
    if len(ids) != len(set(ids)):
        raise Invalid("THREAT-ID-COLLISION")
    path_ids = set()
    for raw in result["attack_paths"]:
        from p005.domain.schemas import ThreatPath

        path = ThreatPath.model_validate(raw)
        validate_path(model, path)
        path_ids.add(path.id)
    table_classes: list[tuple[str, type[Strict], str]] = [
        ("controls", ControlRequirement, "id"),
        ("mitigations", Mitigation, "id"),
        ("verification_plan", VerificationCase, "test_id"),
    ]
    for table, cls, key in table_classes:
        rows = [cls.model_validate(r) for r in result[table]]
        if len({getattr(r, key) for r in rows}) != len(rows) or any(
            r.model_dump()["threat_id"] not in ids for r in rows
        ):
            raise Invalid("ANALYSIS-REFERENCE")
    for threat in threats:
        validate_ids(threat.risk_ids)
        if (
            not set(threat.node_ids) <= {n.id for n in model.nodes}
            or not set(threat.edge_ids) <= {e.id for e in model.flows}
            or not set(threat.boundary_ids) <= {b.id for b in model.boundaries}
            or not set(threat.evidence_refs) <= {e.id for e in model.evidence}
            or threat.abuse_path_id not in path_ids
            or not set(threat.control_ids) <= {c["id"] for c in result["controls"]}
            or not set(threat.mitigation_ids) <= {m["id"] for m in result["mitigations"]}
            or not set(threat.test_ids) <= {t["test_id"] for t in result["verification_plan"]}
        ):
            raise Invalid("THREAT-REFERENCE")
        for table, names, key in [
            ("controls", threat.control_ids, "id"),
            ("mitigations", threat.mitigation_ids, "id"),
            ("verification_plan", threat.test_ids, "test_id"),
        ]:
            if any(r["threat_id"] != threat.threat_id for r in result[table] if r[key] in names):
                raise Invalid("CROSS-THREAT-REFERENCE")
