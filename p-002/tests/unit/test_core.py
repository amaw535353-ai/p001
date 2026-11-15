import json
import csv
import io
import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from p002.generators import generate
from p002.models import Dataset, Context, NOW
from p002.policies import evaluate
from p002.exporters import build_files, csv_safe, markdown_safe, canonical
from p002.validation import digest


def test_realistic_graph(dataset):
    d = dataset
    assert len(d.tenants) == 2 and len(d.departments) == 6
    assert all(sum(u.department_id == dep.id for u in d.humans) >= 3 for dep in d.departments)
    assert len(d.scenarios) == 12 and d.workloads and d.issues and d.requests
    assert {x.classification.value for x in d.resources} == {
        "PUBLIC",
        "INTERNAL",
        "CONFIDENTIAL",
        "RESTRICTED",
    }
    assert {x.event_type for x in d.business_events} == {
        "onboarding",
        "offboarding",
        "hr-case",
        "invoice-review",
        "engineering-change",
        "procurement",
        "knowledge-retrieval",
    }


def test_schema_round_trip(dataset):
    Draft202012Validator(Dataset.model_json_schema()).validate(dataset.model_dump(mode="json"))
    assert Dataset.model_validate_json(canonical(dataset.model_dump(mode="json"))) == dataset


def test_determinism_and_content_hashes():
    a, b = generate(12, "tiny"), generate(12, "tiny")
    assert build_files(a) == build_files(b)
    assert build_files(generate(13, "tiny"))["dataset.json"] != build_files(a)["dataset.json"]
    files = build_files(a)
    m = json.loads(files["reproducibility.json"])
    assert all(digest(files[p]) == h for p, h in m["files"].items())
    assert digest(m["files"]) == m["content_root_sha256"]


@pytest.mark.parametrize("profile", ["tiny", "standard"])
def test_profiles(profile):
    assert generate(profile=profile).profile == profile


def test_stress_opt_in():
    with pytest.raises(ValueError, match="allow-stress"):
        generate(profile="stress-local")


@pytest.mark.parametrize(
    "mutation",
    [
        "invalid-tenant",
        "dangling",
        "duplicate",
        "label",
        "time",
        "manager",
        "parent-cycle",
        "membership",
        "approval-self",
        "approval-binding",
        "request-binding",
        "lifecycle",
        "oversized",
        "unknown-field",
        "cross-tenant",
        "version",
        "owner",
        "document-hash",
        "annotation",
        "interval",
    ],
)
def test_invalid_graph_rejected(dataset, mutation):
    raw = dataset.model_dump()
    if mutation == "invalid-tenant":
        raw["humans"][0]["tenant_id"] = "p002:missing"
    if mutation == "dangling":
        raw["issues"][0]["project_id"] = "p002:missing"
    if mutation == "duplicate":
        raw["humans"].append(raw["humans"][0])
    if mutation == "label":
        raw["resources"][0]["classification"] = "SECRET-INVALID"
    if mutation == "time":
        raw["humans"][0]["created_at"] = "2026-02-31T00:00:00Z"
    if mutation == "manager":
        raw["humans"][1]["manager_id"] = raw["humans"][1]["id"]
    if mutation == "parent-cycle":
        raw["resources"][0]["parent_id"] = raw["resources"][0]["id"]
    if mutation == "membership":
        raw["memberships"][0]["user_id"] = raw["humans"][3]["id"]
    if mutation == "approval-self":
        raw["approvals"][0]["approver_id"] = raw["requests"][0]["requester_id"]
    if mutation == "approval-binding":
        raw["approvals"][0]["parameters_sha256"] = "0" * 64
    if mutation == "request-binding":
        raw["requests"][0]["parameters"]["amount_cents"] = 0
    if mutation == "lifecycle":
        raw["lifecycle_events"][0]["after"] = "deleted"
    if mutation == "oversized":
        raw["documents"][0]["body"] = "x" * 32769
    if mutation == "unknown-field":
        raw["humans"][0]["password"] = "not-supported"
    if mutation == "cross-tenant":
        raw["grants"][0]["principal_id"] = "p002:tenant-b:hr:u0"
    if mutation == "version":
        raw["versions"][0]["version"] = 2
    if mutation == "owner":
        raw["owners"].pop()
    if mutation == "document-hash":
        raw["documents"][0]["body"] += "tamper"
    if mutation == "annotation":
        raw["annotations"][0]["label_id"] = "p002:tenant-b:label:public"
    if mutation == "interval":
        raw["grants"][0]["valid_until"] = raw["grants"][0]["valid_from"]
    with pytest.raises((ValidationError, ValueError)):
        Dataset.model_validate(raw)


def test_oracle_denominators_and_independent_policy_cases(dataset):
    d = dataset
    p = "p002:tenant-a:hr"
    res = p + ":doc0"
    assert len(d.decisions) == 100
    assert {r.expected for r in d.decisions} == {"ALLOW", "DENY"}
    assert evaluate(d, p + ":u1", "read", res)[0] == "ALLOW"
    assert evaluate(d, "p002:tenant-b:hr:u1", "read", res) == ("DENY", "tenant-boundary", ["tenant-boundary"])
    assert evaluate(d, "p002:tenant-a:finance:u1", "read", res)[0] == "DENY"
    assert evaluate(d, p + ":u1", "read", p + ":doc3")[1] == "explicit-deny-precedence"
    assert evaluate(d, p + ":u2", "read", res)[1] == "inactive-identity"
    assert all(x.origin == "generated oracle" and x.observed_result is None for x in d.decisions)


def test_oracle_corruption_rejected(dataset):
    raw = dataset.model_dump()
    raw["decisions"][0]["expected"] = "DENY"
    with pytest.raises(ValueError, match="oracle"):
        Dataset.model_validate(raw)


def test_temporal_membership_delete_and_grant(dataset):
    d = dataset.model_copy(deep=True)
    d.decisions.clear()
    p = "p002:tenant-a:hr"
    actor = p + ":u1"
    r = p + ":doc0"
    next(x for x in d.memberships if x.user_id == actor).revoked_at = "2026-01-16T00:00:00Z"
    assert evaluate(d, actor, "read", r, Context(time=NOW))[0] == "ALLOW"
    assert evaluate(d, actor, "read", r, Context(time="2026-01-17T00:00:00Z"))[0] == "DENY"
    res = next(x for x in d.resources if x.id == r)
    res.deleted_at = "2026-01-16T00:00:00Z"
    assert evaluate(d, p + ":u0", "read", r, Context(time="2026-01-17T00:00:00Z"))[1] == "resource-not-live"
    res.deleted_at = None
    g = next(x for x in d.grants if x.principal_id == p + ":group")
    g.valid_until = "2026-01-15T12:00:00Z"
    assert evaluate(d, p + ":u0", "read", r)[0] == "DENY"


def test_service_delegation_and_approval(dataset):
    d = dataset
    p = "p002:tenant-a:hr"
    assert evaluate(d, p + ":service", "read", p + ":doc0", Context(caller_id=p + ":u0"))[0] == "ALLOW"
    assert (
        evaluate(
            d, p + ":service", "read", p + ":doc0", Context(caller_id=p + ":u0", time="2026-03-01T00:00:00Z")
        )[0]
        == "DENY"
    )
    assert evaluate(d, p + ":service", "read", p + ":doc0")[0] == "DENY"
    req = d.requests[0]
    assert (
        evaluate(
            d,
            req.requester_id,
            "execute",
            req.resource_id,
            Context(request_id=req.id, parameters_sha256=req.parameters_sha256),
        )[0]
        == "ALLOW"
    )
    assert (
        evaluate(
            d,
            req.requester_id,
            "execute",
            req.resource_id,
            Context(request_id=req.id, parameters_sha256="bad"),
        )[1]
        == "exact-action-binding"
    )


@pytest.mark.parametrize("value", ["=1+1", "+SUM(1)", "-1+1", "@foo", "  =bad", "\t=bad", "\r=bad"])
def test_spreadsheet_neutralization(value):
    assert csv_safe(value).startswith("'")
    s = io.StringIO()
    csv.writer(s).writerow([csv_safe(value)])
    assert next(csv.reader(io.StringIO(s.getvalue())))[0].startswith("'")


def test_untrusted_markup():
    s = markdown_safe("<script>alert(1)</script>[x](https://example.test)`a`")
    assert "<script>" not in s and "[" not in s and "`" not in s


def test_exports_label_and_contracts(dataset):
    f = build_files(dataset)
    assert len([x for x in f if x.endswith(".md") and x.startswith("documents/")]) == len(dataset.documents)
    for name in ["nextcloud", "redmine", "label-studio", "p001"]:
        m = json.loads(f["imports/" + name + ".json"])
        assert m["dry_run"] and not m["external_ids"]
    for r in dataset.humans:
        assert r.email.endswith(".example.test")
    assert all("SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT" in x.body for x in dataset.documents)


def test_generation_has_no_network_dependency(monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("offline generation attempted network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    assert build_files(generate(2026, "tiny"))["dataset.json"]


def test_historical_identity_and_invalid_clock(dataset):
    p = "p002:tenant-a:hr"
    assert (
        evaluate(dataset, p + ":u2", "read", p + ":doc0", Context(time="2026-01-05T00:00:00Z"))[0] == "ALLOW"
    )
    with pytest.raises(ValueError):
        Context(time="2026-02-31T00:00:00Z")


def test_schema_migration_is_explicit(dataset):
    raw = dataset.model_dump()
    raw["schema_version"] = "2.0"
    with pytest.raises(ValueError):
        Dataset.model_validate(raw)


def test_checked_in_golden_fingerprint():
    from p002.scenarios import ROOT

    expected = (ROOT / "fixtures/golden/seed2026-tiny.sha256").read_text().strip()
    assert digest(canonical(generate(2026, "tiny").model_dump(mode="json"))) == expected
