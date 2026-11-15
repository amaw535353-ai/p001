from copy import deepcopy
import json

import jsonschema
import pytest
import yaml

from p003 import adapters, demo, exports, frameworks, redmine
from p003.models import Engagement
from p003.util import ROOT, digest, load, write_output


def test_aisvs_official_text_version_and_levels():
    result = frameworks.framework_report()
    assert result["sources"]["aisvs"]["commit"] == "3ae3af45c363467b8ad823ef79219236e67ca22f"
    row = frameworks.catalog()["v1.01-C5.2.5"]
    assert row["level"] == 2
    assert (
        row["exact_text"]
        == "**Verify that** the policy decision point for agent authorization is isolated from the agent's execution environment."
    )
    assert len(frameworks.catalog()) == 11


@pytest.mark.parametrize(
    "change",
    [
        {"requirement_id": "v1.01-C5.99.99"},
        {"version": "1.0"},
        {"exact_text": "Invented requirement wording"},
        {"level": 1},
        {"state": "passed"},
    ],
)
def test_unknown_or_altered_framework_claim_rejected(change):
    raw = demo.engagement().model_dump(mode="json")
    raw["requirements"][0].update(change)
    # Remove root digest so this test exercises requirement validation, not only hash rejection.
    raw.pop("content_digest")
    with pytest.raises(ValueError):
        Engagement.model_validate(raw)


def test_oscal_draft_truthfully_rejected_by_official_schema():
    result = frameworks.oscal_draft(demo.engagement())
    assert result["kind"] == "oscal-mapping-draft"
    assert result["conformance"] == "NOT VALID OSCAL"
    assert result["validation"]["observed"] == "REJECT"
    assert result["validation"]["errors"]
    assert any("import-ssp" in x["oscal_field"] and "UNSUPPORTED" in x["status"] for x in result["coverage"])
    assert frameworks.oscal_errors({"assessment-plan": {"uuid": "invalid"}})


def test_strict_json_schema_roundtrip(active):
    spec = active.read("ENG-DEMO-A", "demo-a-owner").spec
    raw = spec.model_dump(mode="json")
    jsonschema.validate(raw, json.loads((ROOT / "schemas/engagement.schema.json").read_text()))
    raw["unexpected"] = "field"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(raw, Engagement.model_json_schema())
    assert Engagement.model_validate(yaml.safe_load(yaml.safe_dump(spec.model_dump(mode="json")))) == spec


def test_safe_exports_and_manifest_hashes(active):
    view = active.read("ENG-DEMO-A", "demo-a-assessor")
    for result in (
        exports.policy_manifest(view),
        exports.evidence_manifest(view),
        frameworks.oscal_draft(view.spec),
    ):
        assert result["content_digest"] == digest({k: v for k, v in result.items() if k != "content_digest"})
        assert result["notice"] == demo.engagement().notice
    manifest = exports.evidence_manifest(view)
    assert manifest["artifacts"][-1]["sha256"] == view.events[-1].content_digest
    text = exports.markdown(view)
    body, footer = text.split("\nDocument SHA-256 (all bytes before this line): ")
    assert digest(body.encode()) == footer.strip()
    assert "[UNFILLED]" in text and "NOT VERIFIED" in text and "NOT DEMONSTRATED" in text


@pytest.mark.parametrize(
    "raw,suffix",
    [
        (b'{"a":1,"a":2}', ".json"),
        (b"a: 1\na: 2\n", ".yaml"),
        (b"a: &v [1]\nb: *v", ".yaml"),
        (b"a: !!python/object:foo {}", ".yaml"),
        (b"bad: [\n", ".yaml"),
        (b"\xff", ".yaml"),
        (b'{"value": NaN}', ".json"),
        (b"x" * (2 * 1024 * 1024 + 1), ".json"),
    ],
)
def test_unsafe_file_parsing_fails(tmp_path, raw, suffix):
    path = tmp_path / ("bad" + suffix)
    path.write_bytes(raw)
    with pytest.raises((ValueError, yaml.YAMLError)):
        load(path)


def test_sensitive_input_and_path_traversal_outputs_refused(tmp_path):
    path = tmp_path / "secret.json"
    path.write_text(json.dumps({"credential": "ghp_" + "a" * 36}))
    with pytest.raises(ValueError):
        load(path)
    with pytest.raises(ValueError):
        write_output(tmp_path / "leak.md", "a synthetic text")
    with pytest.raises(ValueError):
        write_output(ROOT / "generated/../../leak.md", "a synthetic text")


def test_markdown_escapes_active_html(active):
    from p003.models import sealed

    view = active.read("ENG-DEMO-A", "demo-a-assessor")
    spec = sealed(
        Engagement, **{**view.spec.model_dump(mode="json"), "goals": ["<script>alert('untrusted');</script>"]}
    )
    view.versions[view.current] = spec
    result = exports.markdown(view)
    assert "<script>" not in result and "&lt;script&gt;" in result


def test_actual_p001_source_readonly_inventory():
    root = ROOT.parent
    if not (root / "infra/kubernetes/resources.json").exists():
        pytest.skip("P-001 source absent; optional sibling integration")
    before = (root / "infra/kubernetes/resources.json").read_bytes()
    value = adapters.p001_inventory(root)
    assert {x["tenant"] for x in value["assets"]} == {"tenant-a", "tenant-b"}
    assert {x["selector"]["value"] for x in value["assets"]} == {
        "http://127.0.0.1:8081/readyz",
        "http://127.0.0.1:8082/readyz",
    }
    assert all(not x["included"] for x in value["assets"])
    assert value["provenance"]["runtime"].startswith("NOT TESTED")
    assert (root / "infra/kubernetes/resources.json").read_bytes() == before


def test_actual_p002_validated_data_not_authorization():
    root = ROOT.parent / "p-002"
    if not (root / ".venv/bin/python").exists() or not (root / "generated/standard/dataset.json").exists():
        pytest.skip("P-002 core/dataset absent; optional sibling integration")
    value = adapters.p002_inventory(root, root / "generated/standard")
    context = value["imported_context"]
    assert len(context["tenants"]) == 2 and context["scenarios"]
    assert all(x["p003_role"] == "UNASSIGNED" for x in context["actors"])
    assert all(not x["included"] for x in value["assets"])
    assert "never imported as authorization" in context["oracle"]
    assert "decisions" not in context


class Stub:
    """Contract stub, never reported as live Redmine verification."""

    def __init__(self):
        self.project = None
        self.issues = []
        self.calls = []
        self.required_field = False
        self.truncated = False
        self.timeout_once = False

    def request(self, method, path, value=None):
        self.calls.append((method, path, value))
        if path == "/users/current.json":
            return 200, {"user": {"id": 1}}
        if path == "/issue_statuses.json":
            return 200, {"issue_statuses": [{"id": 1, "is_closed": False}]}
        if path == "/trackers.json":
            return 200, {"trackers": [{"id": 1}]}
        if path == "/custom_fields.json":
            return 200, {"custom_fields": [{"id": 7, "is_required": self.required_field}]}
        if path == f"/projects/{redmine.PROJECT}.json":
            return (200, {"project": deepcopy(self.project)}) if self.project else (404, {})
        if method == "POST" and path == "/projects.json":
            self.project = {"id": 123, **value["project"]}
            return 201, {"project": deepcopy(self.project)}
        if path.startswith("/issues.json?"):
            return 200, {
                "issues": deepcopy(self.issues),
                "total_count": len(self.issues) + int(self.truncated),
            }
        if method == "POST" and path == "/issues.json":
            issue = {"id": len(self.issues) + 1, **value["issue"], "project": {"id": 123}}
            self.issues.append(issue)
            if self.timeout_once:
                self.timeout_once = False
                raise ValueError("simulated lost POST response")
            return 201, {"issue": deepcopy(issue)}
        if method == "GET" and path.startswith("/issues/"):
            issue_id = int(path.split("/")[-1].split(".")[0])
            return 200, {"issue": deepcopy(next(x for x in self.issues if x["id"] == issue_id))}
        raise AssertionError((method, path))


@pytest.fixture
def redmine_case(tmp_path, active):
    manifest = tmp_path / "ownership.json"
    redmine.initialize_ownership(manifest, "p003-local")
    view = active.read("ENG-DEMO-A", "demo-a-assessor")
    return redmine.milestone_items(view), manifest, Stub()


def test_redmine_dry_run_zero_network(redmine_case):
    items, manifest, stub = redmine_case
    result = redmine.sync(items, manifest, transport=stub)
    assert result["status"] == "DRY-RUN" and not stub.calls


def test_redmine_idempotent_contract_and_readback(redmine_case):
    items, manifest, stub = redmine_case
    for _ in range(2):
        result = redmine.sync(items, manifest, write=True, confirm="p003-local", transport=stub)
        assert result["status"] == "RECONCILED" and result["governance_effect"] == "NONE"
    assert len(stub.issues) == 1
    assert len([x for x in stub.calls if x[0] == "POST"]) == 2  # one project + one issue
    assert all(x[0] != "DELETE" for x in stub.calls)


def test_redmine_uncertain_post_reconciles_without_duplicate(redmine_case):
    items, manifest, stub = redmine_case
    stub.timeout_once = True
    with pytest.raises(ValueError):
        redmine.sync(items, manifest, write=True, confirm="p003-local", transport=stub)
    assert len(stub.issues) == 1
    redmine.sync(items, manifest, write=True, confirm="p003-local", transport=stub)
    assert len(stub.issues) == 1


@pytest.mark.parametrize(
    "mode", ["project-collision", "issue-drift", "required-field", "truncation", "confirmation"]
)
def test_redmine_nonowned_or_unresolved_refused(redmine_case, mode):
    items, manifest, stub = redmine_case
    confirm = "p003-local"
    if mode == "project-collision":
        stub.project = {
            "id": 123,
            "identifier": redmine.PROJECT,
            "description": "Someone else's project",
            "is_public": False,
        }
    elif mode == "required-field":
        stub.required_field = True
    elif mode == "truncation":
        stub.truncated = True
    elif mode == "confirmation":
        confirm = "wrong"
    elif mode == "issue-drift":
        redmine.sync(items, manifest, write=True, confirm=confirm, transport=stub)
        stub.issues[0]["subject"] = "Unrelated issue content"
    posts = len([x for x in stub.calls if x[0] == "POST"])
    with pytest.raises(ValueError):
        redmine.sync(items, manifest, write=True, confirm=confirm, transport=stub)
    assert len([x for x in stub.calls if x[0] == "POST"]) == posts + (1 if mode == "truncation" else 0)


def test_redmine_transport_no_remote_redirect_or_delete():
    transport = redmine.HTTP("local-test-placeholder")
    with pytest.raises(ValueError):
        transport.request("DELETE", "/issues/1.json")
    with pytest.raises(ValueError):
        transport.request("GET", "https://example.com/issues.json")
    with pytest.raises(ValueError):
        redmine.NoRedirect().redirect_request(None, None, 302, None, None, "https://example.com")
    with pytest.raises(ValueError):
        redmine.HTTP(None)
