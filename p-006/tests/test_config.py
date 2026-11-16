import json
import subprocess
from pathlib import Path

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from p006.models import OIDCClient, Profile, Service, digest
from p006.safety import secret_detected

ROOT = Path(__file__).resolve().parents[1]


def test_c01_repository_and_siblings_preserved():
    assert subprocess.check_output(["git", "config", "--get", "remote.origin.url"], cwd=ROOT, text=True).strip().endswith("amaw535353-ai/p001.git")
    base = json.loads((ROOT / "config/repository.json").read_text())["approved_base_commit"]
    changed = subprocess.check_output(["git", "diff", "--name-only", base, "--", "."], cwd=ROOT.parent, text=True).splitlines()
    assert all(p.startswith("p-006/") for p in changed)


def test_c02_hardened_default():
    spec = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert spec["services"]["weak"]["profiles"] == ["weak"]
    assert "profiles" not in spec["services"]["pep"]


def test_c03_weak_cli_requires_confirmation():
    result = subprocess.run([str(ROOT / "scripts/p006"), "up", "--profile", "vulnerable-lab"], cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode != 0


def test_c04_weak_cannot_bind_public():
    spec = yaml.safe_load((ROOT / "compose.yaml").read_text())
    weak = spec["services"]["weak"]
    assert weak["ports"] == ["127.0.0.1:8088:8080"]
    assert weak["networks"] == ["weak"]
    assert spec["networks"]["weak"]["internal"] is True


def test_c05_unknown_config_rejected(profile):
    data = profile.model_dump()
    data["allow_anonymous"] = True
    with pytest.raises(ValidationError):
        Profile.model_validate(data)


def test_c06_mutable_image_rejected():
    with pytest.raises(ValidationError):
        Service(id="opa", image="openpolicyagent/opa:latest", networks=["policy"], port=8181)


def test_c07_committed_inputs_secret_scan():
    count = 0
    for path in ROOT.rglob("*"):
        if any(p in path.parts for p in (".runtime", ".tools", ".venv", "__pycache__", "evidence", "reports",
                                         ".mypy_cache", ".pytest_cache", ".ruff_cache")):
            continue
        if path.is_file():
            assert not secret_detected(path.read_text()), path.relative_to(ROOT)
            count += 1
    assert count > 25


def test_c08_cleanup_refuses_unrelated_resource(monkeypatch):
    import operate
    monkeypatch.setattr(operate, "capture", lambda args: json.dumps([{"Config": {"Labels": {"io.p006.owner": "p001"}}}]))
    with pytest.raises(ValueError, match="unrelated"):
        operate.owned("container", "p006-pep")


def test_duplicate_principal_rejected(profile):
    data = profile.model_dump()
    data["principals"].append(data["principals"][0])
    with pytest.raises(ValidationError):
        Profile.model_validate(data)


def test_wildcard_oidc_redirect_rejected():
    with pytest.raises(ValidationError):
        OIDCClient(id="open-webui", redirect_uris=["http://127.0.0.1:8086/*"], origins=[])


def test_algorithm_config_rejected(profile):
    data = profile.model_dump()
    data["identity"]["algorithms"] = ["HS256"]
    with pytest.raises(ValidationError):
        Profile.model_validate(data)


def test_provider_url_config_rejected(profile):
    data = profile.model_dump()
    data["route"]["backend"] = "https://example.invalid"
    with pytest.raises(ValidationError):
        Profile.model_validate(data)


def test_unknown_tenant_rejected(profile):
    data = profile.model_dump()
    data["tenants"] = [t for t in data["tenants"] if t["id"] != "tenant-b"]
    with pytest.raises(ValidationError):
        Profile.model_validate(data)


def test_policy_permissive_fallback_rejected(profile):
    data = profile.model_dump()
    data["policy"]["default_allow"] = True
    with pytest.raises(ValidationError):
        Profile.model_validate(data)


def test_configuration_hash_canonical(profile):
    data = profile.model_dump()
    assert digest(data) == digest(dict(reversed(list(data.items()))))
    data["requests_per_minute"] -= 1
    assert digest(data) != digest(profile.model_dump())


def test_all_schema_documents_valid():
    for path in (ROOT / "schemas").glob("*.json"):
        jsonschema.Draft202012Validator.check_schema(json.loads(path.read_text()))


def test_published_schemas_match_strict_versioned_models():
    import ast
    from p006 import models
    tree = ast.parse((ROOT / "scripts/build-schemas.py").read_text())
    mapping = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "mapping" for t in node.targets))
    for name, filename in mapping.items():
        expected = getattr(models, name).model_json_schema()
        expected.update({"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": f"urn:p006:{filename}:v1"})
        assert json.loads((ROOT / "schemas" / f"{filename}.schema.json").read_text()) == expected


def test_policy_data_bound_to_reviewed_principal_and_model_registry(profile):
    data = json.loads((ROOT / "policy/opa/data.json").read_text())["p006"]
    assert data["principals"] == {p.subject: {"tenant": p.tenant, "roles": p.roles, "enabled": p.enabled}
                                   for p in profile.principals}
    assert data["models"] == {m.id: {"required_role": m.required_role} for m in profile.models}


def test_inventory_rejects_unresolved_service_endpoint():
    from p006.models import ServiceInventory
    data = json.loads((ROOT / "contracts/architecture/service-inventory.json").read_text())
    data["endpoints"][0]["service_id"] = "unapproved"
    with pytest.raises(ValidationError):
        ServiceInventory.model_validate(data)


def test_gateway_config_matches_fixed_reviewed_routes(profile):
    data = yaml.safe_load((ROOT / "gateway/litellm/config.yaml").read_text())
    assert {m["model_name"] for m in data["model_list"]} == set(profile.route.model_ids)
    assert all(m["litellm_params"]["api_base"] == profile.route.backend for m in data["model_list"])
    assert all(m["litellm_params"]["api_key"].startswith("os.environ/") for m in data["model_list"])


def test_profile_schema_accepts_configuration(profile):
    jsonschema.validate(profile.model_dump(), json.loads((ROOT / "schemas/architecture-profile.schema.json").read_text()))


def test_w05_real_p007_descriptor_validates():
    schema = ROOT.parent / "p-007/schemas/p006-target-adapter.schema.json"
    jsonschema.validate(json.loads((ROOT / "contracts/p006-target-adapter.json").read_text()), json.loads(schema.read_text()))
    assert (ROOT / "schemas/p006-target-adapter-v1.schema.json").read_bytes() == schema.read_bytes()


def test_w06_live_p007_not_claimed_available():
    descriptor = json.loads((ROOT / "contracts/p006-target-adapter.json").read_text())
    assert descriptor["runtime_status"] == "BLOCKED"
    import sys
    sys.path.insert(0, str(ROOT.parent / "p-007/src"))
    from p007.runners import discover
    assert discover("p006").available is False


def test_network_configuration_has_no_external_route():
    import operate
    operate.validate()


def test_network_ui_not_on_model_or_secrets():
    spec = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert set(spec["services"]["webui"]["networks"]) == {"ui", "identity"}
    assert not spec["services"]["opa"].get("ports")
    assert not spec["services"]["vault"].get("ports")
    assert not spec["services"]["litellm"].get("ports")


def test_network_loopback_published_only():
    spec = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert all(port.startswith("127.0.0.1:") for service in spec["services"].values()
               for port in service.get("ports", []))


def test_vault_no_secret_values_in_profile(profile):
    data = profile.model_dump()
    data["identity"]["client_secret"] = "unacceptable-embedded-value"
    with pytest.raises(ValidationError):
        Profile.model_validate(data)


def test_v08_secret_scan_negative_control():
    import secrets
    marker = "P006_" + "DUMMY_SECRET_" + secrets.token_hex(16)
    assert secret_detected("synthetic disposable text " + marker)
    assert not secret_detected("ordinary synthetic fixture")
