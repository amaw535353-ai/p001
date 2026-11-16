#!/usr/bin/env python3
"""Bounded P-006 operator. Never interprets configuration as shell commands."""

import argparse
import json
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
import yaml

from p006.models import Profile
from p006.weak import WARNING

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"
COMPONENTS = ("webui", "keycloak", "opa", "vault", "pep", "litellm", "model", "weak", "bootstrap", "tester")
NETWORKS = ("ui", "identity", "policy", "secrets", "gateway", "model", "weak")


def command(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def capture(args):
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.DEVNULL)


def compose(*args):
    command(["docker", "compose", "-p", "p006", "-f", str(ROOT / "compose.yaml"), *args])


def validate():
    hard = Profile.model_validate_json((ROOT / "config/hardened.json").read_text())
    weak = Profile.model_validate_json((ROOT / "config/vulnerable-lab.json").read_text())
    if hard.name != "hardened" or weak.name != "vulnerable-lab":
        raise ValueError("profile confusion")
    definition = yaml.safe_load((ROOT / "compose.yaml").read_text())
    for name, net in definition["networks"].items():
        if net.get("internal") is not True or net.get("name") != "p006_" + name:
            raise ValueError("network not internal or not owned")
    pins = json.loads((ROOT / "config/images.lock.json").read_text())
    for name, service in definition["services"].items():
        if service.get("privileged") or service.get("network_mode") or service.get("cap_add"):
            raise ValueError("unsupported privilege")
        env = service.get("environment", {})
        if any(env.get(key) for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]):
            raise ValueError("offline services must not inherit a proxy escape route")
        if env.get("NO_PROXY") != "*" or env.get("no_proxy") != "*":
            raise ValueError("internal service routing must bypass inherited proxies")
        if service.get("labels", {}).get("io.p006.owner") != "p006":
            raise ValueError("unowned service")
        for port in service.get("ports", []):
            if not port.startswith("127.0.0.1:"):
                raise ValueError("non-loopback binding")
        for volume in service.get("volumes", []):
            if "docker.sock" in volume:
                raise ValueError("socket forbidden")
        if name in pins and service["image"] != pins[name]:
            raise ValueError("image lock mismatch")
        if name in {"weak", "bootstrap", "tester"} and not service.get("profiles"):
            raise ValueError("unsafe default service")
    for name in {"ui", "identity", "policy", "secrets", "gateway", "model"}:
        actual = {s for s, service in definition["services"].items() if name in service.get("networks", [])
                  and s not in {"bootstrap", "tester"}}
        if actual != set(hard.egress.networks[name]):
            raise ValueError("network membership mismatch")
    schema = json.loads((ROOT.parent / "p-007/schemas/p006-target-adapter.schema.json").read_text())
    jsonschema.validate(json.loads((ROOT / "contracts/p006-target-adapter.json").read_text()), schema)
    print("PASS strict profiles, image locks, segmented deployment and actual P007 descriptor schema")
    return hard


def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("w") as stream:
        stream.write(data if isinstance(data, str) else json.dumps(data))
    path.chmod(0o444)


def prepare(profile):
    """Generate entirely synthetic local identities; never copy environment secrets."""
    if RUNTIME.is_symlink():
        raise ValueError("runtime symlink refused")
    if RUNTIME.exists():
        shutil.rmtree(RUNTIME)
    RUNTIME.mkdir(mode=0o700)
    for directory in ["pep", "gateway", "operator", "model", "webui", "unrelated", "keycloak"]:
        (RUNTIME / directory).mkdir(mode=0o755)
        (RUNTIME / directory).chmod(0o755)
    introspect, oauth, operator = [secrets.token_urlsafe(40) for _ in range(3)]
    write_private(RUNTIME / "pep/introspection-secret", introspect)
    write_private(RUNTIME / "model/provider-key", secrets.token_urlsafe(48))
    write_private(RUNTIME / "operator/clients.json", {"oauth": oauth, "operator": operator})
    users = {p.username: secrets.token_urlsafe(24) for p in profile.principals}
    write_private(RUNTIME / "operator/users.json", users)
    realm = json.loads((ROOT / "identity/keycloak/realm-template.json").read_text())
    for client in realm["clients"]:
        client["secret"] = {"open-webui": oauth, "p006-pep": introspect, "p006-operator": operator}[client["clientId"]]
    realm["users"] = [{"id": p.subject, "username": p.username, "enabled": True,
                       "email": p.username + "@p006.invalid", "emailVerified": True,
                       "firstName": p.username, "lastName": "Synthetic",
                       "attributes": {"tenant": [p.tenant]}, "clientRoles": {"open-webui": p.roles},
                       "credentials": [{"type": "password", "value": users[p.username], "temporary": False}]}
                      for p in profile.principals]
    realm["users"].append({"username": "service-account-p006-operator", "enabled": True,
                           "serviceAccountClientId": "p006-operator", "clientRoles": {
                               "realm-management": ["manage-users", "view-users"]}})
    write_private(RUNTIME / "keycloak/p006-realm.json", realm)
    write_private(RUNTIME / "webui/environment.json", {"OAUTH_CLIENT_SECRET": oauth,
                   "WEBUI_SECRET_KEY": secrets.token_urlsafe(48),
                   "WEBUI_ADMIN_EMAIL": "bootstrap@p006.invalid", "WEBUI_ADMIN_NAME": "Synthetic bootstrap",
                   "WEBUI_ADMIN_PASSWORD": secrets.token_urlsafe(48)})
    (RUNTIME / "profile").write_text("hardened")


def owned(kind, name):
    try:
        data = json.loads(capture(["docker", kind, "inspect", name]))[0]
    except subprocess.CalledProcessError:
        return False
    labels = data.get("Config", {}).get("Labels", {}) if kind == "container" else data.get("Labels", {})
    if labels.get("io.p006.owner") != "p006":
        raise ValueError("name collision with unrelated resource: " + name)
    return True


def down():
    # Explicit inventory only; no global prune, label-wide deletion or image removal.
    helpers = capture(["docker", "ps", "-aq", "--filter", "label=io.p006.owner=p006",
                       "--filter", "label=com.docker.compose.project=p006"]).split()
    for container_id in helpers:
        data = json.loads(capture(["docker", "container", "inspect", container_id]))[0]
        labels = data["Config"].get("Labels", {})
        if (labels.get("com.docker.compose.service") in {"bootstrap", "tester"}
                and labels.get("com.docker.compose.oneoff", "").lower() == "true"
                and owned("container", container_id)):
            command(["docker", "rm", "-f", container_id], stdout=subprocess.DEVNULL)
    for service in COMPONENTS:
        name = "p006-" + service
        if owned("container", name):
            command(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL)
    for network in NETWORKS:
        name = "p006_" + network
        if owned("network", name):
            command(["docker", "network", "rm", name], stdout=subprocess.DEVNULL)
    print("P006 owned containers/networks removed; evidence retained")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["doctor", "validate", "up", "down", "cleanup", "status",
                                           "live", "compare", "evidence", "verify"])
    parser.add_argument("--profile", choices=["hardened", "vulnerable-lab"], default="hardened")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.action == "doctor":
        print("P006 profile=hardened; host=127.0.0.1:8086,8087; model=deterministic-local; network=internal")
        print("Python", sys.version.split()[0])
        command(["docker", "version", "--format", "Docker {{.Server.Version}}"])
        command(["docker", "compose", "version"])
        print("Browser port publishing, optional inference, other hosts and Kubernetes require live checks.")
        return
    if args.action == "validate":
        validate()
    elif args.action == "up":
        profile = validate()
        if args.profile == "vulnerable-lab":
            if args.confirm != "local-synthetic-only":
                raise ValueError("weak profile requires CONFIRM=local-synthetic-only")
            print(WARNING, flush=True)
            compose("--profile", "weak", "up", "-d", "weak")
            return
        for service in COMPONENTS:
            if owned("container", "p006-" + service):
                raise ValueError("stack exists; use status/down before a fresh bootstrap")
        prepare(profile)
        lock_hash = __import__("hashlib").sha256((ROOT / "requirements.lock").read_bytes()).hexdigest()
        try:
            image = json.loads(capture(["docker", "image", "inspect", "p006-runtime:1.0.0"]))[0]
            current_lock = image["Config"].get("Labels", {}).get("io.p006.requirements")
        except subprocess.CalledProcessError:
            current_lock = None
        if current_lock != lock_hash:
            compose("build", "pep")
        compose("up", "-d", "vault", "keycloak", "opa", "model")
        bootstrap = subprocess.run(["docker", "compose", "-p", "p006", "--profile", "tools", "run", "--rm",
                                    "-T", "--no-deps", "bootstrap"], cwd=ROOT, capture_output=True, text=True, timeout=120)
        if bootstrap.returncode:
            raise ValueError("Vault bootstrap failed; captured credentials and output withheld")
        roles = json.loads(bootstrap.stdout)["roles"]
        if set(roles) != {"pep", "gateway", "operator", "unrelated"}:
            raise ValueError("unexpected bootstrap roles")
        for role, credential in roles.items():
            write_private(RUNTIME / role / "approle.json", credential)
        print("Vault bootstrap completed; root revoked; narrow AppRole credentials delivered privately")
        compose("up", "-d", "pep", "litellm", "webui")
        compose("--profile", "tools", "run", "--rm", "-T", "--no-deps", "tester", "provision")
        print("Started hardened; local UI=127.0.0.1:8086; Keycloak=127.0.0.1:8087; no public egress")
    elif args.action == "down":
        down()
    elif args.action == "cleanup":
        if args.confirm != "p006-owned-resources":
            raise ValueError("cleanup requires CONFIRM=p006-owned-resources")
        down()
        if RUNTIME.is_symlink():
            raise ValueError("symlink refused")
        if RUNTIME.exists():
            shutil.rmtree(RUNTIME)
        print("Synthetic runtime credentials/state removed; evidence/reports retained")
    elif args.action == "status":
        compose("--profile", "weak", "ps", "-a")
    elif args.action == "live":
        validate()
        command([sys.executable, "scripts/live.py"])
    elif args.action == "compare":
        command([sys.executable, "-m", "pytest", "tests", "-k", "weak", "-v"])
    elif args.action in {"evidence", "verify"}:
        validate()
        command([sys.executable, "scripts/verify.py"])


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError):
        raise SystemExit("BLOCKED: operator action refused or dependency failed; inspect readiness and configuration") from None
