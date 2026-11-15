"""Sequential owned Docker labs. Never starts public listeners or calls production."""

import argparse
import json
import secrets
import shutil
import subprocess
import time
from p002.adapters import RUNTIME, credentials, private_write
from p002.adapters.transport import Client, owned_container
from p002.scenarios import ROOT

IMAGES = {
    "nextcloud": "nextcloud@sha256:25d07d3091844c87c5f812037f5281b5d61fbb47f2c3f125274baabfe6f3ed1b",
    "redmine": "redmine@sha256:a37d315fe55c3aafa5a38a9d1a02d7d761335a21a9b38a4b4037fecee607f28a",
    "label-studio": "heartexlabs/label-studio@sha256:afcc516a22775a39d0d66f4c2ddc95d01be3e3d3862b21fcf4f9de34b4ad4e12",
    "http": "python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f",
    "s3": "localstack/localstack@sha256:3ebc37595918b8accb852f8048fef2aff047d465167edd655528065b07bc364a",
}
NETWORK = "p002-local-internal"


def docker(*args, input=None):
    p = subprocess.run(["docker", *args], input=input, text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(
            "Docker operation failed: " + args[0] + "; output redacted (may contain credentials)"
        )
    return p.stdout.strip()


def exists(name, kind="container"):
    return subprocess.run(["docker", kind, "inspect", name], capture_output=True).returncode == 0


def prepare_secrets():
    if (RUNTIME / "secrets.json").exists():
        return credentials()
    users = {
        f"p002-{t}-{dept}-u{i}": secrets.token_urlsafe(32)
        for t in ["tenant-a", "tenant-b"]
        for dept in ["hr", "finance", "engineering"]
        for i in [0, 1]
    }
    s = {
        n: {
            "admin_user": "p002admin" if n != "label-studio" else "p002admin@example.test",
            "admin_password": secrets.token_urlsafe(32),
            "users": dict(users),
        }
        for n in ["nextcloud", "redmine", "label-studio"]
    }
    s["redmine"]["secret_key_base"] = secrets.token_hex(64)
    s["label-studio"]["api_token"] = secrets.token_hex(20)
    private_write(RUNTIME / "secrets.json", s)
    return s


def run(name, image, env=None, command=(), user=None):
    if exists(name):
        if not owned_container(name):
            raise ValueError("pre-existing unowned container name: " + name)
        # Never automatically adopt stopped/incompatible owned instances.
        running = docker("inspect", "--format", "{{.State.Running}}", name)
        if running != "true":
            raise ValueError("owned container stopped; explicitly tear down this lab before restarting")
        return
    args = ["run", "-d", "--name", name, "--label", "owner=p002-local-v1", "--network", NETWORK]
    if env:
        path = RUNTIME / (name + ".env")
        if path.is_symlink():
            raise ValueError("symlink refused")
        # env values never enter command arguments or process output.
        fd = __import__("os").open(
            path, __import__("os").O_WRONLY | __import__("os").O_CREAT | __import__("os").O_TRUNC, 0o600
        )
        with __import__("os").fdopen(fd, "w") as f:
            f.write("\n".join(k + "=" + v for k, v in env.items()) + "\n")
        args += ["--env-file", str(path)]
    if user:
        args += ["--user", user]
    docker(*args, image, *command)


def up(name):
    if name not in ["nextcloud", "redmine", "label-studio", "p001"]:
        raise ValueError("unknown lab name")
    service = "p002-p001-api" if name == "p001" else "p002-" + name
    image = "p001-workload:local" if name == "p001" else IMAGES[name]
    cached = subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
    minimum = (2 if cached else 8) * 2**30
    if not exists(service) and shutil.disk_usage(ROOT).free < minimum:
        raise ValueError(f"need at least {minimum // 2**30} GiB free for this sequential optional lab")
    others = [
        x
        for x in ["nextcloud", "redmine", "label-studio", "p001-api"]
        if x not in [name, "p001-api" if name == "p001" else name] and exists("p002-" + x)
    ]
    if others:
        raise ValueError("run labs sequentially; first down " + ",".join(others))
    s = prepare_secrets()
    if exists(NETWORK, "network"):
        if docker("network", "inspect", "--format", '{{index .Labels "owner"}}', NETWORK) != "p002-local-v1":
            raise ValueError("unowned network collision")
    else:
        docker("network", "create", "--internal", "--label", "owner=p002-local-v1", NETWORK)
    run("p002-http", IMAGES["http"], command=("sleep", "infinity"))
    if name == "nextcloud":
        run(
            "p002-nextcloud",
            IMAGES[name],
            {
                "SQLITE_DATABASE": "p002",
                "NEXTCLOUD_ADMIN_USER": s[name]["admin_user"],
                "NEXTCLOUD_ADMIN_PASSWORD": s[name]["admin_password"],
                "NEXTCLOUD_TRUSTED_DOMAINS": "p002-nextcloud localhost",
            },
        )
        wait(name, "/status.php", lambda status, body: status == 200 and json.loads(body).get("installed"))
        # Supported local config, no external email/connectivity checks.
        docker(
            "exec",
            "--user",
            "www-data",
            "p002-nextcloud",
            "php",
            "occ",
            "config:system:set",
            "has_internet_connection",
            "--type=boolean",
            "--value=false",
        )
        docker(
            "exec",
            "--user",
            "www-data",
            "p002-nextcloud",
            "php",
            "occ",
            "config:system:set",
            "appstoreenabled",
            "--type=boolean",
            "--value=false",
        )
        version = docker(
            "exec", "--user", "www-data", "p002-nextcloud", "php", "occ", "status", "--output=json"
        )
    elif name == "redmine":
        run("p002-redmine", IMAGES[name], {"SECRET_KEY_BASE": s[name]["secret_key_base"]})
        wait(name, "/login", lambda status, body: status == 200)
        docker(
            "exec",
            "-e",
            "REDMINE_LANG=en",
            "p002-redmine",
            "bundle",
            "exec",
            "rake",
            "redmine:load_default_data",
            "RAILS_ENV=production",
        )
        bootstrap = """require 'json'
s=JSON.parse(STDIN.read)
u=User.find_by(login:'admin') || User.find_by(login:'p002admin')
raise 'bootstrap admin missing' unless u
u.login='p002admin'; u.password=s['admin_password']; u.password_confirmation=s['admin_password'];u.must_change_passwd=false;u.mail_notification='none';u.save!
Setting.rest_api_enabled='1';Setting.default_language='en'
r=Role.find_or_initialize_by(name:'P002Analyst');r.permissions=[:view_issues,:add_issues,:edit_issues,:add_issue_notes];r.save!
puts Redmine::VERSION.to_s
"""
        version = docker(
            "exec",
            "-i",
            "p002-redmine",
            "bundle",
            "exec",
            "rails",
            "runner",
            "-e",
            "production",
            bootstrap,
            input=json.dumps(s[name]),
        )
    elif name == "label-studio":
        run(
            "p002-label-studio",
            IMAGES[name],
            {
                "LABEL_STUDIO_USERNAME": s[name]["admin_user"],
                "LABEL_STUDIO_PASSWORD": s[name]["admin_password"],
                "LABEL_STUDIO_USER_TOKEN": s[name]["api_token"],
                "LABEL_STUDIO_ENABLE_LEGACY_API_TOKEN": "true",
                "LABEL_STUDIO_DISABLE_SIGNUP_WITHOUT_LINK": "true",
                "COLLECT_ANALYTICS": "false",
                "SENTRY_DSN": "",
                "DJANGO_DB": "sqlite",
            },
        )
        wait(name, "/health", lambda status, body: status == 200)
        version = docker(
            "exec",
            "p002-label-studio",
            "python",
            "-c",
            'import importlib.metadata; print(importlib.metadata.version("label-studio"))',
        )
    else:
        run(
            "p002-p001-s3",
            IMAGES["s3"],
            {"SERVICES": "s3", "DNS_ADDRESS": "0", "DISABLE_EVENTS": "1", "SKIP_SSL_CERT_DOWNLOAD": "1"},
            command=(),
        )
        # Add only the P-001-required fixed DNS alias on our own internal network.
        aliases = json.loads(docker("inspect", "p002-p001-s3"))[0]["NetworkSettings"]["Networks"][
            NETWORK
        ].get("Aliases", [])
        aliases = aliases or []
        if "localstack.emulator.svc.cluster.local" not in aliases:
            docker("network", "disconnect", NETWORK, "p002-p001-s3")
            docker(
                "network",
                "connect",
                "--alias",
                "localstack.emulator.svc.cluster.local",
                NETWORK,
                "p002-p001-s3",
            )
        for _ in range(60):
            q = subprocess.run(
                [
                    "docker",
                    "exec",
                    "p002-p001-s3",
                    "python",
                    "-c",
                    "import urllib.request;assert urllib.request.urlopen('http://127.0.0.1:4566/_localstack/health').status==200",
                ],
                capture_output=True,
            )
            if q.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("BLOCKED: P-001 emulator readiness")
        code = "import boto3;from botocore.config import Config;s=boto3.client('s3',endpoint_url='http://127.0.0.1:4566',aws_access_key_id='test',aws_secret_access_key='test',region_name='us-east-1',config=Config(proxies={}));existing={b['Name'] for b in s.list_buckets()['Buckets']};[s.create_bucket(Bucket=b) for b in ['p001-tenant-a','p001-tenant-b'] if b not in existing]"
        docker("exec", "p002-p001-s3", "python", "-c", code)
        image = "p001-workload:local"
        docker("image", "inspect", image)
        run(
            "p002-p001-api",
            image,
            {
                "P001_TENANT": "tenant-a",
                "P001_S3_ENDPOINT": "http://localstack.emulator.svc.cluster.local:4566",
            },
        )
        wait(name, "/readyz", lambda status, body: status == 200 and json.loads(body).get("simulator"))
        version = "P-001 existing workload image ID " + docker(
            "image", "inspect", "--format", "{{.Id}}", image
        )
    private_write(
        RUNTIME / (name + "-version.json"),
        {"name": name, "image": IMAGES.get(name, "p001-workload:local"), "version": version},
    )
    return {
        "status": "READY",
        "name": name,
        "version": version,
        "exposure": "internal-only; docker exec HTTP transport",
    }


def wait(name, path, check):
    c = Client(name, "lab", transport="docker")
    for _ in range(150):
        try:
            status, body, _ = c.request("GET", path)
            if check(status, body):
                return
        except (RuntimeError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError("BLOCKED: " + name + " did not reach functional readiness; private logs remain local")


def down(name, confirm):
    if confirm != "p002-local":
        raise ValueError("teardown requires --confirm p002-local")
    if name not in ["nextcloud", "redmine", "label-studio", "p001", "all"]:
        raise ValueError("unknown lab name")
    selected = ["nextcloud", "redmine", "label-studio", "p001"] if name == "all" else [name]
    for item in selected:
        containers = ["p002-p001-api", "p002-p001-s3"] if item == "p001" else ["p002-" + item]
        for n in containers:
            if exists(n):
                if not owned_container(n):
                    raise ValueError("refusing non-owned teardown")
                # -v removes only anonymous volumes attached to this owned lab instance.
                docker("rm", "-f", "-v", n)
        journal = RUNTIME / (item + "-ownership.json")
        if journal.exists():
            v = json.loads(journal.read_text())
            if v.get("owner") != "p002-local-v1":
                raise ValueError("unowned journal")
            archive = RUNTIME / "retired"
            archive.mkdir(exist_ok=True)
            target = archive / (item + "-" + str(time.time_ns()) + ".json")
            journal.rename(target)
    active = [
        n
        for n in ["p002-nextcloud", "p002-redmine", "p002-label-studio", "p002-p001-api", "p002-p001-s3"]
        if exists(n)
    ]
    if not active:
        if exists("p002-http"):
            if not owned_container("p002-http"):
                raise ValueError("unowned helper")
            docker("rm", "-f", "p002-http")
        if exists(NETWORK, "network"):
            if (
                docker("network", "inspect", "--format", '{{index .Labels "owner"}}', NETWORK)
                != "p002-local-v1"
            ):
                raise ValueError("unowned network")
            docker("network", "rm", NETWORK)
    return {"status": "removed-only-owned-lab", "name": name}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("operation", choices=["up", "down"])
    p.add_argument("name", choices=["nextcloud", "redmine", "label-studio", "p001", "all"])
    p.add_argument("--confirm")
    a = p.parse_args()
    try:
        result = up(a.name) if a.operation == "up" else down(a.name, a.confirm)
        print(json.dumps(result))
        return 0
    except (RuntimeError, ValueError) as e:
        print(json.dumps({"status": "BLOCKED", "error": str(e)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
