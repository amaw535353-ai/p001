"""Own-resource-only Compose lifecycle. Never prune or alter host/kernel settings."""

import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess

from p009.safety import ROOT, Blocked, Invalid, canonical, digest, load, write_new

LABEL = "io.p009.owner"


def run(args: list[str], *, env=None, input=None, timeout=180, include_stderr=False) -> str:
    try:
        result = subprocess.run(
            args, cwd=ROOT, env=env, input=input, text=True, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("LOCAL-PROCESS-UNAVAILABLE-OR-TIMEOUT") from None
    if result.returncode:
        from uuid import uuid4

        write_new(
            ROOT / "work" / ("failure-" + uuid4().hex + ".txt"),
            (result.stdout + result.stderr).encode()[:1_048_576],
        )
        # Product output may contain credentials or payloads; expose a fixed failure class only.
        raise Blocked("LOCAL-PRODUCT-COMMAND-FAILED")
    return result.stdout + (result.stderr if include_stderr else "")


def resources() -> dict:
    info = json.loads(run(["docker", "info", "--format", "{{json .}}"], timeout=10))
    return {
        "cpus": info["NCPU"],
        "memory_bytes": info["MemTotal"],
        "free_disk_bytes": shutil.disk_usage(ROOT).free,
        "storage_driver": info["Driver"],
        "vm_max_map_count": int(open("/proc/sys/vm/max_map_count").read()),
        "docker": info["ServerVersion"],
    }


def credentials():
    path = ROOT / ".runtime/credentials.json"
    if not path.exists():
        values = {
            key: secrets.token_urlsafe(32)
            for key in (
                "P009_COLLECTOR_TOKEN",
                "P009_OPERATOR_TOKEN",
                "P009_VIEWER_B_TOKEN",
                "P009_OTLP_PASSWORD",
            )
        }
        values["P009_OTLP_HTPASSWD"] = (
            "producer:{SHA}"
            + base64.b64encode(hashlib.sha1(values["P009_OTLP_PASSWORD"].encode()).digest()).decode()
        )
        write_new(path, canonical(values))
    values = load(path)
    return {
        **os.environ,
        **values,
        "P009_DEPLOYMENT_DIGEST": digest(
            {"compose": load_yaml(ROOT / "compose.yaml"), "config": load(ROOT / "config/defaults.json")}
        ),
    }


def load_yaml(path):
    import yaml

    return yaml.safe_load(path.read_text())


def compose(*args, timeout=180):
    return run(
        ["docker", "compose", "-f", str(ROOT / "compose.yaml"), *args], env=credentials(), timeout=timeout
    )


def assert_owned(kind: str, name: str):
    if kind not in {"container", "network", "volume"}:
        raise Invalid("RESOURCE-KIND")
    result = subprocess.run(["docker", kind, "inspect", name], cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        return
    value = json.loads(result.stdout)[0]
    labels = value.get("Labels", value.get("Config", {}).get("Labels", {})) or {}
    if labels.get(LABEL) != "p009":
        raise Invalid("UNOWNED-RESOURCE-COLLISION")


def preflight():
    for kind, names in {
        "container": ["p009-archive-1", "p009-collector-1", "p009-model-backend-1"],
        "network": ["p009-core"],
        "volume": ["p009-archive"],
    }.items():
        for name in names:
            assert_owned(kind, name)


def runtime_status(tenant="tenant-a"):
    """Read-only process/ingestion state; historical checks are labelled separately."""
    result = {
        "configured_images": load(ROOT / "config/images.lock.json"),
        "containers": [],
        "native_archive": "NOT_RUNNING",
        "last_verification": {},
    }
    for profile in ("core", "langfuse", "wazuh"):
        paths = sorted((ROOT / ".runtime/live").glob(profile + "-*.json"), key=lambda p: p.stat().st_mtime)
        if paths:
            value = load(paths[-1])
            result["last_verification"][profile] = value["counts"]
    try:
        output = run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                "label=" + LABEL + "=p009",
                "--format",
                "{{.Names}}\t{{.State}}\t{{.Image}}",
            ],
            timeout=10,
        )
        # A full Docker ps JSON projection requests expensive filesystem-size walks on vfs.
        rows = [
            dict(zip(("Names", "State", "Image"), line.split("\t", 2), strict=True))
            for line in output.splitlines()
            if line.strip()
        ]
        result["containers"] = [
            {"name": r["Names"], "process_state": r["State"], "image": r["Image"]} for r in rows
        ]
        if (
            any(r["Names"] == "p009-archive-1" and r["State"] == "running" for r in rows)
            and (ROOT / ".runtime/credentials.json").exists()
        ):
            from p009.live import probe

            response = probe("archive", "/status", auth="operator" if tenant == "tenant-a" else "other")
            result["native_archive"] = (
                json.loads(response["body"]) if response["status"] == 200 else "UNAVAILABLE"
            )
    except (Blocked, ValueError, KeyError):
        result["native_archive"] = "UNAVAILABLE"
    return result


def up(profile="core"):
    if profile not in {"core", "langfuse", "wazuh", "full"}:
        raise Invalid("PROFILE-UNKNOWN")
    host = resources()
    if host["free_disk_bytes"] < 3_000_000_000 or host["memory_bytes"] < 2_000_000_000:
        raise Blocked("CORE-RESOURCE-BOUND")
    preflight()
    if profile == "full" and host["vm_max_map_count"] < 262144:
        raise Blocked("WAZUH-INDEXER-VM-MAX-MAP-COUNT")
    if profile != "core":
        from p009.products import product_up

        return product_up(profile, host)
    run(["docker", "volume", "create", "--label", LABEL + "=p009", "p009-archive"])
    run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--label",
            LABEL + "=p009",
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "--security-opt",
            "no-new-privileges",
            "-v",
            "p009-archive:/data",
            "p009-app:local",
            "python",
            "-c",
            "import os;os.chown('/data',1000,1000);os.chmod('/data',0o700)",
        ]
    )
    compose("up", "-d", "archive", "collector", "model-backend", timeout=180)
    return {"status": "STARTED", "profile": profile, "host": host}


def down():
    preflight()
    compose("--profile", "run", "down", "--timeout", "10")
    from p009.products import product_down

    product_down()
    return {"status": "STOPPED", "evidence": "retained", "credentials": "retained until cleanup"}


def cleanup(confirm):
    if confirm != "p009-owned-resources":
        raise Invalid("CLEANUP-CONFIRMATION")
    preflight()
    down()
    # Remove the exact owned disposable native volume; preserve local archive/history.
    for name in (
        "p009-archive",
        "p009-postgres",
        "p009-clickhouse",
        "p009-minio",
        "p009-redis",
        "p009-clickhouse-logs",
    ):
        assert_owned("volume", name)
        result = subprocess.run(["docker", "volume", "inspect", name], capture_output=True)
        if result.returncode == 0:
            run(["docker", "volume", "rm", name])
    for name in ("credentials.json", "product-secrets.json"):
        path = ROOT / ".runtime" / name
        if path.exists():
            path.unlink()
    return {
        "status": "PASS",
        "scope": "exact p009 Docker resources and runtime credentials",
        "local_evidence": "retained; use tenant retention workflow for deletion",
    }
