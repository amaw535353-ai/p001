"""Local platform adapters, durable ownership journals and independent evidence."""

import json
import os
from pathlib import Path
from datetime import datetime, timezone
from p002.exporters import canonical
from p002.scenarios import ROOT, load_dataset, verify_files
from p002.validation import digest
from p002.adapters.transport import ENDPOINTS, owned_container

RUNTIME = ROOT / ".runtime"


def utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def private_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("symlink refused")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(canonical(value))


def credentials():
    p = RUNTIME / "secrets.json"
    if p.is_symlink() or not p.exists():
        raise RuntimeError("BLOCKED: private local bootstrap credentials absent; run scripts/lab up NAME")
    if p.stat().st_mode & 0o077:
        raise ValueError("local secret file must be mode 0600")
    return json.loads(p.read_text())


class Journal:
    def __init__(self, name, dataset_hash):
        self.path = RUNTIME / (name + "-ownership.json")
        self.name = name
        if self.path.is_symlink():
            raise ValueError("ownership symlink refused")
        self.data = (
            json.loads(self.path.read_text())
            if self.path.exists()
            else {
                "owner": "p002-local-v1",
                "name": name,
                "dataset_sha256": dataset_hash,
                "objects": {},
                "phase": "new",
            }
        )
        if (
            self.data.get("owner") != "p002-local-v1"
            or self.data.get("name") != name
            or self.data.get("dataset_sha256") != dataset_hash
        ):
            raise ValueError("ownership/dataset conflict; refusing adoption")

    def put(self, key, kind, external_id, **metadata):
        self.data["objects"][key] = {"kind": kind, "external_id": external_id, **metadata}
        self.save()
        return self.data["objects"][key]

    def get(self, key):
        return self.data["objects"].get(key)

    def save(self):
        private_write(self.path, self.data)

    def phase(self, phase):
        self.data["phase"] = phase
        self.save()


def observe(platform, case, actor, operation, actual, expected, **extra):
    status = actual
    if expected == "ALLOW":
        passed = 200 <= status < 300
    else:
        passed = status in [401, 403, 404]
    return {
        "id": platform + ":" + case,
        "platform": platform,
        "actor": actor,
        "operation": operation,
        "http_status": status,
        "outcome": "ALLOW" if 200 <= status < 300 else "DENY",
        "expected": expected,
        "origin": "OBSERVED_ENFORCEMENT",
        "utc": utc(),
        "status": "PASS" if passed else "FAIL",
        **extra,
    }


def adapter(name, d, transport="docker"):
    from p002.adapters.platforms import Nextcloud, Redmine, LabelStudio, P001

    cls = {"nextcloud": Nextcloud, "redmine": Redmine, "label-studio": LabelStudio, "p001": P001}[name]
    return cls(d, Journal(name, digest(canonical(d.model_dump(mode="json")))), transport)


def command(args):
    if args.operation == "status":
        return {
            name: {
                "endpoint": url,
                "status": "AVAILABLE" if owned_container(container) else "NOT TESTED",
                "observations": "see evidence/integration-*.json; availability is not a test result",
            }
            for name, (url, container, port) in ENDPOINTS.items()
        }
    if not args.name:
        raise ValueError("--name is required")
    d = load_dataset(args.dataset)
    if args.operation == "dry-run":
        return json.loads((Path(args.dataset) / f"imports/{args.name}.json").read_text())
    if args.target != "lab":
        raise ValueError("explicit --target lab is required")
    obj = adapter(args.name, d, args.transport)
    if args.operation == "cleanup":
        if args.confirm != "p002-local":
            raise ValueError("cleanup requires --confirm p002-local")
        return obj.cleanup()
    if args.operation == "seed":
        obj.seed()
        return {
            "status": "SEEDED",
            "platform": args.name,
            "mapping_path": str(obj.journal.path),
            "owned_objects": len(obj.journal.data["objects"]),
        }
    rows = obj.verify()
    from p002.operations import record_run

    path = record_run(
        "integration-" + args.name,
        rows,
        d,
        args=f"p002 adapters verify --target lab --name {args.name} --transport {args.transport}",
    )
    verify_files(args.dataset)
    if any(r["status"] == "FAIL" for r in rows):
        raise RuntimeError("integration verification failed; see " + str(path))
    return {"status": "PASS", "observations": rows, "evidence": str(path)}
