"""Actual checkout boundaries and read-only execution of the actual P006 audit emitter."""

import ast
import importlib.util
import json
import logging
import os
import subprocess
import sys
import uuid
from types import SimpleNamespace

from p009.adapters import p006_event
from p009.operate import assert_owned, cleanup
from p009.safety import REPO, Invalid, digest, read


def test_scope_has_no_sibling_changes():
    base = (
        "origin/" + os.environ["GITHUB_BASE_REF"]
        if os.environ.get("GITHUB_BASE_REF")
        else "85302ea391f11df403630416b5dbf0decda831d3"
    )
    result = subprocess.run(
        ["git", "diff", "--name-only", base],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    assert all(
        p.startswith("p-009/") or p == ".github/workflows/p009-offline.yml"
        for p in result.stdout.splitlines()
    )


def test_runtime_and_evidence_ignored():
    paths = [
        "p-009/.runtime/archive/objects/one.json",
        "p-009/evidence/generated.json",
        "p-009/.env",
        "p-009/work/raw.txt",
        "p-009/.venv/pyvenv.cfg",
        "p-009/reports/generated.json",
    ]
    result = subprocess.run(
        ["git", "check-ignore", *paths], cwd=REPO, capture_output=True, text=True, check=True
    )
    assert set(result.stdout.splitlines()) == set(paths)


def test_cleanup_confirmation_refuses_before_docker(monkeypatch):
    def forbidden(*_, **__):
        raise AssertionError("must not touch Docker")

    monkeypatch.setattr(subprocess, "run", forbidden)
    import pytest

    with pytest.raises(Invalid):
        cleanup("unrelated")


def test_unowned_named_resource_collision_refused(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0, stdout=json.dumps([{"Config": {"Labels": {"io.p001.owner": "p001"}}}])
        ),
    )
    import pytest

    with pytest.raises(Invalid):
        assert_owned("container", "p009-archive-1")


def test_actual_p006_authorize_emits_observed_schema(cfg, caplog):
    """Execute its actual method with fixture dependencies; no live P006 stack claim."""
    models_path = REPO / "p-006/src/p006/models.py"
    spec = importlib.util.spec_from_file_location("p009_test_actual_p006_models", models_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    source = read(REPO / "p-006/src/p006/pep.py")
    tree = ast.parse(source)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Engine")
    method = next(n for n in cls.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "authorize")
    namespace = {
        "Action": str,
        "AuthzRequest": module.AuthzRequest,
        "uuid": uuid,
        "json": json,
        "audit": logging.getLogger("p009.actual-p006-emitter"),
        "Denied": Invalid,
    }
    exec(  # noqa: S102 -- executes the actual pinned sibling method with fixture dependencies
        compile(ast.Module(body=[method], type_ignores=[]), str(REPO / "p-006/src/p006/pep.py"), "exec"),
        namespace,
    )
    principal = SimpleNamespace(
        subject="00000000-0000-4000-8000-000000000001", tenant="tenant-a", roles=["user"]
    )

    async def verify(_):
        return principal

    async def reserve(*_):
        return None

    async def decide(_):
        return SimpleNamespace(allow=True, reason="ALLOW", policy_version="p006-authz-v1")

    engine = SimpleNamespace(
        profile=SimpleNamespace(models=[SimpleNamespace(id="local-basic")]),
        identity=SimpleNamespace(verify=verify),
        limits=SimpleNamespace(reserve=reserve),
        policy=SimpleNamespace(decide=decide),
    )
    with caplog.at_level(logging.INFO, logger="p009.actual-p006-emitter"):
        coroutine = namespace["authorize"](engine, "synthetic-token", "chat", "local-basic", None)
        try:
            coroutine.send(None)
        except StopIteration as completed:
            _, decision = completed.value
        else:
            raise AssertionError("Fixture dependencies must finish without event-loop I/O")
    payload = json.loads(caplog.records[-1].message)
    assert payload["decision_id"] == decision and "request_id" not in payload
    normalized = p006_event(cfg, payload, "2026-11-16T12:00:00Z")
    assert normalized.request_id is None and normalized.correlation_status == "partial"
    assert len(digest(source)) == 64
