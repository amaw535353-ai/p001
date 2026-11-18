"""Redmine issue synchronization for the network-disabled P-010 fixture."""

import fcntl
import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlencode

from p010.models import Finding, RedmineSync, Remediation, Retest
from p010.safety import ROOT, Invalid, canonical, digest, now, parse, report_text, timestamp
from p010.store import Version, Workspace
from p010.workflow import Workflow

IMAGE = (
    "docker.io/library/redmine:7.0.3@sha256:d1733887bbc92c096042eebd035b6f0b18d90e3a8e3925abd817c9fea9c0a50b"
)
IMAGE_CONFIG = "sha256:b27c9c51ca298b6a26fcefcfe6d9552b1da0f0343d759dbecd6da063f725535e"
NAME = "p010-redmine"
VOLUME = "p010-redmine-files"
OWNER_LABEL = "io.p010.owner"
PROJECT = "p010-synthetic"
DESCRIPTION = "P-010 owned synthetic local remediation project v1"
PRIORITIES = {"UNRATED": "Normal", "LOW": "Low", "MEDIUM": "Normal", "HIGH": "High", "CRITICAL": "Immediate"}
MAP_VERSION = "p010-redmine-map-1.0"


class RedmineFailure(Invalid):
    def __init__(self, reason: str, *, rejected: bool = False):
        super().__init__(reason)
        self.rejected = rejected


class RedmineAPI(Protocol):
    def request(self, method: str, path: str, body: dict | None = None) -> dict: ...


def _docker(
    *args: str, body: bytes | None = None, timeout: float = 30, allow_missing: bool = False
) -> bytes | None:
    try:
        result = subprocess.run(
            ["docker", *args],
            input=body,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RedmineFailure("Local Docker daemon or fixture is unavailable") from None
    if result.returncode != 0:
        if allow_missing and b"no such" in result.stderr.lower():
            return None
        raise RedmineFailure("Local Docker fixture command failed")
    if len(result.stdout) > 1024 * 1024:
        raise RedmineFailure("Local Redmine reply exceeds the byte limit")
    return result.stdout


def _inspect(kind: str, name: str, *, missing: bool = False) -> dict | None:
    raw = _docker("inspect", "--type", kind, name, allow_missing=missing)
    if raw is None:
        return None
    [record] = parse(raw)
    return record


def _container(*, missing: bool = False) -> dict | None:
    item = _inspect("container", NAME, missing=missing)
    if item is None:
        return None
    config, host = item["Config"], item["HostConfig"]
    mounts = item["Mounts"]
    if (
        (config.get("Labels") or {}).get(OWNER_LABEL) != "p010"
        or item["Image"] != IMAGE_CONFIG
        or host["NetworkMode"] != "none"
        or host["Privileged"]
        or host.get("PortBindings")
        or host.get("Binds")
        or len(mounts) != 1
        or mounts[0].get("Name") != VOLUME
        or mounts[0]["Destination"] != "/usr/src/redmine/files"
    ):
        raise Invalid("Redmine container ownership or network isolation check failed")
    return item


def _volume(*, missing: bool = False) -> dict | None:
    item = _inspect("volume", VOLUME, missing=missing)
    if item and (item.get("Labels") or {}).get(OWNER_LABEL) != "p010":
        raise Invalid("Redmine volume ownership check failed")
    return item


def doctor() -> dict:
    mem_limit_path = Path("/sys/fs/cgroup/memory.max")
    try:
        limit = mem_limit_path.read_text().strip()
    except OSError:
        limit = "max"
    disk = shutil.disk_usage(ROOT).free
    memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    if limit.isdecimal():
        memory = min(memory, int(limit))
    cpus = len(os.sched_getaffinity(0))
    return {
        "cpu_count": cpus,
        "memory_bytes": memory,
        "disk_free_bytes": disk,
        "ready": disk >= 2**30 and memory >= 2 * 2**30 and cpus >= 1,
    }


def up() -> dict:
    if not doctor()["ready"]:
        raise Invalid("Redmine fixture needs one CPU, 2 GiB accessible memory and 1 GiB free disk")
    container = _container(missing=True)
    if container is None:
        if _volume(missing=True) is None:
            _docker("volume", "create", "--label", f"{OWNER_LABEL}=p010", VOLUME)
        _docker(
            "run",
            "-d",
            "--name",
            NAME,
            "--label",
            f"{OWNER_LABEL}=p010",
            "--network",
            "none",
            "--memory",
            "1g",
            "--cpus",
            "1",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            f"type=volume,source={VOLUME},target=/usr/src/redmine/files",
            IMAGE,
            "rails",
            "server",
            "-b",
            "127.0.0.1",
            timeout=240,
        )
        container = _container()
    assert container is not None
    _volume()
    if not container["State"]["Running"]:
        _docker("start", container["Id"])
    live = LocalRedmine(container["Id"])
    for _ in range(45):
        try:
            live.raw("GET", "/login", None, auth="none")
            break
        except RedmineFailure:
            time.sleep(1)
    else:
        raise RedmineFailure("Local Redmine did not become ready")
    _docker(
        "exec",
        "-i",
        "--user",
        "redmine",
        container["Id"],
        "bundle",
        "exec",
        "rails",
        "runner",
        "-",
        body=(ROOT / "redmine/bootstrap.rb").read_bytes(),
        timeout=90,
    )
    remote_project(live)
    return {"status": "PASS", "project": PROJECT, "version": "7.0.3", "image": IMAGE}


def down(confirmation: str) -> dict:
    if confirmation != "p010-owned-resources":
        raise Invalid("Redmine cleanup requires the P-010 ownership confirmation")
    container = _container(missing=True)
    volume = _volume(missing=True)
    if container is not None:
        if container["State"]["Running"]:
            _docker("stop", "--time", "10", container["Id"])
        _docker("rm", container["Id"])
    if volume is not None:
        _docker("volume", "rm", VOLUME)
    if _container(missing=True) or _volume(missing=True):
        raise Invalid("P-010 Redmine cleanup could not verify resource removal")
    return {"status": "PASS", "container_removed": bool(container), "volume_removed": bool(volume)}


class LocalRedmine:
    def __init__(self, container_id: str, auth: Literal["sync", "reader"] = "sync"):
        self.container_id = container_id
        self.auth = auth

    @classmethod
    def connect(cls, auth: Literal["sync", "reader"] = "sync") -> "LocalRedmine":
        container = _container()
        assert container is not None
        _volume()
        if not container["State"]["Running"]:
            raise RedmineFailure("Local Redmine is not running")
        return cls(container["Id"], auth)

    def raw(self, method: str, path: str, body: dict | None, *, auth: str) -> dict:
        envelope = canonical({"method": method, "path": path, "body": body, "auth": auth})
        code = (ROOT / "redmine/request.rb").read_text()
        reply = _docker(
            "exec", "-i", "--user", "redmine", self.container_id, "ruby", "-e", code, body=envelope
        )
        assert reply is not None
        try:
            decoded = parse(reply)
            status = decoded["status"]
            result = decoded["body"]
        except (Invalid, KeyError, TypeError):
            raise RedmineFailure("Malformed Redmine response") from None
        if type(status) is not int:
            raise RedmineFailure("Malformed Redmine response status")
        if status not in {200, 201, 204}:
            reason = "Redmine rejected access" if status in {401, 403} else "Redmine rejected the request"
            raise RedmineFailure(
                reason if status < 500 else "Redmine service failure",
                rejected=status in {400, 401, 403, 404, 409, 422},
            )
        return result

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        response = self.raw(method, path, body, auth=self.auth)
        if response is None and method == "PUT":
            return {}
        if not isinstance(response, dict):
            raise RedmineFailure("Malformed Redmine JSON response")
        return response


def _positive(value: Any) -> int:
    if type(value) is not int or value <= 0:
        raise RedmineFailure("Malformed Redmine identity")
    return value


def remote_project(api: RedmineAPI) -> int:
    project = api.request("GET", f"/projects/{PROJECT}.json").get("project")
    if (
        not isinstance(project, dict)
        or project.get("identifier") != PROJECT
        or project.get("is_public") is not False
        or project.get("description") != DESCRIPTION
    ):
        raise RedmineFailure("Redmine project failed the synthetic ownership check")
    return _positive(project.get("id"))


def _json_fields(issue: dict) -> dict:
    if (
        not isinstance(issue, dict)
        or not isinstance(issue.get("project"), dict)
        or not isinstance(issue.get("priority"), dict)
    ):
        raise RedmineFailure("Malformed Redmine issue")
    try:
        valid = {
            "project_id": _positive(issue["project"]["id"]),
            "subject": issue["subject"],
            "description": issue["description"],
            "priority_id": _positive(issue["priority"]["id"]),
            "due_date": issue.get("due_date"),
        }
    except KeyError:
        raise RedmineFailure("Malformed Redmine issue fields") from None
    if not isinstance(valid["subject"], str) or not isinstance(valid["description"], str):
        raise RedmineFailure("Malformed Redmine issue content")
    valid["description"] = valid["description"].replace("\r\n", "\n")
    return valid


def _fingerprint(issue: dict) -> str:
    stamp = issue.get("updated_on")
    status = issue.get("status")
    if not isinstance(stamp, str) or not isinstance(status, dict):
        raise RedmineFailure("Redmine issue lacks a revision or status")
    timestamp(stamp)
    return digest(
        {
            **_json_fields(issue),
            "updated_on": stamp,
            "status": _positive(status.get("id")),
            "assigned_to": issue.get("assigned_to"),
            "tracker": issue.get("tracker"),
        }
    )


def _key(flow: Workflow, finding: Version) -> str:
    return "P010-" + digest([flow.id, finding.link.id])[:28]


def _planned(flow: Workflow, finding: Version) -> dict:
    data = finding.as_type(Finding)
    if data.validation_status != "CONFIRMED" or data.lifecycle == "CLOSED":
        raise Invalid("Redmine sync requires an active confirmed finding")
    rows = flow.store.versions(flow.id, current=True)
    actions = [
        row.data
        for row in rows
        if isinstance(row.data, Remediation) and row.data.finding.id == finding.link.id
    ]
    retests = [
        row.link.id for row in rows if isinstance(row.data, Retest) and row.data.finding.id == finding.link.id
    ]
    excerpts = [
        "Training issue. Assessment evidence remains in the local P-010 store.",
        f"Finding version {finding.link.version}",
        report_text(data.title),
        "Retest references " + ", ".join(report_text(ref) for ref in retests),
    ]
    for action in actions:
        excerpts.append(
            " — ".join(
                report_text(text) for text in (action.recommendation, action.owner_ref, action.target_date)
            )
        )
    return {
        "key": _key(flow, finding),
        "project": PROJECT,
        "subject": f"[P-010] {data.title[:180]}",
        "description": _key(flow, finding) + "\n\n" + "\n\n".join(excerpts)[:6000],
        "priority": PRIORITIES[data.severity.severity if data.severity else "UNRATED"],
        "due_date": min((action.target_date for action in actions), default=None),
        "mapping_version": MAP_VERSION,
    }


def preview(flow: Workflow, finding_id: str) -> dict:
    finding = flow.current("finding", finding_id)
    payload = _planned(flow, finding)
    flow.audit("redmine-preview", "Prepared a local issue dry run without contacting Redmine", [finding.link])
    return {"status": "DRY_RUN", "issue": payload}


def _matching(api: RedmineAPI, project: int, key: str) -> list[dict]:
    issues = []
    for offset in range(0, 500, 100):
        query = urlencode({"project_id": project, "status_id": "*", "limit": 100, "offset": offset})
        reply = api.request("GET", "/issues.json?" + query)
        page, total = reply.get("issues"), reply.get("total_count")
        if (
            not isinstance(page, list)
            or type(total) is not int
            or total < 0
            or total > 500
            or len(page) != min(100, max(0, total - offset))
        ):
            raise RedmineFailure("Redmine issue listing is incomplete or exceeds the limit")
        for row in page:
            fields = _json_fields(row)
            if fields["project_id"] != project:
                raise RedmineFailure("Unexpected Redmine issue project")
            if fields["description"].split("\n", 1)[0] == key:
                issues.append(row)
        if offset + len(page) == total:
            break
    return issues


@contextmanager
def _lock(workspace: Workspace) -> Iterator[None]:
    workspace._owned()
    # The fixture project is shared by every P-010 workspace.
    runtime = ROOT / ".runtime"
    if runtime.is_symlink():
        raise Invalid("Redmine runtime symlinks are refused")
    runtime.mkdir(mode=0o700, exist_ok=True)
    workspace._private(runtime, directory=True)
    path = runtime / "redmine-sync.lock"
    fd = os.open(path, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    try:
        workspace._private(path)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def synchronize(
    workspace: Workspace,
    engagement_id: str,
    actor: str,
    finding_id: str,
    *,
    confirmation: str,
    project: str,
    api: RedmineAPI | None = None,
) -> dict:
    if confirmation != "p010-synthetic-local" or project != PROJECT:
        raise Invalid("Write confirmation and project must identify the P-010 synthetic fixture")
    with _lock(workspace):
        try:
            if api is None:
                api = LocalRedmine.connect()
            return _sync(workspace, engagement_id, actor, finding_id, api)
        except Invalid:
            with workspace.session() as store:
                flow = Workflow(store, engagement_id, actor)
                flow.audit(
                    "redmine-refused", "Redmine sync stopped on access, integrity or reconciliation check"
                )
            raise


def _sync(workspace: Workspace, engagement: str, actor: str, finding_id: str, api: RedmineAPI) -> dict:
    with workspace.session() as store:
        flow = Workflow(store, engagement, actor)
        flow.require("AUTHOR", "REMEDIATION_OWNER")
        finding = flow.current("finding", finding_id)
        plan = _planned(flow, finding)
        key = plan["key"]
        prior_version = store.latest("redmine-sync", key, required=False)
        prior = prior_version.as_type(RedmineSync) if prior_version else None

    project_id = remote_project(api)
    priorities = api.request("GET", "/enumerations/issue_priorities.json").get("issue_priorities")
    if not isinstance(priorities, list) or any(not isinstance(row, dict) for row in priorities):
        raise RedmineFailure("Redmine priority list is malformed")
    matches = [row for row in priorities if row.get("name") == plan["priority"] and row.get("active", True)]
    if len(matches) != 1:
        raise RedmineFailure("Redmine priority mapping is unavailable")
    safe = {
        "project_id": project_id,
        "subject": plan["subject"],
        "description": plan["description"],
        "priority_id": _positive(matches[0].get("id")),
        "due_date": plan["due_date"],
    }
    expected = digest(safe)
    rows = _matching(api, project_id, key)
    if len(rows) > 1:
        raise RedmineFailure("Redmine has duplicate synchronization keys")
    found = rows[0] if rows else None
    issue_id = _positive(found.get("id")) if found else None
    if prior and prior.state in {"PENDING_CREATE", "PENDING_UPDATE"}:
        if (
            found
            and digest(_json_fields(found)) == prior.expected_fields
            and (prior.issue_id is None or prior.issue_id == issue_id)
        ):
            return _binding(workspace, engagement, actor, prior_version, prior, found, "RECONCILED")
        raise RedmineFailure("Previous Redmine write is unresolved. Reconciliation is required.")
    if prior and prior.state in {"SYNCED", "REJECTED"} and prior.issue_id is not None:
        if not found or issue_id != prior.issue_id or prior.remote_fingerprint != _fingerprint(found):
            raise RedmineFailure("Redmine issue changed independently. Reconciliation is required.")
        if digest(_json_fields(found)) == expected:
            with workspace.session() as store:
                flow = Workflow(store, engagement, actor)
                flow.audit(
                    "redmine-unchanged", "Verified the existing local issue and binding", [finding.link]
                )
            return {"status": "UNCHANGED", "issue_id": issue_id, "finding": finding.link.id}
    elif found:
        raise RedmineFailure("Unbound Redmine issue uses the selected synchronization key")

    intent = RedmineSync(
        finding=finding.link,
        sync_key=key,
        state="PENDING_UPDATE" if issue_id else "PENDING_CREATE",
        issue_id=issue_id,
        expected_fields=expected,
        remote_fingerprint=_fingerprint(found) if found else None,
    )
    with workspace.session() as store:
        flow = Workflow(store, engagement, actor)
        if flow.current("finding", finding_id).link != finding.link:
            raise RedmineFailure("Finding changed during Redmine preview")
        planned = flow.save(
            "redmine-sync",
            key,
            intent,
            "redmine-intent",
            "Recorded local write intent",
            prior_version.link if prior_version else None,
        )
    try:
        if issue_id:
            current = api.request("GET", f"/issues/{issue_id}.json").get("issue")
            if not isinstance(current, dict) or _fingerprint(current) != intent.remote_fingerprint:
                raise RedmineFailure("Redmine issue changed before update", rejected=True)
            api.request("PUT", f"/issues/{issue_id}.json", {"issue": safe})
        else:
            response = api.request("POST", "/issues.json", {"issue": safe}).get("issue")
            if not isinstance(response, dict):
                raise RedmineFailure("Redmine did not confirm the created issue")
            issue_id = _positive(response.get("id"))
    except RedmineFailure as error:
        if error.rejected:
            with workspace.session() as store:
                flow = Workflow(store, engagement, actor)
                flow.save(
                    "redmine-sync",
                    key,
                    intent.model_copy(update={"state": "REJECTED"}),
                    "redmine-rejected",
                    "Local API definitively rejected the write",
                    planned.link,
                )
        raise
    matched = api.request("GET", f"/issues/{issue_id}.json").get("issue")
    if (
        not isinstance(matched, dict)
        or matched.get("id") != issue_id
        or digest(_json_fields(matched)) != expected
    ):
        raise RedmineFailure("Redmine write readback failed")
    return _binding(workspace, engagement, actor, planned, intent, matched, "SYNCED")


def _binding(
    workspace: Workspace,
    engagement: str,
    actor: str,
    prior: Version | None,
    intent: RedmineSync,
    remote: dict,
    status: str,
) -> dict:
    issue_id = _positive(remote.get("id"))
    record = intent.model_copy(
        update={
            "state": "SYNCED",
            "issue_id": issue_id,
            "remote_fingerprint": _fingerprint(remote),
            "synced_at": now(),
        }
    )
    with workspace.session() as store:
        flow = Workflow(store, engagement, actor)
        assert prior is not None
        flow.save(
            "redmine-sync",
            intent.sync_key,
            record,
            "redmine-bound",
            "Read back and verified local issue identity",
            prior.link,
        )
    return {"status": status, "issue_id": issue_id, "finding": intent.finding.id}
