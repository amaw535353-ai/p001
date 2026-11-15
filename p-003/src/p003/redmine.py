"""Opt-in, local-only tracking. Issue states never modify governance approval.

No delete, user management, role changes, remote production targets or write retry.
An uncertain POST must be reconciled by a later read before another create.
"""

import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
from uuid import uuid4

from p003 import NOTICE
from p003.util import canonical, digest, load, safe

ENDPOINT = "http://127.0.0.1:8782"
PROJECT = "p003-synthetic-engagements"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redmine redirect refused")


class HTTP:
    def __init__(self, token):
        if not token:
            raise ValueError("P003_REDMINE_TOKEN missing; supply it privately, never in chat/logs")
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, value=None):
        if not re.fullmatch(r"/[A-Za-z0-9_.?=&,*-]+", path) or method not in ("GET", "POST", "PUT"):
            raise ValueError("unsupported Redmine request")
        body = canonical(value) if value is not None else None
        if value:
            safe(value)
        req = urllib.request.Request(
            ENDPOINT + path,
            body,
            {"X-Redmine-API-Key": self.token, "Content-Type": "application/json"},
            method=method,
        )
        try:
            with self.opener.open(req, timeout=5) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError("oversized Redmine response")
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            return exc.code, {}
        except OSError as exc:
            raise ValueError("local Redmine unavailable; no target/token details logged") from exc


def initialize_ownership(path: Path, confirm: str):
    if confirm != "p003-local" or path.exists() or path.is_symlink():
        raise ValueError("fresh ownership manifest and --confirm p003-local required")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    value: dict = {
        "schema_version": "1.0",
        "owner": "p003-redmine-v1",
        "notice": NOTICE,
        "endpoint": ENDPOINT,
        "project": PROJECT,
        "marker": "p003-owned-" + str(uuid4()),
        "project_id": None,
        "issues": {},
        "pending": {},
    }
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)
    return value


def milestone_items(view):
    items = [
        {
            "key": view.spec.engagement_id + ":v" + str(view.current) + ":review",
            "subject": "Synthetic engagement review required",
            "description": NOTICE
            + "\nRecorded issue status is not legal authorization.\nPolicy digest: "
            + view.spec.content_digest,
        }
    ]
    for event in view.events:
        if event.event_type in ("amend", "stop", "reject"):
            items.append(
                {
                    "key": event.id,
                    "subject": "Synthetic " + event.event_type + " review",
                    "description": NOTICE + "\nEvent reference: " + event.id,
                }
            )
    return items


def sync(items, path: Path, *, write=False, confirm=None, transport=None):
    safe(items)
    if not write:
        return {
            "notice": NOTICE,
            "status": "DRY-RUN",
            "network_requests": 0,
            "endpoint": ENDPOINT,
            "project": PROJECT,
            "proposed_issues": items,
            "governance_effect": "NONE",
        }
    if confirm != "p003-local":
        raise ValueError("write requires --write --confirm p003-local")
    state = load(path)
    if (
        state.get("owner") != "p003-redmine-v1"
        or state.get("notice") != NOTICE
        or state.get("endpoint") != ENDPOINT
        or state.get("project") != PROJECT
        or not re.fullmatch(r"p003-owned-[0-9a-f-]{36}", state.get("marker", ""))
    ):
        raise ValueError("non-owned Redmine manifest")
    transport = transport or HTTP(os.environ.get("P003_REDMINE_TOKEN"))

    def request(method, target, value=None, expected=(200,)):
        code, result = transport.request(method, target, value)
        if code not in expected:
            raise ValueError(f"Redmine capability/request failed: HTTP {code}; no response values logged")
        return code, result

    def save():
        # Private manifest contains only synthetic IDs and ownership metadata, no token.
        temp = path.with_suffix(".tmp")
        if temp.exists() or temp.is_symlink():
            raise ValueError("ownership temporary path collision")
        temp.write_text(json.dumps(state, indent=2) + "\n")
        temp.chmod(0o600)
        os.replace(temp, path)

    # Discover actual server capabilities before any writes. A 403 blocks safely.
    _, current = request("GET", "/users/current.json")
    if not current.get("user", {}).get("id"):
        raise ValueError("authenticated current Redmine user not confirmed")
    _, statuses = request("GET", "/issue_statuses.json")
    opened = [x["id"] for x in statuses.get("issue_statuses", []) if x.get("is_closed") is False]
    _, trackers = request("GET", "/trackers.json")
    tracker_ids = [x["id"] for x in trackers.get("trackers", [])]
    _, fields = request("GET", "/custom_fields.json")
    if not opened or not tracker_ids or any(x.get("is_required") for x in fields.get("custom_fields", [])):
        raise ValueError("required Redmine statuses/trackers/custom-field capability unresolved")
    code, project = request("GET", f"/projects/{PROJECT}.json", expected=(200, 404))
    description = NOTICE + "\n" + state["marker"]
    if code == 404:
        if state["project_id"] is not None:
            raise ValueError("owned project missing; no automatic replacement")
        if "project" in state["pending"]:
            raise ValueError("uncertain project POST; independently reconcile before retry")
        state["pending"]["project"] = state["marker"]
        save()
        _, project = request(
            "POST",
            "/projects.json",
            {
                "project": {
                    "identifier": PROJECT,
                    "name": "P-003 Synthetic Engagements",
                    "description": description,
                    "is_public": False,
                    "enabled_module_names": ["issue_tracking"],
                    "tracker_ids": tracker_ids,
                }
            },
            expected=(201,),
        )
    project = project["project"]
    if (
        project.get("identifier") != PROJECT
        or project.get("description") != description
        or project.get("is_public") is not False
        or (state["project_id"] is not None and project["id"] != state["project_id"])
    ):
        raise ValueError("non-owned Redmine project collision")
    state["project_id"] = project["id"]
    state["pending"].pop("project", None)
    save()
    # Bounded listing refuses truncation instead of accidentally creating duplicates.
    _, listing = request("GET", f"/issues.json?project_id={project['id']}&status_id=*&limit=100&offset=0")
    issues = listing.get("issues", [])
    if listing.get("total_count") != len(issues):
        raise ValueError("incomplete issue reconciliation; no writes")
    for item in items:
        marker = state["marker"] + ":" + item["key"]
        desc = item["description"] + "\n" + marker
        hits = [x for x in issues if x.get("description", "").endswith("\n" + marker)]
        if len(hits) > 1:
            raise ValueError("duplicate issue ownership marker")
        mapped = state["issues"].get(item["key"])
        if mapped is not None and (not hits or hits[0]["id"] != mapped):
            raise ValueError("journaled issue missing or non-owned")
        if hits:
            issue = hits[0]
            if issue.get("subject") != item["subject"] or issue.get("description") != desc:
                raise ValueError("owned issue drift; refuse overwrite")
        else:
            if item["key"] in state["pending"]:
                raise ValueError("uncertain issue POST; independently reconcile before retry")
            state["pending"][item["key"]] = digest(desc)
            save()  # On timeout later sync reconciles listing before considering POST.
            _, result = request(
                "POST",
                "/issues.json",
                {
                    "issue": {
                        "project_id": project["id"],
                        "subject": item["subject"],
                        "description": desc,
                        "tracker_id": tracker_ids[0],
                        "status_id": opened[0],
                    }
                },
                expected=(201,),
            )
            issue = result["issue"]
        _, result = request("GET", f"/issues/{issue['id']}.json")
        observed = result["issue"]
        if (
            observed.get("description") != desc
            or observed.get("subject") != item["subject"]
            or observed.get("project", {}).get("id") != project["id"]
        ):
            raise ValueError("Redmine readback/ownership mismatch")
        state["issues"][item["key"]] = issue["id"]
        state["pending"].pop(item["key"], None)
        save()
    # Confirm project readback as well; no authority flows back into P-003.
    _, readback = request("GET", f"/projects/{PROJECT}.json")
    if readback["project"].get("description") != description:
        raise ValueError("project readback mismatch")
    return {
        "notice": NOTICE,
        "status": "RECONCILED",
        "issues": len(items),
        "governance_effect": "NONE",
        "capabilities": {
            "identity_endpoint": True,
            "open_status_ids": opened,
            "tracker_ids": tracker_ids,
            "custom_fields_inspected": True,
        },
        "server_version": "NOT VERIFIED: REST endpoints do not identify edition/version reliably",
    }
