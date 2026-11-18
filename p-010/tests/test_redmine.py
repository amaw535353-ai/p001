"""Redmine contract fault matrix. Actual product checks run separately."""

import copy
from urllib.parse import parse_qs, urlsplit

import pytest

from p010 import redmine
from p010.demo import AUTHOR, ENGAGEMENT, FINDING, REVIEWER
from p010.models import Finding
from p010.safety import Invalid, canonical
from p010.workflow import Workflow
from test_workflow import REASON, actors, rating


class Fixture:
    def __init__(self):
        self.issues = {}
        self.calls = []
        self.mode = None

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if self.mode == "outage":
            raise redmine.RedmineFailure("Fixture unavailable")
        if path.startswith("/projects/"):
            return {
                "project": {
                    "identifier": redmine.PROJECT,
                    "is_public": False,
                    "id": 1,
                    "description": redmine.DESCRIPTION if self.mode != "unowned" else "Foreign project",
                }
            }
        if path == "/enumerations/issue_priorities.json":
            return {
                "issue_priorities": [
                    {"id": index + 1, "name": title, "active": True}
                    for index, title in enumerate(sorted(set(redmine.PRIORITIES.values())))
                ]
            }
        if path.startswith("/issues.json?"):
            params = parse_qs(urlsplit(path).query)
            result = list(self.issues.values())
            if self.mode == "listing":
                return {"total_count": 2, "issues": []}
            if self.mode == "duplicate" and result:
                result *= 2
            offset = int(params["offset"][0])
            return {"total_count": len(result), "issues": copy.deepcopy(result[offset : offset + 100])}
        if method in ("POST", "PUT"):
            if self.mode == "permission":
                raise redmine.RedmineFailure("Redmine rejected access", rejected=True)
            row = body["issue"]
            issue_id = int(path.split("/")[-1].partition(".")[0]) if method == "PUT" else len(self.issues) + 1
            self.issues[issue_id] = {
                "id": issue_id,
                "project": {"id": row["project_id"]},
                "subject": row["subject"],
                "description": row["description"].replace("\n", "\r\n"),
                "due_date": row["due_date"],
                "priority": {"id": row["priority_id"]},
                "status": {"id": 1},
                "updated_on": "2026-11-18T12:30:00Z",
            }
            if self.mode == "lose-reply":
                raise redmine.RedmineFailure("Response lost")
            if self.mode == "malformed-write":
                return {"issue": {"id": "unknown"}}
            return {"issue": {"id": issue_id}} if method == "POST" else {}
        ident = int(path.split("/")[-1].partition(".")[0])
        return {"issue": copy.deepcopy(self.issues[ident])}


def perform(workspace, api, **kwargs):
    return redmine.synchronize(
        workspace,
        ENGAGEMENT,
        AUTHOR,
        FINDING,
        **{
            "confirmation": "p010-synthetic-local",
            "project": redmine.PROJECT,
            "api": api,
            **kwargs,
        },
    )


def test_M02_dry_run_does_not_invoke_transport(example, monkeypatch):
    monkeypatch.setattr(redmine.LocalRedmine, "connect", lambda: pytest.fail("Dry run reached Redmine"))
    with example.session() as store:
        author, _ = actors(store)
        result = redmine.preview(author, FINDING)
        assert result["status"] == "DRY_RUN"
        assert result["issue"]["project"] == redmine.PROJECT
        assert store.latest("redmine-sync", result["issue"]["key"], required=False) is None


def test_M03_M04_create_idempotently_and_keep_exact_binding(example):
    fixture = Fixture()
    assert perform(example, fixture)["status"] == "SYNCED"
    assert perform(example, fixture)["status"] == "UNCHANGED"
    assert len(fixture.issues) == 1
    assert len([call for call in fixture.calls if call[0] == "POST"]) == 1
    with example.session() as store:
        author, _ = actors(store)
        key = redmine.preview(author, FINDING)["issue"]["key"]
        record = store.current("redmine-sync", key).as_type(redmine.RedmineSync)
        assert record.issue_id == 1 and record.state == "SYNCED"
        assert record.finding.id == FINDING
        assert store.verify()["status"] == "PASS"


def test_M05_denied_write_then_safe_retry(example):
    fixture = Fixture()
    fixture.mode = "permission"
    with pytest.raises(Invalid, match="rejected"):
        perform(example, fixture)
    assert not fixture.issues
    fixture.mode = None
    assert perform(example, fixture)["status"] == "SYNCED"


@pytest.mark.parametrize("mode", ["outage", "listing", "unowned"])
def test_M06_errors_do_not_change_canonical_finding(example, mode):
    fixture = Fixture()
    fixture.mode = mode
    with example.session() as store:
        before = store.current("finding", FINDING).link
    with pytest.raises(Invalid):
        perform(example, fixture)
    with example.session() as store:
        assert store.current("finding", FINDING).link == before
        assert store.verify()["status"] == "PASS"
    assert not fixture.issues


@pytest.mark.parametrize("mode", ["malformed-write", "lose-reply"])
def test_M03_uncertain_write_reconciles_without_reposting(example, mode):
    fixture = Fixture()
    fixture.mode = mode
    with pytest.raises(Invalid):
        perform(example, fixture)
    assert len(fixture.issues) == 1
    fixture.mode = None
    assert perform(example, fixture)["status"] == "RECONCILED"
    assert perform(example, fixture)["status"] == "UNCHANGED"
    assert len([call for call in fixture.calls if call[0] == "POST"]) == 1


def test_M07_remote_edit_and_duplicates_surface_conflict(example):
    fixture = Fixture()
    perform(example, fixture)
    fixture.mode = "duplicate"
    with pytest.raises(Invalid, match="duplicate"):
        perform(example, fixture)
    fixture.mode = None
    fixture.issues[1]["subject"] = "Edited outside P-010"
    with pytest.raises(Invalid, match="changed independently"):
        perform(example, fixture)
    assert fixture.issues[1]["subject"] == "Edited outside P-010"


def test_M07_uncontested_local_change_updates_existing_issue(example):
    fixture = Fixture()
    perform(example, fixture)
    with example.session() as store:
        reviewer = Workflow(store, ENGAGEMENT, REVIEWER)
        reviewer.severity(FINDING, rating(severity="MEDIUM"), REASON, "HUMAN_AUTHORED")
    assert perform(example, fixture)["status"] == "SYNCED"
    assert [call[0] for call in fixture.calls].count("PUT") == 1
    assert len(fixture.issues) == 1


def test_M08_external_state_does_not_close_finding(example):
    fixture = Fixture()
    perform(example, fixture)
    fixture.issues[1]["status"]["id"] = 5
    with pytest.raises(Invalid, match="changed independently"):
        perform(example, fixture)
    with example.session() as store:
        finding = store.current("finding", FINDING).as_type(Finding)
        assert finding.lifecycle == "RESIDUAL_RISK_ACCEPTED"
        assert finding.retest_status == "PENDING_RETEST"


@pytest.mark.parametrize(
    ("project", "confirmation"),
    [
        ("external-client", "p010-synthetic-local"),
        ("p010-synthetic", "write"),
        ("http://example.invalid", "authorized"),
    ],
)
def test_M09_nonlocal_target_never_reaches_transport(example, project, confirmation):
    fixture = Fixture()
    with pytest.raises(Invalid):
        perform(example, fixture, project=project, confirmation=confirmation)
    assert not fixture.calls


def test_M10_ticket_field_projections_exclude_credentials(example, monkeypatch):
    monkeypatch.setenv("P010_LANGFUSE_SECRET_KEY", "P010_SECRET_REDMINE_TEST")
    fixture = Fixture()
    perform(example, fixture)
    assert b"P010_SECRET" not in canonical(fixture.calls)
    assert b"credential" not in canonical(fixture.issues)


def test_Q11_Q12_cleanup_does_not_touch_unowned_resources(monkeypatch):
    with pytest.raises(Invalid, match="confirmation"):
        redmine.down("wrong confirmation")
    monkeypatch.setattr(
        redmine,
        "_inspect",
        lambda *_args, **_kwargs: {
            "Config": {"Labels": {redmine.OWNER_LABEL: "different-owner"}},
            "HostConfig": {},
            "Image": "different",
            "Mounts": [],
        },
    )
    monkeypatch.setattr(
        redmine, "_docker", lambda *_args, **_kwargs: pytest.fail("Unowned resource was mutated")
    )
    with pytest.raises(Invalid, match="ownership"):
        redmine.down("p010-owned-resources")
