"""Run the network-disabled native Redmine fixture and check supported behavior."""

import argparse
from tempfile import TemporaryDirectory
from pathlib import Path

from p010 import redmine
from p010.demo import AUTHOR, ENGAGEMENT, FINDING, REVIEWER, run
from p010.models import Finding, SeverityInput
from p010.safety import Invalid, canonical
from p010.store import Workspace
from p010.workflow import Workflow


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True, choices=["p010-owned-resources"])
    args = parser.parse_args()
    rows = {}

    with TemporaryDirectory(prefix="p010-native-redmine-") as temp:
        workspace = Workspace(Path(temp) / "native")
        run(workspace)
        config = {"confirmation": "p010-synthetic-local", "project": redmine.PROJECT}
        try:
            rows["product"] = redmine.up()
            api = redmine.LocalRedmine.connect()
            project = redmine.remote_project(api)
            with workspace.session() as store:
                flow = Workflow(store, ENGAGEMENT, AUTHOR)
                before = store.current("finding", FINDING)
                preview = redmine.preview(flow, FINDING)
            key = preview["issue"]["key"]
            if redmine._matching(api, project, key):
                raise Invalid("Native check needs a fresh owned Redmine fixture")
            rows["dry_run_zero_issues"] = True
            try:
                redmine.synchronize(
                    workspace,
                    ENGAGEMENT,
                    AUTHOR,
                    FINDING,
                    **config,
                    api=redmine.LocalRedmine.connect("reader"),
                )
            except redmine.RedmineFailure as error:
                if not error.rejected or redmine._matching(api, project, key):
                    raise Invalid("Read-only role refusal could not be verified") from None
            else:
                raise Invalid("Read-only Redmine role unexpectedly wrote")
            rows["read_only_role_denied"] = True
            first = redmine.synchronize(workspace, ENGAGEMENT, AUTHOR, FINDING, **config)
            repeat = redmine.synchronize(workspace, ENGAGEMENT, AUTHOR, FINDING, **config)
            if (
                first["status"] != "SYNCED"
                or repeat["status"] != "UNCHANGED"
                or first["issue_id"] != repeat["issue_id"]
            ):
                raise Invalid("Native sync did not retain the created issue identity")
            if len(redmine._matching(api, project, key)) != 1:
                raise Invalid("Native sync found duplicate or unavailable issue")
            rows["created_and_repeated"] = {
                "first": first["status"],
                "repeat": repeat["status"],
                "issue_id": first["issue_id"],
            }
            with workspace.session() as store:
                reviewer = Workflow(store, ENGAGEMENT, REVIEWER)
                finding = reviewer.current("finding", FINDING).as_type(Finding)
                assert finding.severity is not None
                reviewer.severity(
                    FINDING,
                    SeverityInput(
                        **(
                            finding.severity.model_dump(
                                exclude={
                                    "rubric_version",
                                    "rubric_sha256",
                                    "suggested_severity",
                                    "decision",
                                }
                            )
                            | {"severity": "MEDIUM"}
                        )
                    ),
                    "Synthetic test decision for an uncontested Redmine update.",
                    "TRAINING_FIXTURE",
                )
            updated = redmine.synchronize(workspace, ENGAGEMENT, AUTHOR, FINDING, **config)
            if updated["status"] != "SYNCED" or updated["issue_id"] != first["issue_id"]:
                raise Invalid("Native update did not preserve the bound issue identity")
            rows["updated_existing_issue"] = True
            issue_id = first["issue_id"]
            route = f"/issues/{issue_id}.json"
            api.request(
                "PUT", route, {"issue": {"subject": "Changed by a separate synthetic fixture operator"}}
            )
            try:
                redmine.synchronize(workspace, ENGAGEMENT, AUTHOR, FINDING, **config)
            except redmine.RedmineFailure as error:
                if "changed independently" not in str(error):
                    raise
            else:
                raise Invalid("Native conflict was overwritten")
            snapshot = api.request("GET", route)["issue"]
            if snapshot["subject"] != "Changed by a separate synthetic fixture operator":
                raise Invalid("Conflicting content was not preserved")
            rows["conflict_preserved"] = True
            with workspace.session() as store:
                canonical_finding = store.current("finding", FINDING).as_type(Finding)
                if canonical_finding.lifecycle != before.as_type(Finding).lifecycle:
                    raise Invalid("Redmine changed the canonical lifecycle")
                rows["canonical_lifecycle_preserved"] = True
                rows["audit"] = store.verify()["status"]
        finally:
            rows["cleanup"] = redmine.down(args.confirm)
    print(canonical(rows).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
