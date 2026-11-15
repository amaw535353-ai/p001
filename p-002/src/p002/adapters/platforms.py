"""Small real API importers: bounded representative subsets, never native ACL emulators."""

import json
from xml.etree import ElementTree
from urllib.parse import urlencode, quote
from p002 import NOTICE
from p002.adapters import credentials, observe
from p002.adapters.transport import Client, basic
from p002.validation import digest


def key(id):
    return id.replace(":", "-")


def must(status, allowed):
    if status not in allowed:
        raise RuntimeError(f"local API returned unexpected HTTP {status}; body not logged")


class Base:
    name = ""

    def __init__(self, d, journal, transport):
        self.d = d
        self.journal = journal
        self.transport = transport
        self.secret = credentials()

    def client(self, user="admin"):
        return Client(
            self.name,
            "lab",
            transport=self.transport,
            headers={
                "Authorization": basic(
                    self.secret[self.name]["admin_user"], self.secret[self.name]["admin_password"]
                )
            },
        )

    def cleanup(self):
        # Complete isolated deployments are removable with verified labels by scripts/lab.
        # Individual-resource API cleanup is separately scoped to journaled objects.
        raise NotImplementedError


class Nextcloud(Base):
    name = "nextcloud"

    def client(self, user="admin"):
        secret = self.secret[self.name]
        password = secret["admin_password"] if user == "admin" else secret["users"][user]
        login = secret["admin_user"] if user == "admin" else user
        return Client(
            self.name,
            "lab",
            transport=self.transport,
            headers={"Authorization": basic(login, password), "OCS-APIRequest": "true"},
        )

    def ocs(self, c, method, path, data=None):
        url = "/ocs/v2.php/" + path + ("?" if "?" not in path else "&") + "format=json"
        raw = urlencode(data).encode() if data is not None else None
        status, b, _ = c.request(method, url, raw, {"Content-Type": "application/x-www-form-urlencoded"})
        must(status, [200])
        obj = json.loads(b)
        if obj["ocs"]["meta"]["statuscode"] not in [100, 200]:
            raise RuntimeError("Nextcloud OCS rejected operation; response not logged")
        return obj["ocs"]["data"]

    def seed(self):
        admin = self.client()
        for dept in self.d.departments:
            group = key(dept.id) + "-group"
            owner = key(dept.manager_id)
            reader = key(dept.id + ":u1")
            if not self.journal.get(group):
                exists = self.ocs(admin, "GET", "cloud/groups")["groups"]
                if group in exists:
                    raise ValueError("pre-existing unowned Nextcloud group")
                self.ocs(admin, "POST", "cloud/groups", {"groupid": group})
                self.journal.put(group, "group", group)
            for uid in [owner, reader]:
                if not self.journal.get(uid):
                    users = self.ocs(admin, "GET", "cloud/users")["users"]
                    if uid in users:
                        raise ValueError("pre-existing unowned Nextcloud user")
                    self.ocs(
                        admin,
                        "POST",
                        "cloud/users",
                        {
                            "userid": uid,
                            "password": self.secret[self.name]["users"][uid],
                            "displayName": "Fictional " + uid,
                        },
                    )
                    self.journal.put(uid, "user", uid)
                    self.ocs(admin, "POST", "cloud/users/" + uid + "/groups", {"groupid": group})
            owner_client = self.client(owner)
            folder = "P002-" + key(dept.id)
            dav = "/remote.php/dav/files/" + owner + "/" + folder
            if not self.journal.get(folder):
                code, _, _ = owner_client.request("PROPFIND", dav, headers={"Depth": "0"})
                if code != 404:
                    raise ValueError("unowned Nextcloud folder collision")
                code, _, headers = owner_client.request("MKCOL", dav)
                must(code, [201])
                self.journal.put(folder, "folder", folder, owner=owner)
            for i in [0, 3]:
                rid = dept.id + f":doc{i}"
                doc = next(x for x in self.d.documents if x.resource_id == rid)
                path = dav + "/" + key(rid) + ".md"
                mapping = self.journal.get(doc.id)
                if mapping:
                    code, raw, headers = owner_client.request("GET", path)
                    must(code, [200])
                    if digest(raw) != doc.content_sha256:
                        raise ValueError("owned Nextcloud content changed; refusing overwrite")
                else:
                    code, _, _ = owner_client.request("GET", path)
                    if code != 404:
                        raise ValueError("unowned Nextcloud file collision")
                    code, _, headers = owner_client.request(
                        "PUT",
                        path,
                        doc.body.encode(),
                        {"Content-Type": "text/markdown", "If-None-Match": "*"},
                    )
                    must(code, [201])
                    self.journal.put(
                        doc.id,
                        "file",
                        path,
                        owner=owner,
                        sha256=doc.content_sha256,
                        resource_id=rid,
                        native_id=headers.get("OC-FileId", headers.get("Oc-Fileid")),
                        last_modified=headers.get("Last-Modified"),
                        share=None,
                    )
                prop_body = b'<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:getlastmodified/><oc:fileid/><d:getetag/></d:prop></d:propfind>'
                code, raw, _ = owner_client.request(
                    "PROPFIND", path, prop_body, {"Depth": "0", "Content-Type": "application/xml"}
                )
                must(code, [207])
                props = ElementTree.fromstring(raw)
                native_id = props.find(".//{http://owncloud.org/ns}fileid")
                modified = props.find(".//{DAV:}getlastmodified")
                if native_id is None or modified is None:
                    raise RuntimeError("Nextcloud readback metadata missing")
                self.journal.get(doc.id).update(native_id=native_id.text, last_modified=modified.text)
                self.journal.save()
                if i == 0 and not self.journal.get(doc.id).get("share"):
                    share = self.ocs(
                        owner_client,
                        "POST",
                        "apps/files_sharing/api/v1/shares",
                        {
                            "path": "/" + folder + "/" + key(rid) + ".md",
                            "shareType": 1,
                            "shareWith": group,
                            "permissions": 3,
                            "sendMail": "false",
                        },
                    )
                    self.journal.get(doc.id)["share"] = share["id"]
                    self.journal.get(doc.id)["share_name"] = share.get("file_target", "/" + key(rid) + ".md")
                    self.journal.save()
        self.journal.phase("SEEDED")

    def verify(self):
        if self.journal.data["phase"] != "SEEDED":
            raise ValueError("seed this owned adapter first")
        rows = []
        for dept in self.d.departments:
            rid = dept.id + ":doc0"
            doc = next(x for x in self.d.documents if x.resource_id == rid)
            m = self.journal.get(doc.id)
            owner = key(dept.manager_id)
            reader = key(dept.id + ":u1")
            outsider = key(
                ("p002:tenant-b:hr:u0" if dept.tenant_id == "p002:tenant-a" else "p002:tenant-a:hr:u0")
            )
            for case, user, path, expected in [
                ("owner", owner, m["external_id"], "ALLOW"),
                (
                    "department-reader",
                    reader,
                    "/remote.php/dav/files/" + reader + quote(m["share_name"], safe="/"),
                    "ALLOW",
                ),
                ("other-tenant", outsider, m["external_id"], "DENY"),
            ]:
                code, raw, headers = self.client(user).request("GET", path)
                row = observe(
                    self.name, key(rid) + "-" + case, user, "GET file", code, expected, canonical_resource=rid
                )
                if expected == "ALLOW" and digest(raw) != doc.content_sha256:
                    row["status"] = "FAIL"
                row["readback_sha256"] = digest(raw) if expected == "ALLOW" else None
                rows.append(row)
            # A recipient has native update permission only on explicitly shared doc0.
            code, _, _ = self.client(reader).request(
                "PUT",
                "/remote.php/dav/files/" + reader + quote(m["share_name"], safe="/"),
                doc.body.encode(),
                {"Content-Type": "text/markdown"},
            )
            rows.append(
                observe(
                    self.name,
                    key(rid) + "-recipient-update",
                    reader,
                    "PUT same synthetic bytes",
                    code,
                    "ALLOW",
                    canonical_resource=rid,
                )
            )
        return rows

    def cleanup(self):
        admin = self.client()
        for m in list(self.journal.data["objects"].values())[::-1]:
            if m["kind"] == "user":
                self.ocs(admin, "DELETE", "cloud/users/" + m["external_id"])
            elif m["kind"] == "group":
                self.ocs(admin, "DELETE", "cloud/groups/" + m["external_id"])
        self.journal.data["objects"] = {}
        self.journal.phase("CLEANED")
        return {"status": "removed-only-journaled-users-and-groups", "platform": self.name}


class Redmine(Base):
    name = "redmine"

    def client(self, user="admin"):
        s = self.secret[self.name]
        return Client(
            self.name,
            "lab",
            transport=self.transport,
            headers={
                "Authorization": basic(
                    s["admin_user"] if user == "admin" else user,
                    s["admin_password"] if user == "admin" else s["users"][user],
                )
            },
        )

    def seed(self):
        c = self.client()
        roles = c.json("GET", "/roles.json")["roles"]
        trackers = c.json("GET", "/trackers.json")["trackers"]
        if not trackers:
            raise RuntimeError("BLOCKED: run supported Redmine default-data bootstrap")
        tracker_ids = [x["id"] for x in trackers]
        role = next((x["id"] for x in roles if x["name"] == "P002Analyst"), None)
        if role is None:
            raise RuntimeError("BLOCKED: bootstrap role P002Analyst absent")
        for dept in self.d.departments:
            users = []
            for uid in [dept.manager_id, dept.id + ":u1"]:
                login = key(uid)
                m = self.journal.get(uid)
                if not m:
                    existing = c.json("GET", "/users.json?name=" + login)["users"]
                    if any(x["login"] == login for x in existing):
                        raise ValueError("unowned Redmine user collision")
                    result = c.json(
                        "POST",
                        "/users.json",
                        {
                            "user": {
                                "login": login,
                                "firstname": "Fictional",
                                "lastname": login,
                                "mail": login + "@example.test",
                                "password": self.secret[self.name]["users"][login],
                                "must_change_passwd": False,
                                "mail_notification": "none",
                                "send_information": False,
                            }
                        },
                        expected=(201,),
                    )
                    m = self.journal.put(uid, "user", result["user"]["id"])
                users.append(m["external_id"])
            pk = key(dept.id) + "-project"
            m = self.journal.get(pk)
            if not m:
                status, _, _ = c.request("GET", "/projects/" + pk + ".json")
                if status != 404:
                    raise ValueError("unowned Redmine project collision")
                obj = c.json(
                    "POST",
                    "/projects.json",
                    {
                        "project": {
                            "name": "Fictional " + dept.name,
                            "identifier": pk,
                            "description": NOTICE,
                            "is_public": False,
                            "enabled_module_names": ["issue_tracking"],
                            "tracker_ids": tracker_ids,
                        }
                    },
                    expected=(201,),
                )["project"]
                m = self.journal.put(pk, "project", obj["id"], identifier=pk)
            c.json(
                "PUT",
                f"/projects/{m['external_id']}.json",
                {"project": {"tracker_ids": tracker_ids}},
                expected=(200, 204),
            )
            for user in users:
                mk = pk + ":membership:" + str(user)
                if not self.journal.get(mk):
                    result = c.json(
                        "POST",
                        f"/projects/{m['external_id']}/memberships.json",
                        {"membership": {"user_id": user, "role_ids": [role]}},
                        expected=(201,),
                    )
                    self.journal.put(mk, "membership", result["membership"]["id"])
            project = next(x for x in self.d.projects if x.resource_id == dept.id + ":project")
            for issue in [x for x in self.d.issues if x.project_id == project.id]:
                if not self.journal.get(issue.id):
                    result = self.client(key(issue.reporter_id)).json(
                        "POST",
                        "/issues.json",
                        {
                            "issue": {
                                "project_id": m["external_id"],
                                "subject": issue.subject,
                                "description": NOTICE + "\nCanonical " + issue.id,
                                "assigned_to_id": users[0],
                                "tracker_id": tracker_ids[0],
                            }
                        },
                        expected=(201,),
                    )
                    self.journal.put(
                        issue.id,
                        "issue",
                        result["issue"]["id"],
                        project=m["external_id"],
                        canonical_resource=issue.resource_id,
                    )
                else:
                    obj = c.json("GET", f"/issues/{self.journal.get(issue.id)['external_id']}.json")["issue"]
                    if obj["subject"] != issue.subject:
                        raise ValueError("owned Redmine issue drift; refusing overwrite")
        self.journal.phase("SEEDED")

    def verify(self):
        if self.journal.data["phase"] != "SEEDED":
            raise ValueError("seed this owned adapter first")
        rows = []
        for issue in self.d.issues:
            m = self.journal.get(issue.id)
            path = f"/issues/{m['external_id']}.json"
            actor = key(issue.reporter_id)
            other = key(
                "p002:tenant-b:hr:u0" if issue.tenant_id == "p002:tenant-a" else "p002:tenant-a:hr:u0"
            )
            for case, user, expected in [("member", actor, "ALLOW"), ("other-tenant", other, "DENY")]:
                code, raw, _ = self.client(user).request("GET", path)
                row = observe(
                    self.name,
                    key(issue.id) + "-" + case,
                    user,
                    "GET issue",
                    code,
                    expected,
                    canonical_resource=issue.resource_id,
                )
                if expected == "ALLOW" and (
                    json.loads(raw)["issue"]["subject"] != issue.subject
                    or json.loads(raw)["issue"]["project"]["id"] != m["project"]
                ):
                    row["status"] = "FAIL"
                rows.append(row)
            code, _, _ = self.client(actor).request(
                "PUT", path, {"issue": {"notes": NOTICE + "; idempotent synthetic verification."}}
            )
            rows.append(
                observe(
                    self.name,
                    key(issue.id) + "-update",
                    actor,
                    "PUT issue notes",
                    code,
                    "ALLOW",
                    canonical_resource=issue.resource_id,
                )
            )
        return rows

    def cleanup(self):
        c = self.client()
        for kind, path in [("project", "/projects/"), ("user", "/users/")]:
            for m in self.journal.data["objects"].values():
                if m["kind"] == kind:
                    code, _, _ = c.request("DELETE", path + str(m["external_id"]) + ".json")
                    must(code, [200, 204, 404])
        self.journal.data["objects"] = {}
        self.journal.phase("CLEANED")
        return {"status": "removed-only-journaled-projects-and-users", "platform": self.name}


class LabelStudio(Base):
    name = "label-studio"

    def client(self, user="admin"):
        return Client(
            self.name,
            "lab",
            transport=self.transport,
            headers={"Authorization": "Token " + self.secret[self.name]["api_token"]},
        )

    def seed(self):
        c = self.client()
        title = "P002-" + self.journal.data["dataset_sha256"][:12]
        project = self.journal.get("project")
        if not project:
            projects = c.json("GET", "/api/projects/")
            values = projects.get("results", []) if isinstance(projects, dict) else projects
            if any(x["title"] == title for x in values):
                raise ValueError("unowned Label Studio project collision")
            cfg = (
                '<View><Text name="text" value="$text"/><Choices name="classification" toName="text" choice="single" required="true">'
                + "".join(
                    f'<Choice value="{x}"/>' for x in ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
                )
                + "</Choices></View>"
            )
            obj = c.json(
                "POST",
                "/api/projects/",
                {"title": title, "description": NOTICE, "label_config": cfg},
                expected=(201,),
            )
            project = self.journal.put("project", "project", obj["id"])
        pid = project["external_id"]
        # One document per department, mapped through actual task and annotation IDs.
        for dept in self.d.departments:
            doc = next(x for x in self.d.documents if x.resource_id == dept.id + ":doc0")
            task = next(x for x in self.d.tasks if x.document_id == doc.id)
            m = self.journal.get(task.id)
            if not m:
                listing = c.json("GET", f"/api/tasks/?project={pid}&page_size=100")
                values = (
                    listing.get("tasks", listing.get("results", [])) if isinstance(listing, dict) else listing
                )
                if any(x.get("data", {}).get("canonical_id") == task.id for x in (values or [])):
                    raise ValueError("unowned Label Studio task collision")
                obj = c.json(
                    "POST",
                    f"/api/projects/{pid}/import?return_task_ids=true",
                    [{"data": {"text": doc.body, "canonical_id": task.id, "notice": NOTICE}}],
                    expected=(201,),
                )
                ids = obj.get("task_ids")
                if not ids or len(ids) != 1:
                    raise RuntimeError("Label Studio sync import did not return one actual task ID")
                m = self.journal.put(task.id, "task", ids[0], document_id=doc.id, project=pid)
            if not self.journal.get(task.id + ":annotation"):
                ann = c.json(
                    "POST",
                    f"/api/tasks/{m['external_id']}/annotations/",
                    {
                        "result": [
                            {
                                "from_name": "classification",
                                "to_name": "text",
                                "type": "choices",
                                "value": {"choices": ["PUBLIC"]},
                            }
                        ]
                    },
                    expected=(201,),
                )
                self.journal.put(task.id + ":annotation", "annotation", ann["id"], task=m["external_id"])
        self.journal.phase("SEEDED")

    def verify(self):
        if self.journal.data["phase"] != "SEEDED":
            raise ValueError("seed this owned adapter first")
        rows = []
        c = self.client()
        for cid, m in self.journal.data["objects"].items():
            if m["kind"] != "task":
                continue
            code, raw, _ = c.request("GET", f"/api/tasks/{m['external_id']}/")
            row = observe(
                self.name,
                key(cid),
                "local-labeling-owner",
                "GET task with annotation",
                code,
                "ALLOW",
                canonical_task=cid,
            )
            if code == 200:
                task = json.loads(raw)
                doc = next(x for x in self.d.documents if x.id == m["document_id"])
                if (
                    task["data"]["canonical_id"] != cid
                    or digest(task["data"]["text"].encode()) != doc.content_sha256
                    or not task.get("annotations")
                ):
                    row["status"] = "FAIL"
                row["readback_sha256"] = digest(task["data"]["text"].encode())
            rows.append(row)
        return rows

    def cleanup(self):
        m = self.journal.get("project")
        if m:
            code, _, _ = self.client().request("DELETE", f"/api/projects/{m['external_id']}/")
            must(code, [204, 404])
        self.journal.data["objects"] = {}
        self.journal.phase("CLEANED")
        return {"status": "removed-only-journaled-project", "platform": self.name}


class P001(Base):
    name = "p001"

    def client(self, user="tenant-a"):
        return Client(
            self.name,
            "lab",
            transport=self.transport,
            headers={"Authorization": "Bearer p001-fixture-" + user},
        )

    def seed(self):
        # The real API accepts only fixed markers; never substitute document bodies.
        k = "fixture-p002-" + self.journal.data["dataset_sha256"][:12]
        path = "/objects/" + k
        m = self.journal.get(k)
        if not m:
            code, _, _ = self.client().request("GET", path)
            if code != 502:
                raise ValueError("P-001 object collision or incompatible endpoint")
            code, _, _ = self.client().request("PUT", path, {"marker": "P001-SYNTHETIC-ONLY"})
            must(code, [201])
            self.journal.put(k, "marker", k, path=path, bucket="p001-tenant-a")
        self.journal.phase("SEEDED")

    def verify(self):
        m = next(iter(self.journal.data["objects"].values()))
        rows = []
        for actor, expect in [("tenant-a", "ALLOW"), ("tenant-b", "DENY")]:
            code, raw, _ = self.client(actor).request("GET", m["path"])
            row = observe(self.name, actor + "-marker", actor, "GET owned marker", code, expect)
            if (
                actor == "tenant-a"
                and code == 200
                and json.loads(raw) != {"tenant": "tenant-a", "object": {"marker": "P001-SYNTHETIC-ONLY"}}
            ):
                row["status"] = "FAIL"
            rows.append(row)
        return rows

    def cleanup(self):
        # P-001 intentionally has no DELETE API. Its separately owned disposable
        # deployment is removed by scripts/lab down p001, not by altering P-001 IaC.
        return {
            "status": "BLOCKED",
            "reason": "No P-001 delete endpoint; use --confirm p002-local owned deployment teardown.",
        }
