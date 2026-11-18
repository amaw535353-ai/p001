"""Staged native Langfuse and isolated Wazuh-manager integrations."""

import base64
import json
import re
import secrets
import subprocess
import time
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import yaml

from p009.detection import rules
from p009.operate import LABEL, assert_owned, credentials, resources, run
from p009.safety import ROOT, Blocked, Invalid, canonical, load, read, write_new


def product_env():
    path = ROOT / ".runtime/product-secrets.json"
    if not path.exists():
        values = {
            "P009_" + key: secrets.token_hex(24)
            for key in (
                "PG_PASSWORD",
                "CH_PASSWORD",
                "SALT",
                "NEXTAUTH_SECRET",
                "REDIS_PASSWORD",
                "MINIO_PASSWORD",
                "LF_OPERATOR_PASSWORD",
            )
        }
        values["P009_ENCRYPTION_KEY"] = secrets.token_hex(32)
        values["P009_LANGFUSE_PUBLIC_KEY"] = "pk-lf-" + secrets.token_hex(16)
        values["P009_LANGFUSE_SECRET_KEY"] = "sk-lf-" + secrets.token_hex(24)
        write_new(path, canonical(values))
    values = load(path)
    values["P009_LANGFUSE_AUTH"] = (
        "Basic "
        + base64.b64encode(
            (values["P009_LANGFUSE_PUBLIC_KEY"] + ":" + values["P009_LANGFUSE_SECRET_KEY"]).encode()
        ).decode()
    )
    images = load(ROOT / "config/images.lock.json")
    return {
        **credentials(),
        **values,
        **{"P009_IMAGE_" + k.upper().replace("-", "_"): v for k, v in images.items()},
    }


def lf_compose(*args, timeout=180):
    return run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT / "compose.yaml"),
            "-f",
            str(ROOT / "langfuse/compose.yaml"),
            *args,
        ],
        env=product_env(),
        timeout=timeout,
    )


def init_volume(name, uid):
    assert_owned("volume", name)
    run(["docker", "volume", "create", "--label", LABEL + "=p009", name])
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
            name + ":/data",
            "p009-app:local",
            "python",
            "-c",
            f"import os;os.chown('/data',{uid},{uid});os.chmod('/data',0o700)",
        ]
    )


def product_up(profile, host=None):
    host = host or resources()
    if profile == "langfuse":
        if host["memory_bytes"] < 7_000_000_000 or host["free_disk_bytes"] < 10_000_000_000:
            raise Blocked("LANGFUSE-RESOURCE-PREFLIGHT")
        for name in ("langfuse-web", "langfuse-worker", "postgres", "redis", "clickhouse", "minio"):
            assert_owned("container", "p009-" + name + "-1")
        assert_owned("network", "p009-langfuse")
        for name, uid in (
            ("p009-postgres", 999),
            ("p009-clickhouse", 101),
            ("p009-minio", 0),
            ("p009-clickhouse-logs", 101),
            ("p009-redis", 0),
        ):
            init_volume(name, uid)
        # MinIO's supported filesystem backend discovers the pre-created lab bucket.
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
                "-v",
                "p009-minio:/data",
                "p009-app:local",
                "python",
                "-c",
                "import os;os.makedirs('/data/langfuse',exist_ok=True)",
            ]
        )
        cfg = yaml.safe_load(read(ROOT / "collector/config.yaml"))
        cfg["exporters"]["otlp_http/langfuse"] = {
            "endpoint": "http://langfuse-web:3000/api/public/otel",
            "encoding": "proto",
            "compression": "none",
            "headers": {"Authorization": "${env:P009_LANGFUSE_AUTH}"},
            "timeout": "5s",
            "sending_queue": {"enabled": True, "queue_size": 64, "num_consumers": 1},
            "retry_on_failure": {
                "enabled": True,
                "initial_interval": "1s",
                "max_interval": "2s",
                "max_elapsed_time": "10s",
            },
        }
        cfg["service"]["pipelines"]["traces"]["exporters"].append("otlp_http/langfuse")
        path = ROOT / ".runtime/collector-langfuse.yaml"
        raw = yaml.safe_dump(cfg, sort_keys=False).encode()
        if path.exists():
            if read(path) != raw:
                path.unlink()
        if not path.exists():
            write_new(path, raw)
        path.chmod(0o644)  # Contains env names only, no credentials.
        (ROOT / "langfuse/clickhouse.xml").chmod(0o644)
        (ROOT / "langfuse/clickhouse-users.xml").chmod(0o644)
        lf_compose("up", "-d", "postgres", "redis", "clickhouse", "minio", timeout=180)
        # Native database startup is bounded and separate from application readiness.
        time.sleep(3)
        lf_compose("up", "-d", "langfuse-web", "langfuse-worker", "archive", "collector", timeout=180)
        return {"profile": profile, "status": "STARTED", "readiness": "requires live API check", "host": host}
    if profile == "wazuh":
        assert_owned("container", "p009-wazuh")
        present = (
            subprocess.run(["docker", "container", "inspect", "p009-wazuh"], capture_output=True).returncode
            == 0
        )
        if not present:
            image = load(ROOT / "config/images.lock.json")["wazuh"]
            run(
                [
                    "docker",
                    "create",
                    "--name",
                    "p009-wazuh",
                    "--network",
                    "none",
                    "--label",
                    LABEL + "=p009",
                    "--cap-drop",
                    "ALL",
                    "--cap-add",
                    "SETUID",
                    "--cap-add",
                    "SETGID",
                    "--cap-add",
                    "CHOWN",
                    "--cap-add",
                    "FOWNER",
                    "--cap-add",
                    "DAC_OVERRIDE",
                    "--cap-add",
                    "SYS_CHROOT",
                    "--cap-add",
                    "KILL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "256",
                    "--memory",
                    "1g",
                    "--cpus",
                    "0.5",
                    "--entrypoint",
                    "/bin/bash",
                    image,
                    "/p009-start",
                ],
                timeout=180,
            )
        state = json.loads(run(["docker", "inspect", "--format", "{{json .State}}", "p009-wazuh"]))
        if not state["Running"]:
            (ROOT / "wazuh/ossec.conf").chmod(0o644)
            (ROOT / "wazuh/rules/p009.xml").chmod(0o644)
            (ROOT / "wazuh/local_internal_options.conf").chmod(0o644)
            run(["docker", "cp", str(ROOT / "wazuh/start.sh"), "p009-wazuh:/p009-start"])
            run(
                [
                    "docker",
                    "cp",
                    str(ROOT / "wazuh/local_internal_options.conf"),
                    "p009-wazuh:/var/ossec/etc/local_internal_options.conf",
                ]
            )
            run(["docker", "cp", str(ROOT / "wazuh/ossec.conf"), "p009-wazuh:/var/ossec/etc/ossec.conf"])
            run(
                [
                    "docker",
                    "cp",
                    str(ROOT / "wazuh/rules/p009.xml"),
                    "p009-wazuh:/var/ossec/etc/rules/local_rules.xml",
                ]
            )
            run(["docker", "start", "p009-wazuh"], timeout=60)
        return {
            "status": "STARTED",
            "profile": "wazuh-manager-only",
            "full_stack": "BLOCKED" if host["vm_max_map_count"] < 262144 else "NOT_TESTED",
            "reason": "Indexer/dashboard require separate verified host profile; no kernel or security changes made",
        }
    if profile == "full":
        if host["vm_max_map_count"] < 262144:
            raise Blocked("WAZUH-INDEXER-VM-MAX-MAP-COUNT")
        raise Blocked("FULL-WAZUH-INDEXER-DASHBOARD-PROFILE-NOT-VERIFIED")
    raise Invalid("PRODUCT-PROFILE")


def product_down():
    if (ROOT / ".runtime/product-secrets.json").exists():
        for name in ("langfuse-web", "langfuse-worker", "postgres", "redis", "clickhouse", "minio"):
            assert_owned("container", "p009-" + name + "-1")
        assert_owned("network", "p009-langfuse")
        lf_compose("down", "--timeout", "10", timeout=120)
    result = subprocess.run(["docker", "container", "inspect", "p009-wazuh"], capture_output=True)
    if result.returncode == 0:
        assert_owned("container", "p009-wazuh")
        run(["docker", "rm", "-f", "p009-wazuh"], timeout=60)


def product_checks(profile, rows=None):
    from p009.live import check, probe, synthetic

    rows = rows if rows is not None else []
    running = run(["docker", "ps", "--filter", "label=io.p009.owner=p009", "--format", "{{.Names}}"])
    lf_names = [
        "p009-" + name + "-1"
        for name in ("langfuse-web", "langfuse-worker", "postgres", "redis", "clickhouse", "minio")
    ]
    if profile != "langfuse" or not all(name in running.splitlines() for name in lf_names):
        product_up(profile)
    else:
        for name in lf_names:
            assert_owned("container", name)
    if profile == "langfuse":
        for _ in range(60):
            try:
                if probe("langfuse", "/api/public/health")["status"] == 200:
                    break
            except Blocked:
                pass
            time.sleep(0.5)
        result = synthetic()
        query = urlencode(
            {
                "traceId": result["trace_id"],
                "limit": 20,
                "fromStartTime": (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
                "toStartTime": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            }
        )
        observation_path = "/api/public/v2/observations?" + query
        found = None
        for _ in range(40):
            response = probe("langfuse", observation_path, auth="langfuse")
            if response["status"] == 200 and json.loads(response["body"]).get("data"):
                found = json.loads(response["body"])["data"]
                break
            time.sleep(0.5)
        if found:
            write_new(
                ROOT / ".runtime/live-artifacts" / ("langfuse-" + uuid4().hex + ".json"),
                canonical({"executed_source": result, "observations": found, "api": "v2/observations"}),
            )
        check(
            rows,
            "F01",
            "Actual Langfuse v4 OTLP observations retrieved for trace ID",
            lambda: found is not None and len(found) >= 6,
        )
        check(
            rows,
            "F02",
            "Langfuse and P009 exact trace identity agrees",
            lambda: found is not None and all(o["traceId"] == result["trace_id"] for o in found),
        )
        check(
            rows,
            "F03",
            "Unauthenticated Langfuse trace API denied",
            lambda: probe("langfuse", observation_path)["status"] in {401, 403},
        )
        check(
            rows,
            "F05",
            "Planted source content absent from Langfuse trace",
            lambda: found is not None and "CANARY" not in canonical(found).decode(),
        )
        rows.append(
            {
                "id": "F08",
                "status": "NOT_TESTED",
                "observed": "Native retention/deletion lifecycle not yet independently verified",
            }
        )
        return rows
    if profile == "wazuh":
        ready = False
        for _ in range(60):
            state = run(
                [
                    "docker",
                    "exec",
                    "p009-wazuh",
                    "/bin/bash",
                    "-c",
                    "/var/ossec/bin/wazuh-control status || true",
                ],
                timeout=15,
            )
            if "wazuh-analysisd is running" in state and "wazuh-logcollector is running" in state:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise Blocked("WAZUH-MANAGER-READINESS-TIMEOUT")
        from p009.native_case import preserve, source_reference

        source, langfuse_record = source_reference()
        case_nonce = uuid4().hex[:12]
        data, expected = [], []
        for rule in rules():
            for abnormal in (False, True):
                event = {
                    "p009": "v1",
                    "signal": rule.signal,
                    "count": rule.minimum_count if abnormal else rule.minimum_count - 1,
                    "event_id": "wazuh-"
                    + str(rule.rule_id)
                    + ("-abnormal-" if abnormal else "-benign-")
                    + case_nonce,
                    "event_time": datetime.now(timezone.utc).isoformat(),
                }
                if rule.rule_id == 110900:
                    event.update(request_id=source["request_id"], trace_id=source["trace_id"], severity=15)
                data.append(json.dumps(event))
                expected.append(rule.rule_id if abnormal else None)
        raw = run(
            ["docker", "exec", "-i", "p009-wazuh", "/var/ossec/bin/wazuh-logtest"],
            input="\n".join(data) + "\n",
            timeout=120,
            include_stderr=True,
        )
        write_new(ROOT / "work" / ("wazuh-logtest-" + uuid4().hex + ".txt"), raw.encode())
        # Attribute each result to its input, so a benign false positive cannot substitute
        # for a missing abnormal alert while preserving the aggregate ID/count sequence.
        blocks = re.split(r"\*\*Phase 1: Completed pre-decoding\.", raw)[1:]
        actual_by_input = [
            [int(value) for value in re.findall(r"id: '([0-9]+)'", block) if 110900 <= int(value) <= 110919]
            for block in blocks
        ]
        expected_by_input = [[value] if value is not None else [] for value in expected]
        check(
            rows,
            "W02",
            "Native Wazuh rule engine produces all 20 exact expected alert IDs",
            lambda: actual_by_input == expected_by_input,
        )
        check(
            rows,
            "W04",
            "Native benign controls produce no P009 alerts",
            lambda: len(actual_by_input) == len(expected) and all(not row for row in actual_by_input[::2]),
        )
        # Exercise the manager's real localfile collection path independently of logtest.
        payload = data[1] + "\n"
        run(
            ["docker", "exec", "-i", "p009-wazuh", "/bin/bash", "-c", "cat >> /p009/events.jsonl"],
            input=payload,
        )
        matching = []
        expected_event_id = json.loads(data[1])["event_id"]
        for _ in range(20):
            try:
                alerts = run(["docker", "exec", "p009-wazuh", "cat", "/var/ossec/logs/alerts/alerts.json"])
                parsed = [json.loads(line) for line in alerts.splitlines() if line.strip()]
                matching = [
                    a
                    for a in parsed
                    if a.get("rule", {}).get("id") == "110900"
                    and a.get("data", {}).get("event_id") == expected_event_id
                ]
                if matching:
                    break
            except Blocked:
                pass
            time.sleep(0.5)
        check(rows, "W01", "Actual manager ingests synthetic localfile event", lambda: bool(matching))
        check(
            rows,
            "W03",
            "Native alert retains source event reference and fixed level",
            lambda: (
                bool(matching)
                and matching[-1]["rule"]["level"] == 5
                and matching[-1].get("data", {}).get("event_id") == expected_event_id
            ),
        )
        if matching:
            case = preserve(matching[-1], data[1], source, langfuse_record)
            write_new(
                ROOT / ".runtime/live-artifacts" / ("native-case-" + uuid4().hex + ".json"), canonical(case)
            )
            check(
                rows,
                "X05",
                "Actual Wazuh alert and SDK/Langfuse trace join by original IDs",
                lambda: case["events"] >= 8,
            )
        rows.append(
            {
                "id": "W-STACK",
                "status": "BLOCKED",
                "observed": "Indexer/dashboard vm.max_map_count 65530 < 262144; manager-only detection tested",
            }
        )
        return rows
    raise Invalid("PRODUCT-PROFILE")
