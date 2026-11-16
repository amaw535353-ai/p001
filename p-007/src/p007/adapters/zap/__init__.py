"""Real ZAP passive analysis of an authorized response, without scanner egress.

The broker sends exactly one scoped request. Pinned exim reads captured HAR only.
No spider, requestor, activeScan, external OpenAPI import or add-on update jobs.
"""

from datetime import datetime, timezone
import re

import yaml

from p007.authorization import GuardedHTTP, active_zap_gate
from p007.models import RunnerResult
from p007.runners import bounded_result, execute
from p007.safety import canonical, digest, write_new


def observations(report: dict) -> list[dict]:
    alerts = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            alerts.append(
                {
                    "rule_id": str(alert.get("pluginid")),
                    "name": alert.get("name", alert.get("alert")),
                    "risk": alert.get("riskdesc"),
                    "confidence": alert.get("confidence"),
                    "evidence_count": len(alert.get("instances", [])),
                    "status": "OBSERVATION",
                    "false_positive_review": "NOT_REVIEWED",
                    "confirmed_vulnerability": False,
                }
            )
    return alerts


def automation(origin, har, folder):
    return {
        "env": {
            "contexts": [
                {
                    "name": "p007-owned",
                    "urls": [origin],
                    "includePaths": [re.escape(origin) + "/ui"],
                    "excludePaths": [],
                }
            ],
            "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": [
            {
                "type": "passiveScan-config",
                "parameters": {"scanOnlyInScope": True},
            },
            {
                "type": "import",
                "parameters": {"type": "har", "fileName": str(har)},
            },
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
            {
                "type": "report",
                "parameters": {
                    "template": "traditional-json",
                    "reportDir": str(folder),
                    "reportFile": "zap.json",
                    "displayReport": False,
                },
            },
        ],
    }


def run(test, plan, capability, folder, guard=None):
    if test.category == "active_scan":
        active_zap_gate(guard=guard)
    row = GuardedHTTP(guard).request(plan.target.origin + test.operation.path)
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "startedDateTime": now,
        "time": 1,
        "request": {
            "method": "GET",
            "url": plan.target.origin + test.operation.path,
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": row["status"],
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in row["headers"].items()],
            "cookies": [],
            "content": {"size": len(row["body"]), "mimeType": "text/html", "text": row["body"].decode()},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(row["body"]),
        },
        "cache": {},
        "timings": {"send": 0, "wait": 1, "receive": 0},
    }
    har = folder / "capture.har"
    write_new(
        har,
        canonical(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "p007-scoped-broker", "version": "1.0"},
                    "entries": [entry],
                }
            }
        ),
    )
    config = automation(plan.target.origin, har, folder)
    configuration = folder / "automation.yaml"
    write_new(configuration, yaml.safe_dump(config).encode())
    command = [
        capability.executable,
        "-Xmx768m",
        "-cmd",
        "-silent",
        "-host",
        "127.0.0.1",
        "-port",
        "0",
        "-dir",
        str(folder / "zap-home"),
        "-config",
        "autoupdate.checkOnStart=false",
        "-config",
        "autoupdate.downloadNewRelease=false",
        "-autorun",
        str(configuration),
    ]
    code, stdout, error = execute(command, folder, test.limits)
    report_file = folder / "zap.json"
    if error != "none" or code != 0 or not report_file.exists():
        return RunnerResult(
            adapter="zap",
            executed=True,
            original_status="ZAP-" + (error.upper() if error != "none" else "AUTOMATION-ERROR"),
            exit_code=code,
            error_class=error if error != "none" else "provider",
            tool_version=capability.version,
            commands=[command],
            metadata={
                "scan_type": "passive-captured-response",
                "stdout_hash": digest(stdout),
                "diagnostic": stdout.decode(errors="replace")[-6000:],
            },
        )
    report = bounded_result(report_file, test.limits)
    alerts = observations(report)
    # A report must contain the captured site and actual message; exit zero is insufficient.
    sites = report.get("site", [])
    site_present = any(
        str(s.get("@host")) == "127.0.0.1" and str(s.get("@port")) == str(guard.lease.server.server_port)
        for s in sites
    )
    completed = site_present and b"passiveScan-wait" in stdout and b"Automation plan" in stdout
    observed = {
        "captured_status": row["status"],
        "passive_completed": completed,
        "confirmed_vulnerability": False,
    }
    return RunnerResult(
        adapter="zap",
        executed=True,
        original_status="COMPLETE",
        exit_code=code,
        observed=observed,
        samples=[observed],
        tool_version=capability.version,
        commands=[command],
        metadata={
            "scan_type": "passive-captured-response",
            "ruleset": "bundled-passive-rules-pinned-distribution",
            "context": "p007-owned",
            "request_count": guard.used,
            "alerts": alerts,
            "config_hash": digest(config),
            "raw_report_hash": digest(report_file.read_bytes()),
            "review": "NOT_REVIEWED",
            "crawler": False,
            "active_scan": False,
            "settings": {"capture_only_import": True, "max_captured_messages": 1},
        },
    )
