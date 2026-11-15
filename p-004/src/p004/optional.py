"""Optional integrations fail closed. Fixtures are never proof of vendor behavior."""

from p004.graph import Graph
from p004.models import Source
from p004.policy import Denied, local_url
from p004.safety import Invalid


def browser_observe(*_args, **_kwargs):
    raise Denied("BROWSER-BLOCKED-NO-INDEPENDENT-EGRESS-SANDBOX")


def kube_observe(*_args, **_kwargs):
    raise Denied("KUBERNETES-BLOCKED-NO-REVIEWED-NAMESPACE-IDENTITY")


def zap_config(value):
    """P004 protected import contract, deliberately NOT an unverified ZAP AF plan."""
    expected = dict(
        schema_version="p004-zap-passive-import-v1",
        mode="safe",
        generate_traffic=False,
        active_scan=False,
        spider=False,
        ajax_spider=False,
        force_browse=False,
        fuzz=False,
        source="guarded-sanitized-traffic-only",
    )
    if value != expected:
        raise Invalid("ZAP-PASSIVE-ONLY-CONTRACT")
    return expected


def passive_alerts(g: Graph, value, ref: Source, allowed_urls: set[str]):
    if (
        set(value) != {"schema_version", "scanner_version", "alerts"}
        or value["schema_version"] != "p004-zap-alerts-v1"
    ):
        raise Invalid("ZAP-ALERT-CONTRACT")
    for alert in value["alerts"]:
        if set(alert) != {"rule_id", "url", "confidence", "passive"} or alert["passive"] is not True:
            raise Invalid("ZAP-PASSIVE-ALERT-REQUIRED")
        url = local_url(alert["url"])
        if url not in allowed_urls:
            raise Invalid("ZAP-ALERT-OUTSIDE-REVIEWED-SCOPE")
        g.note(
            "UNVERIFIED",
            "passive-alert",
            "Passive scanner candidate; not a confirmed vulnerability",
            [ref],
            details={
                "rule_id": alert["rule_id"],
                "url": url,
                "confidence": alert["confidence"],
                "scanner_version": value["scanner_version"],
                "false_positive_review": "required",
            },
        )
    return len(value["alerts"])
