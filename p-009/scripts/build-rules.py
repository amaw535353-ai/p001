#!/usr/bin/env python3
"""Compile bounded P009 rules to actual Wazuh JSON-decoder rules."""

import argparse
from pathlib import Path
from xml.sax.saxutils import escape

from p009.detection import rules

parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
thresholds = {
    1: r"^[1-9][0-9]{0,6}$",
    3: r"^(?:[3-9]|[1-9][0-9]{1,6})$",
    5: r"^(?:[5-9]|[1-9][0-9]{1,6})$",
    20: r"^(?:[2-9][0-9]|[1-9][0-9]{2,6})$",
    50: r"^(?:[5-9][0-9]|[1-9][0-9]{2,6})$",
}
lines = [
    '<group name="p009,synthetic,">',
    '  <rule id="110899" level="0">',
    "    <category>syslog</category>",
    "    <decoded_as>json</decoded_as>",
    '    <field name="p009">^v1$</field>',
    "    <description>P009 synthetic metadata</description>",
    "  </rule>",
]
for rule in rules():
    lines.extend(
        [
            f'  <rule id="{rule.rule_id}" level="{rule.severity}">',
            "    <if_sid>110899</if_sid>",
            f'    <field name="signal">^{rule.signal}$</field>',
            f'    <field name="count" type="pcre2">{escape(thresholds[rule.minimum_count])}</field>',
            f"    <description>P009 {rule.signal} observation v{rule.version}</description>",
            "  </rule>",
        ]
    )
lines.append("</group>")
raw = "\n".join(lines) + "\n"
path = Path(__file__).resolve().parents[1] / "wazuh/rules/p009.xml"
if args.check:
    if path.read_text() != raw:
        raise SystemExit("Wazuh rule drift")
else:
    path.write_text(raw)
print("PASS 20 bounded Wazuh rules")
