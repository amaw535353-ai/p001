# OWASP ZAP integration (#62)

ZAP 2.17.0 Linux archive SHA256:
`efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`.
Java 21 is available. Relevant bundled add-ons: automation 0.58.0, exim 0.16.0,
pscan 0.6.0, pscanrules 70, reports 0.43.0. They remain pinned to this release.

After fresh scope preflight, the broker captures exactly one bounded `/ui` response.
The Automation Framework imports that captured HAR, waits for passive scanning and
exports traditional-json. There are no spider, requestor, activeScan, URL-import,
hosted-provider or update jobs. The runner uses `-Xmx768m -cmd -silent`, a private
runtime home and loopback listener settings. Exit zero, a completed passive job and
the captured site in the actual report are all required by the oracle.

Current online docs include `sendRequests`, `maxMessages` and a newer passive body
option unsupported by these bundled add-ons. The pinned exim 0.16.0 ImportJob source
has only type/fileName parameters and uses HarImporter for HAR; it does not send
requests. P007 bounds the HAR to one recorded response itself. Unsupported options
initially produced exit 2 and were correctly inconclusive until compatibility was
fixed. No broad web assessment or active-scan capability is claimed.

Alerts retain rule, confidence, evidence count and NOT_REVIEWED state; they are
OBSERVATION with confirmed_vulnerability=false. The fixture has no CSP/frame header
and identifies its synthetic Python server, yielding controlled observations.

Sources: [Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/),
[current import docs](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/),
[exact pinned ImportJob](https://github.com/zaproxy/zap-extensions/blob/exim-v0.16.0/addOns/exim/src/main/java/org/zaproxy/addon/exim/automation/ImportJob.java),
[report job](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/),
[release](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0).
