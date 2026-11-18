# Markdown and JSON report package

The main `assessment.md` contains scope, method, architecture, risk
applicability, the findings summary and technical narratives, evidence,
severity rationale, ATLAS, control traceability, remediation, retest,
residual risk, limitations, management response, review and handover.
The exporter also writes executive-summary, findings, risk-register,
evidence, remediation and retest Markdown views.

`report.json` contains frozen canonical versions and source metadata.
`manifest.json` records the exact local references and file SHA-256
values. The declared source-record versions distinguish source statuses
from P-010 judgments. Preview renders escaped Markdown and does not
generate HTML or PDF.
