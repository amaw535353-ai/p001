# Privacy and redaction

`p010-minimization-1.0` distinguishes synthetic records and sensitive
source references. Service credentials belong in private runtime
configuration. Input and output are bounded. Source adapters validate
actual schemas and select permitted fields. Known sensitive values,
control characters and disallowed keys block persistence. An explicitly
selected excerpt is redacted before persistence. The report contains
metadata and approved excerpts only. Text is escaped for Markdown.

The exercise plants secret and email-like canaries. Tests look for them
in source projections, report files and handoff outputs. The pattern
filters do not identify every form of personal data or arbitrary
secrets. Review input data and requested excerpts before use.
