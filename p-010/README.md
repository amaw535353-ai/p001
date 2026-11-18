# P-010 — AI Security Findings, Risk Register, and Consultancy Report Generator

P-010 is a local consultancy workbench for synthetic AI security assessments. It
imports published sibling contracts, records independently reviewed observations,
tracks findings and risk decisions, and builds deterministic Markdown and JSON
packages. The CLI runs offline by default. A synthetic record carries only the
authority and provenance actually recorded in its source.

## Quick start

Linux with Python 3.12, Git, Make and uv.

```bash
cd p-010
./scripts/setup
make verify
make demo
```

The demo prints the workspace name, report path and SHA-256 hashes. Each run with
the same input bytes has the same package hashes. See [operator commands](docs/operations-and-troubleshooting.md)
to import actual P-008 and P-009 exports, write and review your own assessment,
verify source references or preview a report. All workspaces and generated
reports stay in the private `.runtime/` directory.

## Components

| Component | Function |
| --- | --- |
| [Evidence and findings](docs/finding-lifecycle.md) | Read-only intake, exact-version evidence links, explicit author/reviewer state changes |
| [Risk register](docs/risk-register.md) | Local severity rubric, applicability, accountable treatment and dated acceptance |
| [Reports](docs/report-template.md) | Draft preview, 25 quality gates, version-bound independent review, hashes and sanitized handoff |
| [Redmine #142](docs/redmine-integration.md) | Network-disabled synthetic project with dry-run, explicit writes and conflict detection |
| [NIST OSCAL #128](docs/oscal-integration.md) | Pinned official v1.2.3 validation, bounded Assessment Results export and mapping drafts |
| [MITRE ATLAS #125](docs/atlas-integration.md) | Pinned 2026.10 catalog search and reviewed mappings |
| [Langfuse #117](docs/langfuse-integration.md) | Exact trace references and explicit local metadata-only read profile |

[Architecture](docs/architecture.md) · [Validation status](docs/validation-status.md) ·
[Acceptance matrix](docs/acceptance-matrix.md) · [Delivery report](docs/delivery-report.md) ·
[Learner workbook](docs/learner-workbook.md)
