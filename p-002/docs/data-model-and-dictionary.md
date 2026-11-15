# Data model and dictionary

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Schema version `1.0` is strict: unknown fields and unknown versions are rejected.
There is no silent in-place migration. Add a reviewed version-specific converter,
preserve source lineage/hash and validate a new output directory for a future version.
The original baseline remains intact. Canonical records use namespace-prefixed IDs,
tenant, owner, source provenance, creation time, status, schema version and lineage.
ExpectedDecision always has origin `generated oracle` and an unset observed result.
ObservedResult belongs only to a separate append-only integration run.

See `schemas/dataset.schema.json` for the authoritative structural schema and
`src/p002/validation` for foreign keys, cardinality, temporal and policy constraints.

## ActionRequest

| Field | Type | Required |
|---|---|---|
| requester_id | `<class 'str'>` | True |
| resource_id | `<class 'str'>` | True |
| action | `typing.Literal['execute']` | False |
| parameters | `dict[str, str  or  int]` | True |
| parameters_sha256 | `<class 'str'>` | True |

## Annotation

| Field | Type | Required |
|---|---|---|
| task_id | `<class 'str'>` | True |
| annotator_id | `<class 'str'>` | True |
| label_id | `<class 'str'>` | True |

## Approval

| Field | Type | Required |
|---|---|---|
| request_id | `<class 'str'>` | True |
| approver_id | `<class 'str'>` | True |
| parameters_sha256 | `<class 'str'>` | True |
| valid_from | `<class 'str'>` | False |
| valid_until | `<class 'str'>` | False |

## BusinessEvent

| Field | Type | Required |
|---|---|---|
| event_type | `typing.Literal['onboarding', 'offboarding', 'hr-case', 'invoice-review', 'engineering-change', 'procurement', 'knowledge-retrieval']` | True |
| actor_id | `<class 'str'>` | True |
| resource_id | `<class 'str'>` | True |
| effective_at | `<class 'str'>` | True |

## DataOwner

| Field | Type | Required |
|---|---|---|
| resource_id | `<class 'str'>` | True |
| user_id | `<class 'str'>` | True |

## Delegation

| Field | Type | Required |
|---|---|---|
| caller_id | `<class 'str'>` | True |
| service_id | `<class 'str'>` | True |
| resource_id | `<class 'str'>` | True |
| actions | `list[typing.Literal['read', 'update', 'approve', 'execute']]` | True |
| valid_from | `<class 'str'>` | False |
| valid_until | `<class 'str'>` | False |
| revoked_at | `typing.Optional[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$')]]` | False |

## Department

| Field | Type | Required |
|---|---|---|
| name | `<class 'str'>` | True |
| manager_id | `<class 'str'>` | True |

## Document

| Field | Type | Required |
|---|---|---|
| resource_id | `<class 'str'>` | True |
| body | `<class 'str'>` | True |
| trust | `typing.Literal['trusted-template', 'untrusted-text']` | False |
| content_sha256 | `<class 'str'>` | True |

## DocumentVersion

| Field | Type | Required |
|---|---|---|
| document_id | `<class 'str'>` | True |
| version | `<class 'int'>` | True |
| body_sha256 | `<class 'str'>` | True |
| effective_at | `<class 'str'>` | False |

## Enterprise

| Field | Type | Required |
|---|---|---|
| name | `<class 'str'>` | True |

## ExpectedDecision

| Field | Type | Required |
|---|---|---|
| actor_id | `<class 'str'>` | True |
| action | `typing.Literal['read', 'update', 'approve', 'execute']` | True |
| resource_id | `<class 'str'>` | True |
| context | `<class 'p002.models.Context'>` | True |
| expected | `typing.Literal['ALLOW', 'DENY']` | True |
| reason | `<class 'str'>` | True |
| rule_ids | `list[str]` | True |
| origin | `typing.Literal['generated oracle']` | False |
| observed_result | `<class 'NoneType'>` | False |

## Folder

| Field | Type | Required |
|---|---|---|
| resource_id | `<class 'str'>` | True |

## Group

| Field | Type | Required |
|---|---|---|
| department_id | `<class 'str'>` | True |
| name | `<class 'str'>` | True |

## GroupMembership

| Field | Type | Required |
|---|---|---|
| group_id | `<class 'str'>` | True |
| user_id | `<class 'str'>` | True |
| valid_from | `<class 'str'>` | False |
| valid_until | `<class 'str'>` | False |
| revoked_at | `typing.Optional[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$')]]` | False |

## HumanUser

| Field | Type | Required |
|---|---|---|
| department_id | `<class 'str'>` | True |
| display_name | `<class 'str'>` | True |
| email | `<class 'str'>` | True |
| role | `typing.Literal['manager', 'analyst', 'reviewer']` | True |
| manager_id | `typing.Optional[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^p002:[a-z0-9][a-z0-9:_-]{0,127}$')]]` | False |
| hired_at | `<class 'str'>` | False |
| terminated_at | `typing.Optional[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$')]]` | False |

## Issue

| Field | Type | Required |
|---|---|---|
| resource_id | `<class 'str'>` | True |
| project_id | `<class 'str'>` | True |
| reporter_id | `<class 'str'>` | True |
| assignee_id | `<class 'str'>` | True |
| subject | `<class 'str'>` | True |
| state | `typing.Literal['new', 'in-review', 'closed']` | False |

## IssueComment

| Field | Type | Required |
|---|---|---|
| issue_id | `<class 'str'>` | True |
| author_id | `<class 'str'>` | True |
| body | `<class 'str'>` | True |

## LabelDefinition

| Field | Type | Required |
|---|---|---|
| name | `<enum 'Classification'>` | True |
| semantics | `typing.Literal['metadata-only']` | False |

## LabelingTask

| Field | Type | Required |
|---|---|---|
| document_id | `<class 'str'>` | True |
| label_ids | `list[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^p002:[a-z0-9][a-z0-9:_-]{0,127}$')]]` | True |

## LifecycleEvent

| Field | Type | Required |
|---|---|---|
| target_id | `<class 'str'>` | True |
| event_type | `typing.Literal['hire', 'terminate', 'membership-revoke', 'delete', 'reclassify']` | True |
| effective_at | `<class 'str'>` | True |
| before | `<class 'str'>` | True |
| after | `<class 'str'>` | True |

## PermissionGrant

| Field | Type | Required |
|---|---|---|
| principal_id | `<class 'str'>` | True |
| resource_id | `<class 'str'>` | True |
| actions | `list[typing.Literal['read', 'update', 'approve', 'execute']]` | True |
| effect | `typing.Literal['ALLOW', 'DENY']` | False |
| inherited | `<class 'bool'>` | False |
| cross_tenant | `<class 'bool'>` | False |
| valid_from | `<class 'str'>` | False |
| valid_until | `<class 'str'>` | False |
| revoked_at | `typing.Optional[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$')]]` | False |

## Project

| Field | Type | Required |
|---|---|---|
| resource_id | `<class 'str'>` | True |
| name | `<class 'str'>` | True |

## Provenance

| Field | Type | Required |
|---|---|---|
| source | `typing.Literal['self-created-template', 'sdv-self-generated']` | False |
| generator_version | `typing.Literal['1.0.0']` | False |

## Resource

| Field | Type | Required |
|---|---|---|
| department_id | `<class 'str'>` | True |
| title | `<class 'str'>` | True |
| classification | `<enum 'Classification'>` | True |
| parent_id | `typing.Optional[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^p002:[a-z0-9][a-z0-9:_-]{0,127}$')]]` | False |
| deleted_at | `typing.Optional[typing.Annotated[str, StringConstraints(strip_whitespace=None, to_upper=None, to_lower=None, strict=None, min_length=None, max_length=None, pattern='^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$')]]` | False |
| retention | `typing.Literal['retain', 'scheduled-delete', 'deleted']` | False |
| approval_state | `typing.Literal['draft', 'approved']` | False |
| kind | `typing.Literal['folder', 'document', 'kb-page', 'invoice', 'tool-config', 'mock-dataset', 'cloud-object', 'issue', 'project']` | True |
| version | `<class 'int'>` | False |
| attributes | `dict[str, str  or  int]` | False |

## Tenant

| Field | Type | Required |
|---|---|---|
| enterprise_id | `<class 'str'>` | True |
| name | `<class 'str'>` | True |
| domain | `<class 'str'>` | True |

## WorkloadIdentity

| Field | Type | Required |
|---|---|---|
| department_id | `<class 'str'>` | True |
| name | `<class 'str'>` | True |
| authentication | `typing.Literal['nonfunctional-placeholder']` | False |

## Common and additional entities

All Record subclasses inherit id, tenant_id, owner_id, provenance_id, created_at,
schema_version, notice, lineage and status. Resource.kind provides folder, document,
knowledge page, invoice, tool config, dataset, object, project and issue subtypes.
Classification is PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED, metadata only.
Scenario/ScenarioStep/ThreatHypothesis carry declarative exercise preparation.
ObservedResult/EvidencePointer carry actual observations outside deterministic data.
Delegation distinguishes caller and service scope; approval hashes bind exact action
parameters. Dataset is an aggregate of validated tables, not a shared authentication DB.

Foreign-key validation checks common owner/source/tenant references, every typed
relationship, department and manager relationships, resource parent cycles, document
version/current-hash parity, one DataOwner per resource, task label cardinality,
annotation scope, request/approval separation, legal lifecycle transitions, interval
chronology and explicit cross-tenant grant flags. Intended decisions are reevaluated.
Cross-tenant shares are possible only by a specifically flagged grant; defaults create none.
