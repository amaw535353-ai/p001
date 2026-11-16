# Provenance and licensing

Synthetic provenance retains author label, generator version/seed/source digest,
repository commit, location, license identifier, attribution and redistribution
state. `LicenseRef-P008-Synthetic` identifies self-authored fictional content;
redistribution remains review_required. It does not grant upstream corpus rights.

Tool releases and immutable Git references are in the upstream source lock. Python
transitive artifacts use SHA-256 requirement locks; npm uses exact package-lock
versions and integrity hashes. Wheel/license metadata and actual installed versions
are inventoried. MIT tool code licensing does not imply licensing of benchmark data.
No StrongREJECT or official AgentDojo data is copied into the committed dataset.

An upstream-derived component with missing license fields fails strict validation;
restricted/review_required upstream redistribution blocks sanitized export. Local
sanitized self-authored exports remain unpublished and require human license/content
review before any release. SHA-256 and Git history evidence consistency only: no
authorship proof, nonrepudiation, trusted time or label-truth claim is made.
