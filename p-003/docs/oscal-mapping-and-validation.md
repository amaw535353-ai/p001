# NIST OSCAL #128: explicitly partial

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

The official usnistgov/OSCAL v1.2.3 tag resolves to commit
e061961c7702afeabffdf5e59894d35e748dade1. The assessment-plan schema was retrieved
from the official versioned release asset, checksummed and vendored unchanged.
Its schema $id is http://csrc.nist.gov/ns/oscal/1.2.3/oscal-ap-schema.json. The
version and checksums are in src/p003/data/sources.json; NIST license is adjacent.
Official conceptual/validation references supplied in the build prompt remain
references, not claims that every referenced service was reachable from this host.

The AP root requires uuid, metadata, import-ssp and reviewed-controls; import-ssp
requires href and reviewed-controls requires control-selections. This module has no
validated synthetic SSP/control catalog. Inventing those would exceed the P-003
scope and misstate assessment coverage. Export therefore contains kind
oscal-mapping-draft, conformance NOT VALID OSCAL, a coverage/unsupported matrix,
planned requirement references and missing prerequisites. It is never an OSCAL AP,
assessment results, POA&M, FedRAMP artifact, certification or ATO.

`./scripts/p003 export oscal ...` executes official-schema validation on the draft.
The observed result is REJECT (required root and additional properties), as tested.
The export is successful because a labeled draft was requested; rejection is not
counted as valid OSCAL. An independently validated SSP/catalog and semantic mapping
are required before implementing a conformant exporter.

NIST patterns use Unicode properties such as \p{L}. Python's re rejected the
unaltered official schema during initial integration. The validator now uses pinned
regex==2026.11.9 for pattern checks and metaschema regex validation, preserving
schema bytes. This is not a waiver of official validation. Full OSCAL conformance,
SSP linkage and catalog semantic validation remain NOT IMPLEMENTED.
