# Sources, versions and licenses

The supplied P-005 build prompt is the available design source. SHA-256:
`e5f1b6b3009f8688393cb84d3724c136c5b917aa23bb7d659bcddab893eca35a`.

Searched /workspace for the exact named crosswalk, 37-risk practice map, full
project list and career roadmap. None is present. Prior P-002–P-004 documentation
reports the same limitation. No missing formal taxonomy name, roadmap detail,
control identifier or source-file content is invented. risks.json has all 37
number slots; only the 23 explicitly described in prompt section 5 are usable.
Unavailable entries have null descriptions and fail mapping validation.

P-001 manifests, P-002 Dataset/generator, P-003 sealed Engagement and P-004 Snapshot,
Graph and parsers were read from actual committed base 6e153d2. Integration status
is established by local tests, not predecessor master prompts.

ATLAS source: https://raw.githubusercontent.com/mitre-atlas/atlas-data/f56c1468731d6428e5bf875263b4643b46d67437/dist/v6/ATLAS-2026.10.yaml

- Official repository commit: `f56c1468731d6428e5bf875263b4643b46d67437`.
- Content: 2026.10; format: 6.1.0; 221 parsed techniques.
- Original distribution SHA-256: `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`.
- Imported UTC: 2026-11-15T18:03:36Z.
- License: Apache-2.0; upstream notice retained in catalogs/LICENSE-ATLAS.txt; full license in
  catalogs/Apache-2.0.txt and packaged data/LICENSE-ATLAS.txt.
- Inspected official README and atlas/schemas.py; schema source SHA-256:
  `3d1ef841e5c1c49a4e2599dcd7c75cb01e69032042560a5a27d239e9258bdd8b`. Upstream Python was read, not executed.
- dist/ATLAS.yaml is deprecated; dist/ATLAS-latest.yaml and dist/v6/ATLAS-latest.yaml
  are symlink text in raw GitHub. The pinned concrete v6/ATLAS-2026.10.yaml is used.
  Runtime never follows such references or fetches updates.

ATLAS records and rationales are references, not proof of an attack. The curated
mapping is editable data, checked against parsed IDs; other cases are UNMAPPED.

Dependency lock is reused exactly from the inspected P-004 Linux x86_64/Python
3.12 toolchain, including dev tools and optional predecessor requirements. Known
runtime licenses: Pydantic MIT, PyYAML MIT, jsonschema MIT; pytest MIT, Hypothesis
MPL-2.0, Ruff MIT, mypy MIT. Review installed distribution metadata and transitive
licenses before redistribution. This is not a new overall license for the existing
repository. No optional native binary/image is downloaded or asserted licensed.
