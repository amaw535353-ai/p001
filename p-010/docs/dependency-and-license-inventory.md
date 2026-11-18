# Dependencies and licenses

Python 3.12.14 and uv 0.13.6 were used. The 24 installed Python
dependencies are pinned with hashes in `requirements.lock`. `uv pip
check` validated the environment. Exact PyPI release metadata for all
24 packages listed zero advisories at execution. The OSV query returned
HTTP 403. An independent advisory-source check and comprehensive image
SBOM and CVE review remain open.

| Component | Version and pin | Reviewed license |
| --- | --- | --- |
| Redmine | 7.0.3, source `2600f7fb584b6a0a61d48a29358c76fb7a5ae95a`, amd64 manifest `sha256:d1733887bbc92c096042eebd035b6f0b18d90e3a8e3925abd817c9fea9c0a50b` | GPL-2.0 family, upstream `doc/COPYING` |
| NIST OSCAL | v1.2.3, source `e061961c7702afeabffdf5e59894d35e748dade1` | NIST public domain notice and external-contribution terms in the copied official license |
| MITRE ATLAS data | 2026.10, format 6.1.0, source `f56c1468731d6428e5bf875263b4643b46d67437` | Apache-2.0, reuse from the P-005 pin and attribution |
| Langfuse | 4.80.0, source `fd23d7e66992ae9e19eadcd3a7cf6421137cd076` | MIT Expat for open components, separate EE and third-party terms |

Source links for the [Redmine license](https://github.com/redmine/redmine/blob/7.0.3/doc/COPYING),
[NIST release](https://github.com/usnistgov/OSCAL/releases/tag/v1.2.3),
[ATLAS catalog](https://github.com/mitre-atlas/atlas-data/tree/v2026.10)
and [Langfuse license](https://github.com/langfuse/langfuse/blob/v4.80.0/LICENSE).

Pydantic, pydantic-core, PyYAML, jsonschema and its core supporting libraries
declare MIT. Regex declares Apache-2.0 and CNRI-Python. The test/build
lock additionally contains MPL-2.0 (pathspec), Apache-2.0 (types-PyYAML),
Apache-2.0 or BSD-2-Clause (packaging), BSD-2-Clause (Pygments),
PSF-2.0 (typing-extensions), and MIT tools. CI actions use the repo's
existing major-tag convention. No Redmine or Langfuse product source or
images are committed here.
