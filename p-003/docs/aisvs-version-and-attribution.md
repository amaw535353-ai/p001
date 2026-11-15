# OWASP AISVS #126 registry and attribution

SYNTHETIC TRAINING ENGAGEMENT — NOT AUTHORIZATION FOR REAL-WORLD TESTING

Source: https://github.com/OWASP/AISVS, tag v1.01, full commit
3ae3af45c363467b8ad823ef79219236e67ca22f, file
1.01/en/0x10-C05-Access-Control-and-Identity.md. Tag identities were obtained with
read-only git ls-remote; the tagged source and LICENSE.md were retrieved and their
SHA-256 hashes saved in src/p003/data/sources.json. Development v1.02 content is not
used. The vendored Chapter 5 and license are byte-for-byte copies.

OWASP AISVS contributors' material is licensed CC-BY-SA-4.0. Preserve attribution,
license and share-alike obligations when distributing the source, extracted catalog
or derived mapping material. This is not OWASP endorsement. Exact requirement text
retains original Markdown, including **Verify that**. No requirement wording or level
is silently rewritten. The registry parses 11 Chapter 5 rows and rejects unknown IDs,
wrong versions, altered text/levels and assessment states such as passed.

| Selected versioned ID | Source level | Planning rationale |
|---|---|---|
| v1.01-C5.2.1 | 2 | Later verify actual AI-resource default-deny and allowlist controls |
| v1.01-C5.2.5 | 2 | Later verify agent execution/PDP isolation |
| v1.01-C5.3.1 | 2 | Later verify tenant separation in model serving |

Mappings include actual source text, asset references, rationale, method and needed
evidence. They remain planned. P-003 governance tests do not assess these controls
at an AI target. Applicability and results belong to the independent assessor.
