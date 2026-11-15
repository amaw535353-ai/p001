# Pinned ATLAS data

ATLAS-pinned.yaml is the byte-for-byte official v6/ATLAS-2026.10.yaml artifact.
ATLAS-pin.json records the commit, source, format, license and hashes. Its
technique projection is bundled in the Python package for fully offline analysis.

p005 catalog validate --input catalogs/ATLAS-pinned.yaml
p005 catalog list
p005 catalog update --from-local-file catalogs/ATLAS-pinned.yaml --metadata catalogs/ATLAS-pin.json --out generated/catalog-candidate.json

The last command validates a local candidate only; it never fetches, executes or
automatically activates data. Supply reviewed source metadata and correct checksum
for another v6.1 distribution. Changing the bundled pin requires an explicit code
review, regenerated index, ID checks and tests. Unsupported formats fail closed.
