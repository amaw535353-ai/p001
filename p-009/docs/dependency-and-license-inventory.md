# Dependency and license inventory

Exact immutable image references are in `config/images.lock.json`; Python versions and artifact
hashes are in `requirements.lock`. `docs/dependency-inventory.json` records installed distribution
metadata. Collector uses contrib0.165.0, OpenLLMetry traceloop-sdk0.63.0/OTel1.45.2, Langfuse4.80.0
and Wazuh4.14.10. Supporting images pin Python3.12.14, PostgreSQL17, Redis7.4, ClickHouse26.3.62.3
and Chainguard MinIO by exact platform digest. Mutable tag names are never the sole image pin.

Collector/OpenLLMetry upstream source is Apache-2.0. Langfuse's pinned root license is MIT outside
separately licensed enterprise directories and third-party components; preserve ClickHouse's
copyright and upstream notices. Wazuh is GPL-2.0 with separately licensed bundled components.
PostgreSQL uses PostgreSQL License, ClickHouse Apache-2.0, MinIO AGPL-3.0 and Redis7.4 has its
upstream RSALv2/SSPLv1 licensing terms. Images and bundled dependencies need their own review.

Official repository source hashes, reviewed document hashes and sibling interface hashes are
recorded in source-discovery.json. Registry manifests were resolved read-only; exact native
execution is recorded separately. Missing/unknown metadata is not legal clearance. Full transitive
image SBOM/CVE review and redistribution/license analysis remain unverified; hashes do not certify
vulnerability freedom. No upstream source, credential or image is published by this source change.
