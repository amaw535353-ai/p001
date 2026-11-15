# Verified artifact inventory (2026-11-15 UTC)

| Component | Pin | Evidence / caveat |
|---|---|---|
| Python base | 3.12.14-slim + digest | pulled; infra/images.lock.json |
| Host Python | 3.12.14 | executed |
| Docker server | 29.9.2 rootless | executed; host platform supplied |
| kind | v0.33.0 | release binary checked against official SHA-256; bootstrap blocked |
| Kubernetes/kubectl | v1.37.0 | kind default pinned node digest; kubectl release checksum verified |
| Calico | v3.33.1 | official versioned manifest vendored, registry image digests resolved; runtime NOT TESTED |
| LocalStack | 4.14.0 + digest | pulled from official repository; S3 smoke recorded separately |
| OpenTofu | 1.13.9 | release archive checksum verified; init/validate executed |
| AWS provider | 6.25.0 | signed registry.terraform.io release, .terraform.lock.hcl |
| Kubernetes provider | 2.38.0 | signed registry.terraform.io release, .terraform.lock.hcl |
| SDK and transitives | requirements.lock | exact wheel versions + SHA-256, offline verified image install |

Binary URLs/checksums: infra/tools.lock.json. Image digests: infra/images.lock.json
and infra/kind/calico.yaml. Workload image tag is a local build loaded into kind with
imagePullPolicy Never; local image ID recorded by build output. Rebuild after source
changes (the tag is intentionally not a remote publication).

Official sources checked: github.com/kubernetes-sigs/kind v0.33.0 default image and
rootless docs; github.com/projectcalico/calico v3.33.1 manifest; github.com/opentofu/opentofu
v1.13.9 release checksums/changelog; github.com/localstack/docs S3 and IAM pages;
official registry manifests for image digests and signed provider registry metadata.
The latest GitHub API and opentofu.org were proxy-blocked. Tags were discovered with
read-only git ls-remote; version existence does not establish an end-to-end supported
combination. Only actual executed checks establish compatibility. No claim of universal
or full runtime compatibility is made. CI actions use reviewed major tags (mutable
exception); production supply-chain use should pin action commit SHAs after review.
