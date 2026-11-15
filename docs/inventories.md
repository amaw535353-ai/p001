# Inventories

| Asset / namespace | Identity / permissions | Endpoint | Classification |
|---|---|---|---|
| API tenant-a | SA tenant-a:lab-api; get named fixture ConfigMap only; token unmounted | loopback 8081; ClusterIP 8080 | synthetic prompts/markers |
| API tenant-b | SA tenant-b:lab-api; same scoped permission | loopback 8082; ClusterIP 8080 | synthetic prompts/markers |
| mock in each tenant | distinct namespace SA mock; no role binding/token | namespace-local 8080 | simulator responses |
| LocalStack / emulator | no mounted API token; fake test/test | ClusterIP 4566; host forward 4566 | p001-tenant-a/b buckets |
| kind / kube-system | operator and CNI system identities | loopback Kubernetes API | trusted lab platform |
| OpenTofu | host kubeconfig administrator + fake S3 credentials | fixed local providers | ignored local state |
| baseline caller | p001-fixture-tenant-a or tenant-b | loopback API only | public test fixtures |

Dependencies: Docker (container runtime), kind (#103; disposable Kubernetes), Calico
(policy-capable CNI required to test real denials), kubectl (bootstrap/inspection),
OpenTofu (#149; reviewable declarative resources), LocalStack (#101; S3 emulation),
Python stdlib (HTTP, tests, evidence), boto3/botocore (signed S3 API client). Transitive
SDK dependencies and hashes are in services/lab-api/requirements.lock. No other
numbered tool inventory entries are added. #157 is a deferred optional AWS target.
See versions.lock.md for versions, sources and platform caveats.
