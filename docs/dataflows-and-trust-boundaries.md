# Data flows and trust boundaries

| Flow | Identity | Destination / data | Control / limit |
|---|---|---|---|
| Caller → API | public synthetic bearer fixture | loopback 8081/8082; JSON | tenant-specific fixed token, 4096-byte body |
| API → mock | namespace/pod network identity | mock:8080; synthetic prompt | Calico same-namespace selector, no application authentication |
| API → object store | explicit fake test/test SDK credentials | localstack.emulator.svc.cluster.local:4566 | fixed endpoint, bucket derived from workload tenant |
| Operator → cluster | dedicated kubeconfig administrator | loopback kind control plane | operator trusted; never issued to workloads |
| Workload → Kubernetes API | no mounted credential | none required | automount disabled; named ConfigMap RBAC only |
| Request → logs | correlation ID | stdout | allowlisted fields; no prompts, token, object values |

Kubernetes service accounts are not AWS IAM identities. There is no OIDC federation,
IRSA or workload-to-cloud credential exchange. Emulator credentials grant no assurance
of tenant IAM enforcement. API authorization and network controls protect different
boundaries; compromise of a trusted workload is not modeled as a secure IAM boundary.
Port-forward is an operator path and may bypass NetworkPolicy; do not use it to prove
pod-to-pod authorization. Test network policies from pods using numeric Pod IPs.
Plain HTTP is intentional within this disposable local trust boundary; no enterprise
TLS assurance is claimed. Host/container/cluster loopback addresses are not equivalent.
