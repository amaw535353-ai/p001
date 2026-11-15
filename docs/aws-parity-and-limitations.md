# LocalStack versus genuine AWS
S3 bucket/object behavior is the selected local capability. Official LocalStack S3
page marks it Free; the pulled image digest and observed functional results identify
the actual artifact. No token, paid subscription or IAM-enforcement flag is supplied.
IAM policy creation does not prove enforcement. Local IAM authorization is **NOT TESTED**;
no local test can satisfy genuine AWS IAM/STS/federation requirements here. Edition
features and licensing can change: inspect current product terms before upgrading.

Fake test/test emulator credentials are shared by trusted APIs; tenant bucket selection
is application-controlled, not an independently verified cloud authorization boundary.
Kubernetes service accounts do not become AWS roles. No IRSA/OIDC path is implemented.

AWS comparison is optional (#157), separate state/configuration, separately authorized,
with account/profile/region verification, resource scope, costs/budgets and reviewed
plan. See infra/opentofu/aws-optional. Default aws-plan fails closed without API calls.
No AWS, paid model, GPU, registry push, remote publication or third-party scan occurred.

Supported current validation: Linux x86_64 host Python, Docker containers, static IaC.
Full kind+CNI compatibility remains blocked by host delegation. Pinning artifacts
establishes identity/integrity, not absence of vulnerabilities or universal compatibility.
