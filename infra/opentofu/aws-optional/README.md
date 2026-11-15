# Optional genuine AWS comparison — NOT EXECUTED
No AWS provider or deployable resource is included. This directory and state must
remain separate from local state. `make aws-plan` fails closed until a separate
reviewed configuration is created in a separately authorized coding task.

Before any real operation: explicit approval, disposable account ID, named profile,
region, verified STS caller/account, resource-level permissions, cost estimate, budget
and cleanup review. Pricing is NOT VERIFIED in this build. Standard IAM Access Analyzer ValidatePolicy
is generally documented as no additional charge; custom policy checks and active
analyzers may be charged. Recheck current official pricing before use. Nothing was price-verified
online during this build. No default CI AWS credentials or AWS calls are permitted.

After separate authorization, examples to review (do not execute automatically):
`aws --profile <approved> --region <approved> sts get-caller-identity`
`aws --profile <approved> --region <approved> accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policy-example.json`
Then review a genuine provider plan in this directory with separate state. STS role
assumption/federation requires dedicated roles, trust policy and explicit allow/deny
fixtures. LocalStack tokens are no evidence of those behaviors.
