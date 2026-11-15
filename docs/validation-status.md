# Validation status — INCOMPLETE / PARTIALLY VERIFIED

Observed 2026-11-15 UTC by Codex. Synthetic lab / not a real client engagement /
no independently verified findings yet. No Git commit exists in this originally
empty repository; the manifest says unavailable rather than inventing a commit SHA.
Source/configuration hashes and the local workload image ID are retained.

| Acceptance check | Status | Actual evidence / limitation |
|---|---|---|
| 1. Prerequisites, isolation, Docker resources | BLOCKED | Tools installed; rootless cgroup driver none; ambient AWS_PROFILE rejected without printing its value |
| 2. OpenTofu fmt/init/validate | PASS | Signed providers, byte-identical lock on repeat init, valid configuration |
| 2. Reviewable plan/apply/zero drift | BLOCKED | Plan cannot construct Kubernetes client because bootstrap cannot create kubeconfig |
| 3. Cluster/namespaces/pod readiness | BLOCKED | kind requires Delegate=yes on a compatible host |
| 3. Deterministic mock inference | PASS | Both tenant API → mock paths exercised in actual Docker containers |
| 4. Synthetic S3 write/read | PASS | Community LocalStack 4.14.0, two buckets, SDK and API round trips in isolated Docker networks; Kubernetes/host endpoint route untested |
| 5. Caller allow/deny | PASS | Correct fixtures succeed; wrong tenant → 403; invalid marker → 400; missing caller and body budget also unit/HTTP-tested |
| 5. Unauthorized service access | BLOCKED | Pod network enforcement requires live Kubernetes |
| 6. Kubernetes RBAC | BLOCKED | Allow/deny fixtures implemented; no API server to execute them |
| 7. Actual CNI connection denial | BLOCKED | Pinned Calico and policies configured; no runtime enforcement claim |
| 8. Exposure and workload constraints | PASS / BLOCKED | No host ports in Docker smoke; structural restrictions pass; deployed Kubernetes constraints/cgroup enforcement unverified |
| 9. Sanitized logs/evidence | PASS | Allowlisted service logs and correlation IDs verified; manifest/transcript generated |
| 10. Drift detection/restoration | BLOCKED | Implemented test cannot execute without cluster |
| 11. Teardown/rebuild | BLOCKED | Absent-cluster teardown twice succeeds; Docker smoke resources cleaned; live cluster destruction/rebuild not tested |
| 12. Static checks | PASS | Python syntax, shell syntax, JSON/schema syntax, narrow secret patterns, resource structure, IaC validation |
| 12. Dedicated vulnerability/dependency/container/secret scanners | NOT TESTED | Not installed/executed; narrow checks are not comprehensive scanners |
| LocalStack IAM / genuine AWS IAM/STS | NOT TESTED | IAM disabled in observed emulator; no enforcement or AWS parity claim |
| Unauthorized AWS plan gate | PASS | make aws-plan refuses with exit 2 and no AWS calls |
| Remote CI | NOT TESTED | Workflow saved; no push or remote workflow run performed |

Seven unit/HTTP tests and eleven Docker integration checks passed. The successful
container run returned exit 0 and removed all its labelled containers/networks.
Initial TLS build, startup, file-mode and proxy issues were diagnosed and corrected;
TLS/signature/checksum verification was preserved. Raw failed-run logs remain local
under ignored .runtime and are not publication artifacts.

## Precise resolution
Move the checkout/prepared environment to a kind-compatible Linux x86_64 Docker host
(or have an authorized host administrator supply delegated cgroups for rootless
Docker). Do not bypass kind checks. Use a clean shell without real-cloud bindings;
for this platform's ambient profile, `env -u AWS_PROFILE make doctor` removes only
that binding from the command environment, but does not fix cgroups. Then execute
scripts/install, make doctor, make lab-up, make lab-test, make lab-evidence,
make lab-down twice and make lab-rebuild-verify. Preserve actual results and inspect
plan, RBAC, network-denial and drift outcomes before claiming completion.

The optional AWS track has scoped policy examples and validation guidance; aws-plan
is deliberately fail-closed, with no deployable account-specific configuration yet.
Dedicated scanners and human assessment/host comparisons remain deferred.

Reusable cloud configuration: install_script and start_skill were saved as a draft.
Saving does not execute or publish. Review and save them in environment settings;
publish only after accepting the documented limitations or completing blocked checks.
No fresh-task restoration has been verified. No secret or network settings were changed.

Evidence: [evidence/20261115T082804Z/manifest.json](../evidence/20261115T082804Z/manifest.json). Each manifest result has exact command/fixture, UTC timestamp, expected and observed outcome, status and verifier. Full fixture arguments live in the referenced executable script.
