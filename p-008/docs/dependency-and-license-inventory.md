# Dependencies, licenses and observed advisories

The core lock contains 24 third-party packages; the working core environment also
has five local editable projects (29 distributions). The isolated tool lock has
135 distributions. The npm lock records 667 package entries. Exact installed
versions, metadata license fields and all lock hashes are in dependency-inventory.json.
Both Python environments passed `uv pip check`; a fresh core-only environment
installed the hash lock and reproduced the demo without any sibling packages.

Required tools: Inspect AI 0.3.290 (MIT), Inspect Evals 0.29.0 (MIT), AgentDojo
0.1.35 (MIT), Promptfoo 0.125.1 (MIT). Official notices are in docs/licenses/.
The three transitive metadata gaps were reviewed against installed license files:

| Component | Metadata gap resolution | Actual file |
|---|---|---|
| agent-client-protocol 1.0.0 | Apache-2.0 | agent_client_protocol-1.0.0.dist-info/licenses/LICENSE |
| sylvester 0.0.21 | MIT | node_modules/sylvester/LICENSE.txt |
| xmlhttprequest-ssl 2.1.2 | MIT | node_modules/xmlhttprequest-ssl/LICENSE |

The local P-002/P-003/P-005/P-007/P-008 projects lack package license metadata.
Their publication rights remain REVIEW_REQUIRED; this build does not assign a
new license to sibling/user source. Synthetic dataset licensing is separately
identified as LicenseRef-P008-Synthetic, redistribution review_required.

`npm audit --omit=dev --json` initially reported 9 affected dependency entries
(5 high, 4 moderate). Five exact overrides retain Promptfoo 0.125.1 while moving
@hono/node-server to 2.1.8, @modelcontextprotocol/server-filesystem to 2.3.0,
basic-ftp to 6.2.6, glob to 14.0.6, and minimatch to 11.0.8. Overrides are visible
in tools/package.json and fully locked. Actual Promptfoo assertions were rerun.
The final npm audit reported **0 known advisories**.

pip-audit 2.10.1 checked the core (24) and tool (135) requirement locks separately
through PyPI's advisory service; each reported **0 known vulnerabilities**. The
initial attempt to combine incompatible core/tool Pydantic pins was rejected by
the auditor, then replaced with separate environment audits. Raw audit output
stays under ignored .tools/. No advisory suppressions or forced downgrades were
used. These are time-specific database results, not proof of vulnerability absence,
complete supply-chain review, legal compliance or benchmark dataset licensing.
