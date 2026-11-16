# Security boundaries

Datasets are bounded data. Strict models reject unknown fields, unsupported
modalities and invalid scores. Inputs cannot select Python modules, shell commands,
plugins, providers or URLs. JSON duplicate keys and nonfinite values are rejected;
YAML uses SafeLoader and refuses aliases/anchors and object constructors. Only
JSON/YAML files are loaded; archives and pickle are unsupported.

Path traversal, absolute child paths and symlinks are refused; new writes use
O_EXCL/O_NOFOLLOW and private file modes. Dataset versions, plans and run records
are write-once through the registry. Cleanup requires explicit confirmation and
verified ownership, refuses protected baselines, and removes only a selected run.
The filesystem/host is trusted; these are not defenses against a hostile host
administrator or concurrent attacker replacing every anchor.

Execution defaults to the fixed in-process responder. Optional workers receive
sanitized environments without provider credentials, fixed argv and reviewed code.
They have wall/CPU/file/FD limits, Python virtual-address limits, and a bounded
Node heap. Process groups are killed on timeout/cancellation. Output at its limit
is incomplete/BLOCKED even if a child exits zero. Python/Node guards refuse network
connections and DNS. They are application-level guards, not kernel network
namespaces or an arbitrary-code sandbox; hard Node RSS isolation is not claimed.

Sealed outcomes and canaries are private and outside model-visible inputs. Host
oracles explicitly read expected outcomes; model judges cannot. Public exports use
allowlisted fields, remove sealed per-sample statuses/dimensions and raw observations,
and fail on known marker/key strings. Semantic/encoded leakage and aggregate
membership inference cannot be ruled out by these finite redaction tests.

All shipped content is synthetic or attributed tool references. No client data,
real credentials, external target tests or model APIs are used. Dependency risk
remains a supply-chain consideration; see the observed advisory report.
