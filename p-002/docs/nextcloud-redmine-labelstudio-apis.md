# Verified API/edition contracts and limits

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Official documentation hosts (`docs.nextcloud.com`, `www.redmine.org`, `labelstud.io`,
`docs.sdv.dev`) returned proxy tunnel 403 in this task. The builder read official
upstream documentation/controller/test source from `raw.githubusercontent.com`
before coding, then corrected compatibility from actual pinned-image responses.
`integrations/api-sources.json` records URLs, SHA-256 and retrieval outcome. Main/develop
source is not claimed to be immutable release documentation; runtime tests establish
the supported subset for the actual versions below.

| Target | Actual version / edition | Implemented and exercised API subset | Limits |
|---|---|---|---|
| Nextcloud | 34.0.6 Community server (empty edition string) | OCS users/groups, group file shares, WebDAV MKCOL/PUT/GET/PROPFIND | No custom deny/approval/delegation lattice or enterprise classification claim |
| Redmine | 6.1.6.stable, GPL Community | Users, private projects, memberships, issues and notes via JSON REST; supported local Rails/default-data bootstrap | Native role permissions are only the tested project subset; no SSO or generalized per-record ACL claim |
| Label Studio | 1.23.0 Community, Apache-2.0 source | Project label config, synchronous import with actual task IDs, annotation POST, task GET roundtrip | No Enterprise RBAC, asynchronous import, per-tenant project isolation or label-as-authorization claim |
| SDV | 2.2.0 Community, BSL 1.1 | Metadata.detect_from_dataframes; GaussianCopulaSynthesizer dictionary fit/sample | Self-generated numerical seed table only; no paid constraint feature or anonymity claim |
| P-001 | Existing P-001 source/image, generator API contract | Fixed synthetic marker PUT/GET and tenant token mismatch | No full document API, delete endpoint, Kubernetes/IAM or real IdP verification |

Nextcloud provisioning requires `OCS-APIRequest: true`, Basic credentials, URL-encoded
form payloads and explicit generated passwords (no welcome-mail workflow). Sharing
uses type 1 (local group), permissions 3 (read/update), `sendMail=false`; public-link,
email and federation sharing are never used. Imported subset: two documents per
department (ordinary shared doc0 and owner-only restricted doc3), six groups, twelve
ordinary users and six folders. Owner-only doc3 is a deliberately stricter mapping
than some canonical members; complete ACL equivalence is **NOT VERIFIED**. Actual
file IDs, last-modified times, share IDs and hashes are journaled. Wrong-user checks
use ordinary accounts, never the administrator credential.

Redmine creates a role with view/add/edit/note issue permissions during disposable
local bootstrap and loads default trackers/statuses/priorities via the supported rake
task. Twelve users join six private projects. The twelve issues retain canonical
identifiers and requester/assignee mappings. Account mail notification is disabled;
network isolation also prevents external mail. An admin does provisioning; reporter
accounts create/read/update their issues, and other-tenant nonmembers are denied.
The adapter safely reconciles tracker configuration only on its journaled projects.

Label Studio config is Text + single required Choices with the four canonical
classification values. Six representative departmental doc0 tasks (out of 60 standard
tasks) are imported and annotated PUBLIC, matching those canonical documents. The
actual owner token is private and explicitly enabled through the tested legacy-token
bootstrap; no placeholder string is used for authentication. Importing all tenants'
content into this one operator-owned labeling project is a **trusted operator
integration**, not a demonstration of tenant security partitioning. Task IDs and
annotation IDs map to canonical task/document IDs; text readback hashes are checked.

Idempotence is journal-based with readback/collision checks. A crash between native
creation and journal persistence can require explicit investigation; the importer
refuses to adopt a pre-existing unjournaled object rather than claim a successful
reconciliation. Journals and secrets are trusted mode-0600 operator state, not
cryptographically tamper-proof records. Whole-deployment reset removes only exact
owned disposable resources, never pre-existing applications or account-wide data.
