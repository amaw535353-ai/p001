# P-010 security requirements

Keep report intake read-only, reject unknown canonical fields, enforce
byte/path bounds, reject symlinks, and verify exact record references
inside each engagement. Decisions need explicit roles and provenance.
The default workflow has no target executor or external network
transport. Optional Redmine is locally isolated and Langfuse is an
explicit loopback GET binding with version/project validation. Reports
and logs contain minimized synthetic metadata. The acceptance matrix
maps behavior to the corresponding verified or unresolved cases.
