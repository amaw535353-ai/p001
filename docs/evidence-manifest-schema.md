# Evidence schema v1
`make lab-evidence` writes ignored evidence/<UTC>/manifest.json and transcript.txt.
Fields: schema_version (1), utc (ISO-8601 UTC), commit (actual SHA or unavailable for
unborn repo), dirty (boolean), verifier, classification, versions (tool output mapping),
config_hashes (relative path → SHA-256), results (array). Each result contains id,
status (PASS/FAIL/BLOCKED/NOT TESTED/NOT APPLICABLE), command, utc, expected, observed,
verifier, and optional scope. No state, credentials, prompts or raw logs are copied.
Commands describe exact fixtures; executable scripts contain their full arguments.
Evidence locations are the manifest path plus result ID. Capture lifecycle exit status
separately; destructive tests do not run implicitly during ordinary lab-test.

Evidence is builder-generated, not human-verified, digitally signed or immutable.
Review before sharing; hash provenance and ignored output are not a substitute for
redaction review. An unborn repo has no commit hash; do not invent one.
