# Privacy and synthetic-data limitations

SYNTHETIC — TRAINING DATA — NOT A REAL CLIENT

Inputs are a seed, bundled self-authored templates and fixed scenario definitions.
No customer data, scraped names, personnel records, clinical records, emails, financial
records or production credentials are imported, transformed or used as training data.
Addresses end in `example.test`. Accounts, amounts, cloud references and canaries are
explicitly fictional. No email/SMS/invitation or payment integration exists.

Coincidental resemblance is possible; synthetic data is not automatically anonymous
or privacy-proof. SDV fits only generator-created amounts and does not establish a
privacy guarantee. Generated identities are not SSO authentication. Native local test
passwords/tokens are functional only inside disposable, internal lab instances and
are generated into excluded `.runtime/` files, never exported as fixtures.

Untrusted text never becomes Python, a shell command, a template expression, a URL
request or an LLM instruction. JSON serialization preserves it as text. CSV prefixes
formula-like leading content with an apostrophe; Markdown rendering helpers escape
HTML, backticks and link delimiters. Document files are training content, not trusted
renderable HTML. Inert instruction fixtures are opt-in, labelled and excluded from
public commits. Do not publish runtime journals, raw logs, instance IDs, `.env`, secrets,
unsafe snapshots or a learner's unreviewed findings.
