# Playwright integration (#145)

Actual Playwright 1.65.2 drives existing Debian Chromium 156.0.8078.79; a version
mismatch blocks execution. Each synthetic user context is isolated. Every browser
HTTP request is intercepted and fulfilled by GuardedHTTP; no route is continued
directly. Service workers/downloads are disabled; DNS prefetch and background
networking are disabled and host resolution refuses non-loopback destinations.

The browser exercises unauthenticated access, login, same-tenant read, server-side
cross-tenant 403, tenant switch, expired/logout 401, independent context isolation,
safe text rendering, empty local/session storage, HttpOnly/SameSite cookie flags,
denied-model downstream count zero, and external navigation refusal. A hidden
button is never treated as authorization. Network evidence retains paths/statuses
only. Cookies remain in memory; screenshots/traces are omitted rather than exporting
unsanitized credentials. All contexts and browser processes close on completion.

The managed host's Chromium SUID sandbox helper is unavailable. The explicit
`config/browser.json` profile disables the sandbox for these trusted, generated
fixture pages only; this is a residual host limitation and not approval to browse
untrusted sites. Other browser engines, arbitrary apps and browser upgrades are
NOT_TESTED. A compatible, sandbox-capable host should use a reviewed sandbox profile.

Sources inspected: [installation](https://playwright.dev/python/docs/intro),
[network interception](https://playwright.dev/python/docs/network),
[Apache-2.0 license](https://github.com/microsoft/playwright-python/blob/main/LICENSE).
