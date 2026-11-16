"""Actual Chromium flows with every HTTP request fulfilled by the scoped broker.

Service workers are disabled; no browser request is continued to the network.
Server decisions, UI rendering and isolated cookie/session contexts are measured.
"""

import time

from p007.authorization import GuardedHTTP
from p007.models import RunnerResult
from p007.runners import environment
from p007.safety import PROJECT, Blocked, load


def run(test, plan, capability, folder, guard=None):
    from playwright.sync_api import Error, sync_playwright

    if guard is None:
        raise Blocked("P003-GUARD-REQUIRED")
    browser_pin = load(PROJECT / "config/browser.json")
    responses, refusals = [], []
    broker = GuardedHTTP(guard)
    contexts = []
    started = time.monotonic()
    with sync_playwright() as api:
        try:
            browser = api.chromium.launch(
                executable_path=browser_pin["executable"],
                headless=True,
                chromium_sandbox=browser_pin["sandbox"],
                env=dict(environment(folder)),
                args=[
                    "--dns-prefetch-disable",
                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                    "--disable-domain-reliability",
                    "--disable-client-side-phishing-detection",
                    "--no-default-browser-check",
                ],
            )
        except Error as exc:
            raise Blocked("CHROMIUM-LAUNCH-FAILED:" + type(exc).__name__) from exc
        try:
            if browser.version != browser_pin["version"]:
                raise Blocked("CHROMIUM-VERSION-PIN-MISMATCH")

            def context():
                ctx = browser.new_context(service_workers="block", accept_downloads=False)
                contexts.append(ctx)
                ctx.set_default_timeout(5000)
                ctx.set_default_navigation_timeout(5000)

                def route_handler(route):
                    request = route.request
                    if time.monotonic() - started > test.limits.timeout_seconds:
                        refusals.append("TIME-BUDGET")
                        route.abort()
                        return
                    try:
                        # Only synthetic session state is passed in memory, never persisted.
                        cookie = request.headers.get("cookie", "")
                        session = next(
                            (x.split("=", 1)[1] for x in cookie.split("; ") if x.startswith("p007_session=")),
                            None,
                        )
                        row = broker.request(request.url, request.method, session=session)
                        responses.append(
                            {"path": request.url.removeprefix(plan.target.origin), "status": row["status"]}
                        )
                        headers = dict(row["headers"])
                        if row["set_session"]:
                            headers["Set-Cookie"] = (
                                "p007_session=" + row["set_session"] + "; HttpOnly; SameSite=Strict; Path=/"
                            )
                        route.fulfill(status=row["status"], headers=headers, body=row["body"])
                    except Blocked as exc:
                        refusals.append(str(exc))
                        route.abort()

                ctx.route("**/*", route_handler)
                return ctx

            a = context()
            page = a.new_page()
            page.goto(plan.target.origin + "/ui")

            def click(identifier, expected_status):
                page.locator("#" + identifier).click()
                page.wait_for_function(
                    "prefix => document.querySelector('#result').textContent.startsWith(prefix)",
                    arg=str(expected_status) + ":",
                )
                return int(page.locator("#result").inner_text().split(":", 1)[0])

            unauth = click("own", 401)
            click("login-a", 200)
            own, denied = click("own", 200), click("other", 403)
            cookies = a.cookies()
            httponly = bool(cookies) and all(c["httpOnly"] and c["sameSite"] == "Strict" for c in cookies)
            click("login-b", 200)
            switched = click("own", 403)
            click("expired", 200)
            expired = click("own", 401)
            click("login-a", 200)
            click("logout", 200)
            logout = click("own", 401)
            safe_render = page.locator("#unsafe img").count() == 0 and not page.evaluate(
                "Boolean(window.p007Markup)"
            )
            storage_empty = page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
            denied_model = broker.request(plan.target.origin + "/model/denied")
            import json

            denied_payload = json.loads(denied_model["body"])
            model_before = denied_model["status"] == 403 and denied_payload.get("downstream_calls") == 0
            # Independently isolated context cannot inherit A's synthetic session.
            b = context()
            page_b = b.new_page()
            response_b = page_b.goto(plan.target.origin + "/objects/a")
            isolated = response_b is not None and response_b.status == 401
            try:
                page.goto("https://example.invalid/")
            except Error:
                pass
            outside = bool(refusals) and not any("example.invalid" in r["path"] for r in responses)
            observed = dict(
                positive_status=own,
                denied_status=denied,
                unauthenticated_status=unauth,
                expired_status=expired,
                logout_status=logout,
                switched_denial=switched,
                safe_rendering=safe_render,
                outside_blocked=outside,
                cookie_httponly=httponly,
                storage_empty=storage_empty and isolated,
                model_denied_before_invoke=model_before,
            )
            return RunnerResult(
                adapter="playwright",
                executed=True,
                original_status="COMPLETE",
                exit_code=0,
                observed=observed,
                samples=[observed],
                tool_version=capability.version,
                commands=[
                    [
                        capability.executable,
                        "p007.adapters.playwright.run",
                        "--owned-target",
                        plan.target.target_id,
                    ]
                ],
                metadata={
                    "browser": browser.version,
                    "browser_executable": browser_pin["executable"],
                    "sandbox": browser_pin["sandbox"],
                    "network": responses,
                    "blocked_requests": refusals,
                    "context_count": len(contexts),
                    "screenshots_traces": "omitted to avoid cookie/token retention",
                    "settings": {"service_workers": "block", "requests_continued": 0},
                },
            )
        except Error:
            return RunnerResult(
                adapter="playwright",
                executed=True,
                original_status="BROWSER-FLOW-ERROR",
                exit_code=1,
                error_class="provider",
                tool_version=capability.version,
                metadata={"network": responses, "blocked_requests": refusals},
            )
        finally:
            for ctx in contexts:
                ctx.close()
            browser.close()
