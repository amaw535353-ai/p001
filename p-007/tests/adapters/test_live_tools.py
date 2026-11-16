import pytest
from p007.adapters import execute_test
from p007.assertions import normalize
from p007.authorization import Guard, P003Reader
from p007.catalog import plan
from p007.runners import discover

pytestmark = pytest.mark.live


def required(adapter):
    cap = discover(adapter)
    if not cap.available:
        pytest.skip("BLOCKED live gate: " + adapter + ": " + cap.reason)
    return cap


def test_R01_promptfoo_version():
    cap = required("promptfoo")
    assert cap.version == "0.125.1" and cap.executable.endswith("promptfoo")


def test_R02_promptfoo_real_local_eval():
    required("promptfoo")
    selected = plan("local-model", "promptfoo", test_id="T-promptfoo-cross-tenant")
    raw = execute_test(selected.tests[0], selected)
    assert raw.executed and raw.samples[0]["http_status"] == 403
    assert normalize(selected.tests[0], raw, compatibility={}).status == "PASS"


@pytest.fixture(scope="module")
def inspect_run():
    required("inspect_ai")
    selected = plan("local-model", "inspect_ai", test_id="T-inspect_ai-model-denied")
    return selected, execute_test(selected.tests[0], selected)


def test_R04_inspect_actual_task(inspect_run):
    selected, raw = inspect_run
    assert raw.executed and raw.original_status == "EVALUATED"
    assert normalize(selected.tests[0], raw, compatibility={}).status == "PASS"


def test_R05_inspect_samples_and_aggregate(inspect_run):
    _, raw = inspect_run
    assert raw.metadata["samples"][0]["scores"]["exact_behavior"] == "C"
    assert raw.metadata["aggregate"] is not None and raw.samples[0]["downstream_calls"] == 0


def test_R07_zap_real_passive_scan(network_context):
    required("zap")
    lease, _, ref, _, _ = network_context
    selected = plan("local-fixture", "zap", target=lease.target)
    guard = Guard(lease.target, P003Reader(ref), lease, selected.tests[0])
    raw = execute_test(selected.tests[0], selected, guard)
    assert normalize(selected.tests[0], raw, compatibility={}).status == "PASS", raw.metadata
    assert guard.used == 1 and all(not a["confirmed_vulnerability"] for a in raw.metadata["alerts"])


@pytest.fixture
def browser_run(network_context):
    required("playwright")
    _, _, _, guard, selected = network_context
    raw = execute_test(selected.tests[0], selected, guard)
    if not raw.executed and raw.original_status.startswith("CHROMIUM-LAUNCH-FAILED"):
        pytest.skip("BLOCKED browser: " + raw.original_status)
    return raw


def test_R10_browser_positive(browser_run):
    assert browser_run.observed["positive_status"] == 200
    assert browser_run.metadata["browser"] == "156.0.8078.79"


def test_R11_browser_server_denial_session_switch_logout(browser_run):
    obs = browser_run.observed
    assert obs["denied_status"] == obs["switched_denial"] == 403
    assert obs["logout_status"] == obs["expired_status"] == 401


def test_R12_browser_external_navigation_refused(browser_run):
    assert browser_run.observed["outside_blocked"] is True
    assert browser_run.metadata["settings"]["requests_continued"] == 0
    assert browser_run.metadata["blocked_requests"]
