import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import pytest
from p002.generators import generate
from p002.operations import record_run

ROWS = []


@pytest.fixture(scope="session")
def dataset():
    return generate(profile="tiny")


def pytest_runtest_logreport(report):
    if report.when == "call" or (report.when == "setup" and (report.failed or report.skipped)):
        ROWS.append(
            {
                "id": report.nodeid,
                "status": "PASS" if report.passed else ("NOT TESTED" if report.skipped else "FAIL"),
                "precondition": "isolated synthetic test fixture",
                "expected": "all declared assertions pass",
                "observed": "assertions passed"
                if report.passed
                else ("skipped" if report.skipped else "assertions failed; see private pytest output"),
            }
        )


def pytest_sessionfinish(session, exitstatus):
    if ROWS:
        record_run(
            "core-tests",
            ROWS,
            generate(profile="tiny"),
            args="python -m pytest " + " ".join(session.config.invocation_params.args),
        )
