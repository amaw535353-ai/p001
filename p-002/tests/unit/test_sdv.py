import importlib.util
import pytest
from p002.generators import generate


@pytest.mark.skipif(importlib.util.find_spec("sdv") is None, reason="optional SDV not installed")
def test_sdv_generated_only_fields_and_bounds():
    a = generate(1, "tiny")
    b = generate(1, "tiny", "sdv")
    assert b.sdv_report["rows"] == 6 and b.sdv_report["version"] == "2.2.0"
    assert (
        a.humans == b.humans
        and a.grants == b.grants
        and [x.expected for x in a.decisions] == [x.expected for x in b.decisions]
    )
    assert a.documents == b.documents
    assert all(1000 <= r.attributes["amount_cents"] <= 100000 for r in b.resources if r.kind == "invoice")
