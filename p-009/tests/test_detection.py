import pytest

from p009.detection import candidates, rules
from p009.safety import Invalid


@pytest.mark.parametrize("rule", rules(), ids=lambda r: r.signal)
def test_synthetic_abnormal_pair_has_exact_candidate(rule):
    value = {"p009": "v1", "signal": rule.signal, "count": rule.minimum_count}
    matched = candidates(value)
    assert [m.rule_id for m in matched] == [rule.rule_id]
    assert matched[0].severity == rule.severity


@pytest.mark.parametrize("rule", rules(), ids=lambda r: r.signal)
def test_synthetic_benign_pair_below_precondition(rule):
    assert candidates({"p009": "v1", "signal": rule.signal, "count": rule.minimum_count - 1}) == []


def test_forged_severity_has_no_effect():
    value = {"p009": "v1", "signal": "event-replay", "count": 1, "severity": 15}
    assert candidates(value)[0].severity == 4


def test_unknown_signal_not_alert():
    assert not candidates({"p009": "v1", "signal": "forged-rule", "count": 100})


def test_unclassified_log_injection_body_refused():
    with pytest.raises(Invalid):
        candidates({"p009": "v1", "signal": "log-injection", "count": 1, "raw": "forged\nmessage"})
