from collections import Counter

from security.aggregate_report import gate_decision


def test_gate_fails_on_critical():
    passed, _ = gate_decision(Counter({"critical": 1}), fail_on_high=False, fail_on_critical=True)
    assert not passed


def test_gate_fails_on_high_when_enabled():
    passed, _ = gate_decision(Counter({"high": 1}), fail_on_high=True, fail_on_critical=False)
    assert not passed


def test_gate_passes_when_no_blocking_severity():
    passed, _ = gate_decision(Counter({"medium": 3}), fail_on_high=True, fail_on_critical=True)
    assert passed
