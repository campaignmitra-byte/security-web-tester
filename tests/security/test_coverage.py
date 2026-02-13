from security.attack_taxonomy import ATTACK_TAXONOMY
from security.coverage import coverage_summary


def test_coverage_detects_full_mapping():
    catalog = [{"attack_id": attack.id} for attack in ATTACK_TAXONOMY]
    summary = coverage_summary(catalog)
    assert summary["missing_attack_ids"] == []
    assert summary["unknown_attack_ids"] == []


def test_coverage_detects_missing_items():
    summary = coverage_summary([{"attack_id": ATTACK_TAXONOMY[0].id}])
    assert summary["covered_attack_classes"] == 1
    assert len(summary["missing_attack_ids"]) == len(ATTACK_TAXONOMY) - 1
