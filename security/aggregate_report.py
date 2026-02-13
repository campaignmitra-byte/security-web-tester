from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = ROOT / "security" / "reports"
CONFIG = ROOT / "security" / "config.json"


def load_stage_reports() -> list[dict]:
    reports = []
    for file in sorted(REPORTS_DIR.glob("*.json")):
        reports.append(json.loads(file.read_text(encoding="utf-8")))
    return reports


def summarize_findings(reports: list[dict]) -> Counter:
    counter: Counter = Counter()
    for report in reports:
        for finding in report.get("findings", []):
            counter[finding.get("severity", "unknown").lower()] += 1
    return counter


def gate_decision(summary: Counter, fail_on_high: bool, fail_on_critical: bool) -> tuple[bool, str]:
    if fail_on_critical and summary.get("critical", 0) > 0:
        return False, "critical findings present"
    if fail_on_high and summary.get("high", 0) > 0:
        return False, "high findings present"
    return True, "gate passed"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fail-on-high", action="store_true")
    parser.add_argument("--fail-on-critical", action="store_true")
    args = parser.parse_args()

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    gate_cfg = config.get("gates", {})
    fail_on_high = args.fail_on_high or bool(gate_cfg.get("fail_on_high", False))
    fail_on_critical = args.fail_on_critical or bool(gate_cfg.get("fail_on_critical", True))

    reports = load_stage_reports()
    summary = summarize_findings(reports)
    passed, reason = gate_decision(summary, fail_on_high, fail_on_critical)

    result = {
        "report_count": len(reports),
        "severity_summary": dict(summary),
        "gate": {"passed": passed, "reason": reason},
    }

    out_path = REPORTS_DIR / "aggregate.json"
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))

    raise SystemExit(0 if passed else 1)
