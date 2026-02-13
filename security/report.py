from __future__ import annotations

import json
from pathlib import Path


def _severity_summary(issues: list[dict]) -> dict:
    summary = {"high": 0, "medium": 0, "low": 0}
    for issue in issues:
        sev = issue.get("severity", "").lower()
        if sev in summary:
            summary[sev] += 1
    return summary


def generate_report(target: str, issues: list[dict], output_path: str = "security-report.json") -> dict:
    report = {
        "target": target,
        "issues": issues,
        "summary": _severity_summary(issues),
    }

    Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
