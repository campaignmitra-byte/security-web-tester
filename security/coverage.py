from __future__ import annotations

import argparse
import json
from pathlib import Path

from security.attack_taxonomy import taxonomy_ids

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "security" / "test-catalog.json"
REPORTS_DIR = ROOT / "security" / "reports"


def load_catalog() -> list[dict]:
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def coverage_summary(catalog: list[dict]) -> dict:
    mapped = {item["attack_id"] for item in catalog}
    known = taxonomy_ids()
    unknown = sorted(mapped - known)
    missing = sorted(known - mapped)
    return {
        "total_attack_classes": len(known),
        "covered_attack_classes": len(mapped & known),
        "coverage_percent": round((len(mapped & known) / len(known)) * 100, 2) if known else 0.0,
        "unknown_attack_ids": unknown,
        "missing_attack_ids": missing,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-full", action="store_true", help="Exit non-zero unless all taxonomy IDs are mapped")
    args = parser.parse_args()

    summary = coverage_summary(load_catalog())
    out = REPORTS_DIR / "coverage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))

    has_gap = bool(summary["unknown_attack_ids"] or summary["missing_attack_ids"])
    raise SystemExit(1 if (args.require_full and has_gap) else 0)
