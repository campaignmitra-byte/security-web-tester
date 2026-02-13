from __future__ import annotations

import argparse
import sys

from security.crawler import discover_targets
from security.executor import run_security_tests
from security.report import generate_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CLI website security scanner")
    parser.add_argument("url", help="Target base URL, e.g. https://example.com")
    args = parser.parse_args(argv)

    target = args.url

    print(f"[1/5] Crawling target: {target}")
    targets = discover_targets(target)

    print("[2/5] Discovery complete")
    print(f"  pages={len(targets['pages'])}, forms={len(targets['forms'])}, params={len(targets['params'])}, endpoints={len(targets['endpoints'])}")

    print("[3/5] Running security tests")
    issues = run_security_tests(targets)

    print("[4/5] Saving report")
    report = generate_report(target, issues, output_path="security-report.json")

    print("[5/5] Summary")
    summary = report["summary"]
    print(f"  high={summary['high']} medium={summary['medium']} low={summary['low']}")
    print("  report=security-report.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
