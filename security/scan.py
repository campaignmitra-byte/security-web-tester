from __future__ import annotations

import argparse
import importlib
import sys
from urllib.parse import urlparse

from security.crawler import discover_targets
from security.executor import run_security_tests
from security.report import generate_report


def normalize_target_url(target: str) -> str:
    """Normalize user-provided target URL.

    Accepts hostnames like `example.com` and upgrades them to `https://example.com`.
    """

    parsed = urlparse(target)
    if parsed.scheme:
        return target
    return f"https://{target}"


def _check_dependencies() -> list[str]:
    missing: list[str] = []
    for module_name in ("requests", "bs4"):
        try:
            importlib.import_module(module_name)
        except ModuleNotFoundError:
            missing.append(module_name)
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CLI website security scanner")
    parser.add_argument("url", help="Target base URL, e.g. https://example.com")
    args = parser.parse_args(argv)

    missing = _check_dependencies()
    if missing:
        print(
            "Missing required dependencies: "
            + ", ".join(missing)
            + "\nInstall them with: pip install requests beautifulsoup4",
            file=sys.stderr,
        )
        return 2

    target = normalize_target_url(args.url)

    try:
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
    except Exception as exc:  # defensive CLI boundary
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
