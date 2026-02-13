from __future__ import annotations

from security.scanner import (
    test_auth_required_endpoint,
    test_directory_traversal,
    test_open_redirect,
    test_rate_limit,
    test_security_headers,
    test_sql_injection,
    test_xss,
)


def run_security_tests(targets: dict) -> list[dict]:
    """Iterate discovered targets and run all security tests."""

    endpoints = targets.get("endpoints", [])
    pages = targets.get("pages", [])
    params = targets.get("params", [])

    scan_targets = sorted(set(endpoints + pages))
    findings: list[dict] = []

    for url in scan_targets:
        findings.extend(test_sql_injection(url, params))
        findings.extend(test_xss(url, params))
        findings.extend(test_open_redirect(url, params))
        findings.extend(test_security_headers(url))
        findings.extend(test_directory_traversal(url, params))
        findings.extend(test_auth_required_endpoint(url))
        findings.extend(test_rate_limit(url))

    return findings
