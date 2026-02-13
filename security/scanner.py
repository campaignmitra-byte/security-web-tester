from __future__ import annotations

from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

TIMEOUT_SECONDS = 10

SQL_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<script>alert('xss')</script>"
TRAVERSAL_PAYLOAD = "../../../../etc/passwd"
REDIRECT_PAYLOAD = "https://evil.example.com"


def _build_param_map(params: list[str], payload: str) -> dict[str, str]:
    if not params:
        return {"q": payload}
    return {param: payload for param in params}


def _issue(name: str, severity: str, url: str, evidence: str) -> dict[str, Any]:
    return {
        "test": name,
        "severity": severity,
        "url": url,
        "evidence": evidence,
    }


def test_sql_injection(url: str, params: list[str]) -> list[dict]:
    import requests

    issues: list[dict] = []
    try:
        response = requests.get(url, params=_build_param_map(params, SQL_PAYLOAD), timeout=TIMEOUT_SECONDS)
        body = response.text.lower()
        sql_error_markers = [
            "sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "psql",
            "sqlite",
            "odbc",
        ]
        if any(marker in body for marker in sql_error_markers):
            issues.append(_issue("sql_injection", "high", response.url, "Database error signature detected"))
    except requests.RequestException as exc:
        issues.append(_issue("sql_injection", "low", url, f"Request failed: {exc}"))
    return issues


def test_xss(url: str, params: list[str]) -> list[dict]:
    import requests

    issues: list[dict] = []
    try:
        response = requests.get(url, params=_build_param_map(params, XSS_PAYLOAD), timeout=TIMEOUT_SECONDS)
        if XSS_PAYLOAD in response.text:
            issues.append(_issue("xss", "high", response.url, "Payload reflected in response"))
    except requests.RequestException as exc:
        issues.append(_issue("xss", "low", url, f"Request failed: {exc}"))
    return issues


def test_open_redirect(url: str, params: list[str]) -> list[dict]:
    import requests

    issues: list[dict] = []
    redirect_params = [p for p in params if p.lower() in {"next", "url", "redirect", "return", "return_to"}]
    if not redirect_params:
        redirect_params = ["next"]

    try:
        crafted = {name: REDIRECT_PAYLOAD for name in redirect_params}
        response = requests.get(url, params=crafted, timeout=TIMEOUT_SECONDS, allow_redirects=False)
        location = response.headers.get("Location", "")
        if response.status_code in {301, 302, 303, 307, 308} and "evil.example.com" in location:
            issues.append(_issue("open_redirect", "medium", response.url, f"Redirected to external location: {location}"))
    except requests.RequestException as exc:
        issues.append(_issue("open_redirect", "low", url, f"Request failed: {exc}"))
    return issues


def test_security_headers(url: str) -> list[dict]:
    import requests

    issues: list[dict] = []
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
    ]

    try:
        response = requests.get(url, timeout=TIMEOUT_SECONDS)
        for header in required_headers:
            if header not in response.headers:
                issues.append(_issue("security_headers", "medium", url, f"Missing header: {header}"))
    except requests.RequestException as exc:
        issues.append(_issue("security_headers", "low", url, f"Request failed: {exc}"))

    return issues


def test_directory_traversal(url: str, params: list[str]) -> list[dict]:
    import requests

    issues: list[dict] = []
    candidate_params = [p for p in params if any(t in p.lower() for t in ["file", "path", "dir", "folder", "template"])]
    if not candidate_params:
        candidate_params = ["file"]

    try:
        response = requests.get(url, params={p: TRAVERSAL_PAYLOAD for p in candidate_params}, timeout=TIMEOUT_SECONDS)
        if "root:x:" in response.text or "[boot loader]" in response.text.lower():
            issues.append(_issue("directory_traversal", "high", response.url, "Sensitive file content signature detected"))
    except requests.RequestException as exc:
        issues.append(_issue("directory_traversal", "low", url, f"Request failed: {exc}"))

    return issues


def test_auth_required_endpoint(url: str) -> list[dict]:
    import requests

    issues: list[dict] = []
    try:
        response = requests.get(url, timeout=TIMEOUT_SECONDS, allow_redirects=False)
        parsed = urlparse(url)
        path = parsed.path.lower()
        likely_protected = any(segment in path for segment in ["admin", "account", "profile", "settings", "billing", "dashboard"])
        if likely_protected and response.status_code == 200:
            issues.append(_issue("auth_required_endpoint", "high", url, "Potentially sensitive path accessible without auth"))
    except requests.RequestException as exc:
        issues.append(_issue("auth_required_endpoint", "low", url, f"Request failed: {exc}"))
    return issues


def test_rate_limit(url: str) -> list[dict]:
    import requests

    issues: list[dict] = []
    status_codes = []
    try:
        for _ in range(12):
            response = requests.get(url, timeout=TIMEOUT_SECONDS)
            status_codes.append(response.status_code)

        if 429 not in status_codes:
            issues.append(_issue("rate_limit", "medium", url, "No HTTP 429 observed during burst requests"))
    except requests.RequestException as exc:
        issues.append(_issue("rate_limit", "low", url, f"Request failed: {exc}"))

    return issues


def normalize_url(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = urlencode(params)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
