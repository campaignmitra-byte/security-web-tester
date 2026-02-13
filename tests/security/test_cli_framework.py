from __future__ import annotations

import json
from pathlib import Path

import pytest


class DummyResponse:
    def __init__(self, text: str, status_code: int = 200, headers: dict | None = None, url: str = ""):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.url = url


class DummySession:
    def __init__(self, fixtures: dict[str, DummyResponse]):
        self.fixtures = fixtures

    def get(self, url: str, timeout: int = 10):
        return self.fixtures[url]


def test_discover_targets_internal_links_and_depth(monkeypatch):
    pytest.importorskip("requests")
    pytest.importorskip("bs4")

    from security.crawler import discover_targets

    fixtures = {
        "https://example.com": DummyResponse(
            '<a href="/a?x=1">A</a><a href="https://external.com/out">ext</a><form action="/login" method="post"><input name="username"/></form>'
        ),
        "https://example.com/a": DummyResponse('<a href="/b">B</a>'),
        "https://example.com/b": DummyResponse('<a href="/c">C</a>'),
    }

    import requests

    monkeypatch.setattr(requests, "Session", lambda: DummySession(fixtures))
    targets = discover_targets("https://example.com")

    assert "https://example.com" in targets["pages"]
    assert "https://example.com/a" in targets["pages"]
    assert "https://example.com/b" in targets["pages"]
    assert "https://example.com/c" not in targets["pages"]  # depth limit 2
    assert "username" in targets["params"]
    assert "x" in targets["params"]
    assert any(f["action"] == "https://example.com/login" for f in targets["forms"])


def test_generate_report_counts(tmp_path: Path):
    from security.report import generate_report

    issues = [
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "low"},
    ]
    out = tmp_path / "security-report.json"
    report = generate_report("https://example.com", issues, str(out))
    assert report["summary"] == {"high": 1, "medium": 1, "low": 2}
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["target"] == "https://example.com"


def test_run_security_tests_with_stubbed_scanner(monkeypatch):
    pytest.importorskip("requests")

    import security.executor as executor

    monkeypatch.setattr(executor, "test_sql_injection", lambda u, p: [{"severity": "high", "url": u, "test": "sql", "evidence": "x"}])
    monkeypatch.setattr(executor, "test_xss", lambda u, p: [])
    monkeypatch.setattr(executor, "test_open_redirect", lambda u, p: [])
    monkeypatch.setattr(executor, "test_security_headers", lambda u: [])
    monkeypatch.setattr(executor, "test_directory_traversal", lambda u, p: [])
    monkeypatch.setattr(executor, "test_auth_required_endpoint", lambda u: [])
    monkeypatch.setattr(executor, "test_rate_limit", lambda u: [])

    findings = executor.run_security_tests({"endpoints": ["https://example.com/api"], "pages": [], "params": ["id"]})
    assert len(findings) == 1
    assert findings[0]["test"] == "sql"
