# Python CLI Website Security Scanner (High-Level Framework)

This repository includes a **high-level, extensible CLI framework** to crawl a website, discover attack surface, run automated web security tests, and produce a structured JSON report.

## CLI Usage

```bash
python -m security.scan https://example.com
```

You can also pass a bare domain (scheme will be auto-added):

```bash
python -m security.scan example.com
```

## Required Project Structure

- `security/crawler.py`
- `security/scanner.py`
- `security/executor.py`
- `security/report.py`
- `security/scan.py` (CLI entrypoint)

## End-to-End Flow

`scan.py` executes:

1. URL input
2. Crawl site
3. Discover endpoints
4. Run security tests
5. Save report
6. Print summary

## What the Crawler Discovers

`discover_targets(base_url) -> dict` returns:

```json
{
  "pages": [],
  "forms": [],
  "params": [],
  "endpoints": []
}
```

Crawler behavior:

- Uses `requests` + `BeautifulSoup`
- Follows **internal links only**
- Extracts pages, forms, URLs, and query parameters
- Prevents infinite loops via visited URL tracking
- Limits crawl depth to `2`

## Security Tests Included

`security/scanner.py` implements:

- `test_sql_injection(url, params)`
- `test_xss(url, params)`
- `test_open_redirect(url, params)`
- `test_security_headers(url)`
- `test_directory_traversal(url, params)`
- `test_auth_required_endpoint(url)`
- `test_rate_limit(url)`

Each test returns structured issues.

## Executor and Reporting

- `run_security_tests(targets)` in `executor.py` runs all tests across discovered pages/endpoints.
- `generate_report(...)` in `report.py` writes `security-report.json`:

```json
{
  "target": "",
  "issues": [],
  "summary": {
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

## Installation

Python 3.10+ is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Troubleshooting

- `python -m security.scan <url>` causes shell error because `<url>` is a placeholder. Use a real value.
  - ✅ `python -m security.scan https://example.com`
- `No module named security.scan` usually means you are not running from the project root or package is not installed in the active venv.
  - Run from repo root and/or: `python -m pip install -e .`
- Missing dependency message (`requests`, `bs4`):
  - `python -m pip install requests beautifulsoup4`

## High-Level Framework Extension Guide

1. Add new `test_*` functions in `scanner.py`.
2. Register them in `executor.py` within `run_security_tests`.
3. Keep severity values normalized (`high`, `medium`, `low`).
4. Extend `crawler.py` discovery heuristics as needed.
5. Run scanner in CI on staging and archive `security-report.json`.

## Notes

- This scanner is a practical baseline from multiple attacker viewpoints.
- No scanner guarantees all future unknown exploits; evolve tests with architecture and threat intel changes.
