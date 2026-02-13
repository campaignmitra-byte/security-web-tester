# Python CLI Website Security Scanner (High-Level Framework)

This repository now includes a **high-level, extensible CLI framework** to crawl a website, discover attack surface, run automated web security tests, and produce a structured JSON report.

## CLI Usage

```bash
python -m security.scan https://example.com
```

## Required Project Structure

The scanner is implemented exactly with the requested structure:

- `security/crawler.py`
- `security/scanner.py`
- `security/executor.py`
- `security/report.py`
- `security/scan.py` (CLI entrypoint)

## End-to-End Flow

`scan.py` executes this pipeline:

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

`security/scanner.py` implements these automated checks as functions:

- `test_sql_injection(url, params)`
- `test_xss(url, params)`
- `test_open_redirect(url, params)`
- `test_security_headers(url)`
- `test_directory_traversal(url, params)`
- `test_auth_required_endpoint(url)`
- `test_rate_limit(url)`

Each function returns structured issues (test name, severity, url, evidence).

## Executor and Reporting

- `run_security_tests(targets)` in `executor.py` runs all tests across discovered pages/endpoints.
- `generate_report(...)` in `report.py` writes `security-report.json` with format:

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
pip install requests beautifulsoup4 pytest
```

## High-Level Framework Extension Guide

Use this design as a framework, not a one-off script:

1. **Add tests in `scanner.py`**
   - Create new `test_*` functions that accept URL/params and return issue dictionaries.
2. **Register tests in `executor.py`**
   - Add your new test function call in `run_security_tests`.
3. **Keep severities consistent**
   - Use `high`, `medium`, `low` for report compatibility.
4. **Refine discovery**
   - Extend `crawler.py` heuristics for API docs, JS-routed paths, sitemap.xml, robots.txt parsing.
5. **Automate in CI**
   - Run `python -m security.scan <staging-url>` and archive `security-report.json`.

## Notes

- This scanner is a practical baseline for automated checks from multiple attacker viewpoints.
- No scanner can guarantee detection of every future/unknown exploit; keep expanding test logic based on architecture changes and threat intel.
