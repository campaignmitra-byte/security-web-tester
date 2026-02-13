# Security Web Tester (Python)

A Python-only starter project to proactively test application security before deployment.

## What this gives you

- Python runners for SAST, SCA, DAST, and API fuzzing stages.
- Aggregated security gate report with pass/fail thresholds.
- A broad attack taxonomy and machine-checkable coverage mapping.
- CI workflow that blocks deployment on high/critical findings and coverage gaps.

## Important reality check

No tool can promise protection from **every possible attack**. This project enforces a strong baseline and makes blind spots visible, but you must continuously extend tests for your business logic and architecture changes.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m security.runners.run_sast
python -m security.runners.run_sca
python -m security.runners.run_dast
python -m security.runners.run_api_fuzz
python -m security.coverage --require-full
python -m security.aggregate_report --fail-on-high --fail-on-critical
```

Reports are written to `security/reports/*.json`.

## Key files

- `security/attack_taxonomy.py`: baseline attack classes.
- `security/test-catalog.json`: test mapping for each attack class.
- `security/coverage.py`: fails when taxonomy coverage is incomplete.
- `security/config.json`: stage commands and gate settings.
