# Security Test Catalog (Comprehensive Baseline)

This project now tracks a broader baseline attack taxonomy in `security/attack_taxonomy.py` and maps tests in `security/test-catalog.json`.

## Coverage policy

- Every `attack_id` in the taxonomy must have at least one mapped test case in `security/test-catalog.json`.
- CI runs `python -m security.coverage --require-full` to fail if any taxonomy entry is unmapped.
- Each mapped attack should include:
  - at least one automated test (unit/integration/DAST/fuzz), and
  - one adversarial manual test scenario for business logic abuse.

## Scope included in baseline

- Access control (IDOR/BFLA/mass assignment/privilege escalation)
- Authentication/session abuse (token tampering, replay, MFA bypass, brute force)
- Injection families (SQL/NoSQL/command/SSTI/LDAP/XPath/CRLF)
- Browser attacks (reflected/stored/DOM XSS, CSRF, clickjacking)
- File/parser abuse (path traversal, unsafe upload, deserialization, XXE)
- Server-side attack surface (SSRF, CORS, request smuggling, host-header abuse)
- Crypto/data exposure (weak crypto, secret leakage, TLS/config)
- Availability and abuse (rate-limit bypass, race conditions, app-layer DoS)
- Supply chain / operational risk (vulnerable deps, CI/CD poisoning)

> Note: No checklist can guarantee coverage of **every** possible future attack. Keep the taxonomy updated as your architecture changes.
