"""Canonical attack taxonomy used to track security test coverage.

This does not claim "all attacks ever", but provides a broad baseline across
web, API, auth, cloud/runtime, and abuse scenarios.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackClass:
    id: str
    category: str
    name: str
    description: str


ATTACK_TAXONOMY: tuple[AttackClass, ...] = (
    # Access control / identity
    AttackClass("AC-01", "access-control", "Broken object level authorization (IDOR)", "Accessing objects across tenant/user boundaries."),
    AttackClass("AC-02", "access-control", "Broken function level authorization", "Calling privileged endpoints as low-privilege user."),
    AttackClass("AC-03", "access-control", "Mass assignment", "Overposting hidden/protected fields in payloads."),
    AttackClass("AC-04", "access-control", "Privilege escalation", "Escalating from user to admin/system roles."),
    # Authentication / sessions
    AttackClass("AU-01", "authentication", "Credential stuffing", "Automated login attempts with breached credentials."),
    AttackClass("AU-02", "authentication", "Brute force", "Password/PIN guessing at auth endpoints."),
    AttackClass("AU-03", "authentication", "Session fixation", "Forcing predictable/predefined session IDs."),
    AttackClass("AU-04", "authentication", "Session replay", "Reusing stolen tokens/cookies."),
    AttackClass("AU-05", "authentication", "JWT/token tampering", "Manipulating algorithm, claims, signature, expiry, audience."),
    AttackClass("AU-06", "authentication", "MFA bypass", "Bypassing/abusing second-factor flow."),
    # Injection family
    AttackClass("IN-01", "injection", "SQL injection", "Injecting SQL via parameters, headers, or JSON bodies."),
    AttackClass("IN-02", "injection", "NoSQL injection", "Injecting query operators or JSON conditions."),
    AttackClass("IN-03", "injection", "Command injection", "Executing shell/system commands through unsanitized input."),
    AttackClass("IN-04", "injection", "Server-side template injection", "Injecting template expressions for code execution."),
    AttackClass("IN-05", "injection", "LDAP/XPath injection", "Injecting directory/query expressions."),
    AttackClass("IN-06", "injection", "CRLF/header injection", "Injecting response headers or splitting responses."),
    # XSS / browser-side
    AttackClass("XS-01", "client-side", "Reflected XSS", "Script injection reflected from request to response."),
    AttackClass("XS-02", "client-side", "Stored XSS", "Persistent script payloads rendered to users."),
    AttackClass("XS-03", "client-side", "DOM XSS", "Client-side sink misuse in JavaScript."),
    AttackClass("XS-04", "client-side", "CSRF", "Cross-site requests exploiting ambient auth."),
    AttackClass("XS-05", "client-side", "Clickjacking", "UI redressing using iframes and missing frame controls."),
    # File / deserialization
    AttackClass("FD-01", "file-handling", "Path traversal", "Reading/writing files outside allowed paths."),
    AttackClass("FD-02", "file-handling", "Unsafe file upload", "Uploading executable or polyglot payloads."),
    AttackClass("FD-03", "file-handling", "Insecure deserialization", "Triggering gadget chains / object abuse."),
    AttackClass("FD-04", "file-handling", "XXE", "XML external entity processing abuse."),
    # Server-side / network
    AttackClass("SV-01", "server-side", "SSRF", "Forcing server to fetch internal or metadata endpoints."),
    AttackClass("SV-02", "server-side", "Open redirect", "Abusing redirection for phishing/token theft."),
    AttackClass("SV-03", "server-side", "CORS misconfiguration", "Overly permissive origins/credentials."),
    AttackClass("SV-04", "server-side", "HTTP request smuggling", "Desyncing front-end/back-end parsers."),
    AttackClass("SV-05", "server-side", "Host header injection", "Abusing trust in Host/X-Forwarded headers."),
    # Cryptography / secrets / data exposure
    AttackClass("CR-01", "crypto-data", "Weak cryptography", "Deprecated algorithms, bad modes, short keys."),
    AttackClass("CR-02", "crypto-data", "Sensitive data exposure", "PII/secret leakage in responses/logs/errors."),
    AttackClass("CR-03", "crypto-data", "Secrets in source/control plane", "Hardcoded keys, tokens, credentials."),
    AttackClass("CR-04", "crypto-data", "TLS misconfiguration", "Weak ciphers/protocols or invalid certificate handling."),
    # Availability / abuse
    AttackClass("AV-01", "availability", "Rate-limit bypass", "Evading throttling with distributed identities/IPs."),
    AttackClass("AV-02", "availability", "Application-level DoS", "Expensive query/payload amplification abuse."),
    AttackClass("AV-03", "availability", "Race condition", "Winning concurrency window in critical operations."),
    # Supply chain / config / operations
    AttackClass("OP-01", "operations", "Vulnerable dependency", "Known CVEs in direct/transitive packages."),
    AttackClass("OP-02", "operations", "Security misconfiguration", "Debug mode, default creds, unsafe headers."),
    AttackClass("OP-03", "operations", "Insufficient logging/monitoring", "No audit trail for critical events."),
    AttackClass("OP-04", "operations", "CI/CD artifact poisoning", "Tampering build dependencies or release artifacts."),
)


def taxonomy_ids() -> set[str]:
    return {attack.id for attack in ATTACK_TAXONOMY}
