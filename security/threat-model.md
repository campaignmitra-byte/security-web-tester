# Threat Model Template

## Assets
- User data / PII
- Access/refresh tokens and session cookies
- Admin-only APIs and control-plane actions
- Service credentials, signing keys, CI/CD secrets

## Entry points
- Browser UI and public web routes
- REST/GraphQL APIs
- File upload/processing endpoints
- Webhooks, callback URLs, background workers
- Admin panels and support tooling

## Trust boundaries
- Browser -> API gateway
- API -> database/cache/queue
- API -> internal microservices
- API -> third-party providers
- CI/CD -> artifact registry/runtime cluster

## Abuse cases to explicitly model
- Horizontal/vertical privilege escalation
- Business workflow abuse (coupon/payment/refund/order race)
- Multi-tenant isolation bypass
- Secret exfiltration from logs/errors
- SSRF pivot to internal metadata/control planes

## Threat-model output requirements
1. List all internet-exposed endpoints.
2. Map each endpoint to attack classes in `security/attack_taxonomy.py`.
3. Link each mapped attack class to a test in `security/test-catalog.json`.
4. Mark release blockers and owners.
