# Security Documentation

Start here when changing or reviewing APAS Defensible GraphRAG security.

## Documents

### [Security Prompt](../../SECURITY_PROMPT.md)

Operational instructions for coding agents and reviewers. Defines the project's non-negotiable rules, trust boundaries, database/retrieval/model constraints, and required security tests.

### [Security Invariants](SECURITY_INVARIANTS.md)

Properties that must remain true regardless of implementation details, storage adapters, frameworks, or model providers.

### [Threat Model](THREAT_MODEL.md)

Adversaries, protected assets, attack paths, required defenses, explicit limitations, and measurable security targets.

### [Change Review Checklist](CHANGE_REVIEW_CHECKLIST.md)

Checklist to use before merging security-sensitive changes.

### [Project Security Policy](../../SECURITY.md)

High-level security philosophy, sensitive asset definitions, vulnerability classes, secret-handling rules, and reporting expectations.

### [Red-Team Contract](../../RED_TEAM.md)

Repository-specific adversarial scenarios and expected behavior.

---

## Security doctrine

The architecture follows four core ideas:

1. **The LLM is untrusted.**
2. **Authorization happens before retrieval/release.**
3. **Every released material claim must be traceable to authorized evidence.**
4. **When evidence or authorization is uncertain, fail closed.**

---

## Required review areas

Any change touching one of these areas should be treated as security-sensitive:

- OIDC/JWT authentication
- membership resolution
- RBAC/ABAC
- capability tokens
- PostgreSQL roles/RLS
- connection pooling/security context
- pgvector retrieval
- RDF/graph queries
- bitemporal logic
- provenance
- evidence packages/signing
- audit ledger
- ingestion/parsers
- prompt injection controls
- claim verification
- conflict resolution
- human review
- public error behavior and metadata leakage

Use the change-review checklist before merging.
