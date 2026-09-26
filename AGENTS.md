# Agent Instructions

Before modifying this repository, read:

1. `SECURITY_PROMPT.md`
2. `docs/security/SECURITY_INVARIANTS.md`
3. `docs/security/THREAT_MODEL.md`
4. `docs/security/CHANGE_REVIEW_CHECKLIST.md`

## Priority

Security invariants take precedence over convenience, framework defaults, model behavior, and feature velocity.

For changes involving authentication, authorization, RLS, SQL, pgvector, graph access, capabilities, ingestion, provenance, audit, evidence signing, claim verification, or human review:

- identify the relevant threat;
- preserve the documented invariant;
- add a regression test;
- fail closed;
- never weaken an existing security test to make the build pass.

## Core rule

> The LLM is the least-trusted component.

Do not give model-generated content authority over identity, authorization, tools, database execution, tenant scope, security classification, policy, evidence validity, or final release decisions.

If the requested implementation conflicts with a security invariant, preserve the invariant and explain the conflict.
