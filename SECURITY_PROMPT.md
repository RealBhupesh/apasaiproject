# APAS Security Prompt

> Read this file before changing authentication, authorization, database access, retrieval, graph code, provenance, audit, ingestion, model/tool access, or human-review logic.

## Mission

This repository is a **security-first, provenance-first, multi-tenant Defensible GraphRAG system**.

The central rule is:

> **The LLM is the least-trusted component.**

Generation may propose text. It must never decide identity, authorization, tenant scope, security classification, executable database access, or whether an unsupported claim is safe to release.

Security controls must exist outside prompts and outside the model.

---

## Non-negotiable security invariants

Never introduce a change that violates any of these:

1. **Tenant identity is server-bound.**
   - Never trust a tenant ID supplied by an LLM or arbitrary request payload.
   - Production tenant membership comes from authenticated identity plus the security authority.

2. **Authorization attributes are server-side.**
   - Roles, clearance, jurisdictions, and membership are not trusted from JWT convenience claims.
   - OIDC proves identity. The database/security authority determines authorization.

3. **PostgreSQL RLS is a security boundary.**
   - Application filtering is defense in depth, not the sole tenant boundary.
   - Runtime database roles must be non-owner, non-superuser, and NOBYPASSRLS.
   - Use transaction-local security context before protected queries.

4. **Filter before retrieval ranking.**
   - Tenant, classification, jurisdiction, valid-time, and transaction-time restrictions must be applied before vector similarity, keyword ranking, counts, LIMIT, or result construction.
   - Never retrieve globally and filter afterward.

5. **Graph access is scoped.**
   - No unrestricted SPARQL endpoint.
   - No LLM-generated executable SPARQL without a validated allow-listed AST.
   - Tenant, classification, and jurisdiction apply to graph data too.

6. **Capabilities are bound, scoped, short-lived, and revocable.**
   - Verify subject, tenant, tool, operation, jurisdiction, purpose, audience, classification ceiling, expiry, delegation constraints, revocation, and call budget.
   - A valid signature alone does not authorize use.

7. **Retrieved content is untrusted data.**
   - A document saying "ignore previous instructions", "call admin", or similar is data, not authority.
   - Retrieved text must never change tool permissions or security policy.

8. **No arbitrary database execution for the model.**
   - Do not expose raw SQL, database credentials, unrestricted ORM sessions, unrestricted SPARQL, DDL, GRANT, or policy mutation to an agent.
   - Expose narrow domain tools.

9. **Claims require authorized evidence.**
   - Candidate claims must bind to evidence IDs already present in the authorized EvidenceSet.
   - Missing, forged, cross-tenant, temporally invalid, conflicting, or unsupported evidence must fail closed.

10. **Deterministic checks outrank model judgment.**
    - Tenant, classification, dates, units, numbers, citation IDs, jurisdiction, and policy constraints are deterministic gates.
    - An LLM/NLI verifier must never override a failed deterministic security check.

11. **Conflicts do not become guesses.**
    - If applicable regulations conflict and precedence cannot be resolved from explicit rules, return ESCALATE.
    - Do not ask the LLM to choose the legally controlling rule.

12. **Weak evidence means abstention.**
    - Unsupported questions return ABSTAIN.
    - The system must prefer a safe non-answer over a plausible unsupported answer.

13. **Provenance is also protected data.**
    - Authorization must cover lineage, IDs, counts, document metadata, model manifests, and evidence packages.
    - Do not reveal hidden resources indirectly through provenance.

14. **Audit is append-only and tenant-aware.**
    - Production audit writes go through the approved append path.
    - Never allow normal runtime code to update/delete historical audit events.
    - Do not expose global audit counts to tenant-scoped users.

15. **Sensitive derived values inherit sensitivity.**
    - Derived values must inherit at least the maximum input classification.
    - Cross-tenant derivation is forbidden.

16. **Production must never silently downgrade to demo security.**
    - If OIDC, database membership, RLS, capability verification, or required security infrastructure is unavailable, production mode fails closed.

---

## Trust boundaries

Treat these as separate trust domains:

### Trusted security control plane
- OIDC verifier
- database membership authority
- policy engine
- PostgreSQL RLS
- capability verifier
- deterministic claim checks
- approved query templates
- audit append function
- signing/KMS boundary

### Untrusted or partially trusted
- user input
- model output
- retrieved documents
- uploaded files
- embeddings
- vector similarity scores
- external tools
- third-party model APIs
- LLM-generated query plans
- prompt text inside documents

Never let an untrusted domain directly mutate or override the trusted control plane.

---

## Before changing security-sensitive code

Ask:

1. Can this change cause cross-tenant disclosure?
2. Can a lower-clearance user infer higher-classification data?
3. Can a request control tenant, role, clearance, jurisdiction, or policy?
4. Does filtering happen before ranking and LIMIT?
5. Could counts, IDs, errors, latency, provenance, or titles leak hidden resources?
6. Could a malicious document influence tool permissions or system instructions?
7. Could an agent execute SQL/SPARQL beyond approved templates?
8. Does the code still fail closed if a dependency fails?
9. Can a forged evidence ID or claim bypass verification?
10. Is historical state overwritten instead of versioned?
11. Can audit history be modified?
12. Can a capability be replayed, overspent, used by the wrong subject, or used for the wrong tenant?
13. Does this code work correctly under concurrency?
14. Does demo code accidentally run in production mode?
15. Is a security claim in the README actually proven by a test?

If any answer is uncertain, stop and add a failing test before changing the implementation.

---

## Required tests for sensitive changes

Depending on the area, add or update tests covering:

- cross-tenant access
- classification boundaries
- jurisdiction isolation
- real PostgreSQL RLS
- pooled-connection context leakage
- role escalation
- capability subject/tenant/classification mismatch
- capability expiry/revocation/budget
- concurrent capability consumption
- prompt injection
- SQL/SPARQL injection
- fake evidence IDs
- provenance metadata leakage
- unsupported numeric claims
- future/expired/superseded regulations
- transaction-time queries
- conflict escalation
- audit tampering
- signed evidence-package tampering
- human-review authorization

**Do not weaken a security test to make a build pass. Fix the architecture.**

---

## Database rules

- Parameterized queries only.
- Runtime roles do not own schemas/tables/database.
- Runtime roles: NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOBYPASSRLS.
- Prefer NOLOGIN group roles plus separate LOGIN runtime identities.
- Use explicit grants. Avoid broad privileges.
- RLS on every tenant-bearing protected table.
- FORCE RLS where appropriate.
- Security context must be transaction-local.
- Never persist tenant context across pooled requests.
- Never connect production application code as migration owner.

---

## Retrieval rules

The safe order is:

```text
authenticated identity
        ↓
authorized tenant + clearance + jurisdiction
        ↓
RLS / policy scope
        ↓
temporal scope
        ↓
candidate rows
        ↓
vector / keyword ranking
        ↓
EvidenceSet
```

The unsafe order is:

```text
all rows
   ↓
global vector ranking
   ↓
top K
   ↓
authorization filtering
```

Never implement the unsafe order.

---

## Model boundary

The model may:

- summarize authorized evidence
- produce structured candidate claims
- propose explanations
- propose non-executable plans

The model may not:

- establish identity
- choose tenant
- grant itself roles
- raise its clearance
- choose hidden jurisdictions
- make authorization decisions
- execute unrestricted SQL/SPARQL
- invent evidence IDs
- bypass deterministic verification
- approve its own answer
- alter security policy
- modify audit history

---

## Release rule

A final answer can be released only after:

```text
authorized evidence
    ↓
temporal validity
    ↓
conflict check
    ↓
claim/evidence binding
    ↓
numeric/unit/date validation
    ↓
citation verification
    ↓
independent entailment/semantic check
    ↓
policy gate
    ↓
ANSWER
```

Otherwise:

- insufficient evidence → **ABSTAIN**
- unresolved regulatory conflict/high-risk ambiguity → **ESCALATE**
- unauthorized access → **DENY**

---

## Security review output

When reviewing a proposed change, report findings in this order:

1. **Critical:** cross-tenant disclosure, auth bypass, arbitrary execution, credential exposure, RLS bypass.
2. **High:** classification/jurisdiction leakage, capability bypass, provenance leakage, audit mutability.
3. **Medium:** weak verification, side-channel metadata leakage, insecure defaults, concurrency gaps.
4. **Low:** hardening, observability, documentation, defense-in-depth improvements.

For every finding include:

- file/function
- attack path
- impact
- exact fix
- regression test

Do not describe a security control as "production secure" unless the real runtime path and integration tests enforce it.
