# Security Invariants

These are properties the system should preserve regardless of framework, storage adapter, model provider, or UI.

## Identity

- A request cannot choose its own effective tenant.
- A JWT cannot promote its own role, clearance, or jurisdiction.
- Production authorization attributes come from a trusted server-side authority.
- OIDC identity is scoped by issuer and subject.

## Database

- Runtime application identities cannot bypass RLS.
- Runtime application identities do not own protected tables or schemas.
- Tenant security context is transaction-local.
- A pooled connection must not carry a previous request's tenant context.
- Cross-tenant rows are never visible to protected runtime roles.

## Classification

- PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED.
- A caller cannot retrieve above its clearance.
- Derived values inherit the highest classification of their inputs.
- Metadata about unauthorized resources is also treated as protected.

## Jurisdiction

- Jurisdiction restrictions apply to document, vector, graph, provenance, and review data.
- Same-tenant does not imply same-jurisdiction access.

## Retrieval

- Security and temporal filters precede ranking.
- Unauthorized vectors are never candidates.
- Unauthorized rows must not influence counts, top-K, ranking position, or evidence construction.

## Graph

- Graph access follows the same tenant/classification/jurisdiction model as documents.
- No unrestricted model-generated SPARQL.
- Approved templates or validated query structures only.

## Capabilities

A capability is usable only when all relevant bindings match:

- authenticated subject
- tenant
- audience
- tool
- operation
- jurisdiction
- purpose
- classification ceiling
- expiry
- revocation state
- call budget
- delegation policy

Capability usage accounting must be atomic in production.

## Evidence and claims

- A claim can only cite evidence from its current authorized EvidenceSet.
- Fake or foreign evidence IDs fail closed.
- Numbers, units, dates, deadlines, and source references must be supported.
- Deterministic failures cannot be overridden by a model.
- Unsupported material claims are not released.

## Time

- Valid time answers what applied in the modeled world.
- Transaction time answers what the system knew/stored at that point.
- Corrections create new historical state; they do not silently rewrite history.

## Conflicts

- Explicit precedence may resolve a conflict.
- Insufficient precedence returns ESCALATE.
- The generative model cannot decide legal precedence by intuition.

## Provenance

- Every released claim should be traceable to authorized evidence.
- Provenance access requires authorization.
- Hidden lineage cannot leak IDs, counts, titles, classifications, or source existence.

## Audit

- Production security/audit events are append-only.
- Historical mutation must be detectable.
- Tenant users must not receive platform-wide audit counts.
- Security logs must not contain raw secrets or bearer tokens.

## LLM boundary

- Model output is untrusted.
- Retrieved content is untrusted.
- Prompts are not authorization.
- The model receives no raw production database credentials.
- The model receives narrow tools, not unrestricted execution.

## Failure mode

When security infrastructure is missing or uncertain:

> **Fail closed.**

Production mode must never silently fall back to demo security.
