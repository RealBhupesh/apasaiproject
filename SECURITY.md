# Security Policy

## Security philosophy

APAS Defensible GraphRAG is built around a zero-trust principle:

> **Identity, authorization, evidence, and release decisions are enforced outside the LLM.**

The project is a reference implementation and security research/demo system. It should not be treated as a legal compliance product without independent security review, infrastructure hardening, and domain validation.

## Protected assets

The architecture treats the following as sensitive assets:

- tenant data
- regulated documents
- embeddings
- graph relations
- document and chunk metadata
- provenance
- model execution manifests
- capability tokens
- security policies
- audit events
- human-review cases
- evidence packages
- signing keys and secrets

## Security boundaries

Production security is expected to rely on:

- verified OIDC identity
- server-side membership lookup
- RBAC + ABAC
- PostgreSQL RLS
- scoped capability verification
- tenant/classification/jurisdiction-aware retrieval
- bitemporal filtering
- deterministic claim verification
- protected provenance
- append-only audit
- signed evidence packages

Demo-mode identities and in-memory repositories are not production authentication or authorization.

## Vulnerability classes of highest concern

Report or block changes that could cause:

- cross-tenant data access
- classification bypass
- jurisdiction bypass
- SQL/SPARQL injection
- arbitrary tool execution
- capability forgery/replay/scope bypass
- prompt injection crossing the trust boundary
- forged evidence/citation acceptance
- unauthorized provenance disclosure
- audit-history mutation
- signing-key exposure
- unsafe file ingestion
- production fallback to demo security

## Secure-development rule

For security-sensitive changes:

1. create or identify the abuse case;
2. write a failing regression test;
3. implement the smallest safe fix;
4. run unit, integration, adversarial, and live PostgreSQL tests where relevant;
5. update security documentation if the trust boundary changes.

Never delete or weaken a valid security test solely to make CI pass.

## Secrets

Never commit:

- private keys
- production database passwords
- bearer tokens
- API keys
- real customer credentials
- KMS secrets
- real JWT signing material

Use environment/configuration injection and a production secret manager.

## Security contact

For this repository, report suspected vulnerabilities privately to the repository owner before publicly documenting exploitable details.
