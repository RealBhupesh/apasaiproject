# APAS V4 — Defensible GraphRAG

A security-first, provenance-first reference implementation of a multi-tenant regulatory knowledge platform. **All bundled regulations are explicitly synthetic demo data and are not EPA, legal, or compliance advice.**

> The LLM is the least-trusted component. It receives an authorized `EvidenceSet`; it never receives database credentials, chooses tenant identity, makes access decisions, or turns unverified output directly into an official answer.

## What problem this solves

Conventional RAG optimizes retrieval relevance and treats security, time, lineage, and hallucination control as surrounding concerns. APAS V4 moves those concerns into the retrieval and answer path. A response is released only after tenant isolation, RBAC + ABAC, bitemporal resolution, conflict detection, claim verification, a policy gate, provenance capture, and audit chaining.

## Threat model

Protected against accidental or malicious cross-tenant retrieval, low-clearance access, manipulated tenant IDs, prompt injection in retrieved documents, unrestricted SQL/SPARQL, forged evidence IDs, citation spoofing, numeric hallucinations, outdated rules, expired capabilities, role escalation, metadata/count leakage, and historical audit modification. Denials are intentionally generic.

Out of scope for this reference build: compromised PostgreSQL superusers/hosts, side channels below the database layer, production IAM/SSO, KMS-backed signing, and full semantic NLI assurance.

## Architecture

```text
USER / AGENT
  -> Authentication (server-bound identity)
  -> Authorization Engine (RBAC + ABAC + capability)
  -> Policy Enforcement
       |-> PostgreSQL authority: RLS, classification, policies, decisions
       |-> Inspectable orchestrator
             -> allow-listed graph query
             -> tenant-first pgvector/keyword retrieval
             -> EvidenceSet
             -> bitemporal resolver
             -> conflict detector
             -> structured claim composer (untrusted)
             -> deterministic claim verifier
             -> policy gate: ANSWER / ABSTAIN / ESCALATE
             -> provenance graph
             -> tamper-evident audit ledger
```

Core workflow transitions are in `app/orchestration/workflow.py`, not hidden in an agent framework.

## Security design

### PostgreSQL authority and RLS

`app/db/migrations/001_v3.sql` defines `security`, `documents`, `knowledge`, `provenance`, and `audit` schemas. Tenant tables carry `tenant_id`, `created_at`, and `created_by`; protected content also carries classification, jurisdiction, and owner where applicable.

Every tenant-bearing table has `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`. Policies read transaction-local settings:

- `app.tenant_id`
- `app.user_id`
- `app.clearance`
- `app.role`
- `app.jurisdictions`
- `app.agent`
- `app.tool`
- `app.purpose`

`app/db/rls/context.py` sets these with parameterized `set_config(..., true)` after a transaction begins. Runtime roles are `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, and `NOBYPASSRLS`; none owns a schema or database. Application filtering is defense-in-depth, never the security boundary.

### RBAC versus ABAC

RBAC grants broad operations to `admin`, `security_admin`, `analyst`, `engineer`, `viewer`, `ai_agent`, `ingestion_worker`, and `auditor`. ABAC then evaluates tenant, clearance versus resource classification, jurisdiction, operation, agent/tool identity, and purpose. The centralized `PolicyEngine` emits an `AccessDecision` for every resource evaluation with policy/version attribution.

### Database separation of duties

| Role | Allowed | Explicitly not allowed |
|---|---|---|
| `apas_api_reader` | RLS-filtered reads of documents, vectors, graph, provenance | DDL, policy edits, audit deletion, cross-tenant bypass |
| `apas_api_writer` | Reserved for narrowly scoped application writes | Schema/security administration |
| `apas_graph_reader` | Inherits only reader access | Arbitrary graph mutation |
| `apas_ingestion_worker` | Insert/update document pipeline and relations under RLS | Security rules and audit history |
| `apas_audit_writer` | Append/read authorized audit events | Update/delete enforced by trigger |
| `apas_security_admin` | Security-table administration | Migration ownership and superuser access |
| `apas_migration_admin` | Deployment-time DDL only | Must never be used by API or model-facing tools |

Production should provision separate LOGIN identities and grant one or more NOLOGIN group roles. The migration intentionally contains no passwords.

### Agent capabilities

`Capability` scopes an agent to a tenant, allow-listed tools, operations, maximum classification, and expiration. `secure_regulatory_search`/retrieval and graph operations are mediated APIs. No arbitrary SQL endpoint exists. `SecureGraphRepository.execute_sparql()` fails closed; production SPARQL should use parsed AST allow-lists, time/row limits, and fixed named-graph scope.

## Data and retrieval

### Document separation

Raw authoritative object URIs and hashes live in `source_documents`; immutable versions live in `document_versions`; parsed passages in `chunks`; model-specific vectors in `embeddings`; explicit domain edges in `knowledge.relations`. Vectors reference secured chunks and are never the source of truth.

### Bitemporal model

- **Valid time:** `effective_from` / `effective_to` — when a rule applies in the modeled world.
- **Transaction time:** `transaction_from` / `transaction_to` — when APAS stored/believed that version.

Ranges are half-open. Corrections close the old transaction range and insert a new row; they do not overwrite history. Retrieval accepts both `as_of_date` and optional `known_at`.

### Secure pgvector retrieval

`app/retrieval/postgres.py` combines cosine similarity and PostgreSQL full-text rank. Tenant, RLS, jurisdiction, valid-time, and transaction-time predicates execute before ranking. The API returns evidence IDs plus source/version/chunk handles rather than free-floating text.

### RDF / graph isolation

The ontology includes Authority, Jurisdiction, Regulation, Requirement, Facility, Utility, Contaminant, Measurement, Violation, Deadline, Document, DocumentVersion, Claim, Evidence, Agent, and ModelRun. Predicates are allow-listed. The embedded repository represents named-graph isolation through tenant/classification/jurisdiction attributes and an authorization decision per edge. It can be replaced by RDFLib or a triplestore behind the same interface.

## Provenance, verification, and release policy

Lineage is recorded as:

```text
SourceDocument -> DocumentVersion -> Chunk -> RetrievalRun -> EvidenceSet
-> ModelRun -> GeneratedClaim -> VerificationResult -> FinalAnswer
```

`GET /claims/{claim_id}/provenance` returns authorized lineage: document/version/page/section/chunk, retrieval query, model/model version, prompt version, policy version, verifier, and result. The provenance endpoint re-authorizes the claim itself to prevent metadata leakage.

The model can only emit structured candidate claims with evidence IDs. Each claim fails closed unless the cited evidence exists in the request's authorized EvidenceSet, is temporally applicable, contains every material number, and entails the claim. Only `SUPPORTED` claims pass automatically. Weak evidence causes `ABSTAIN`; unresolved normative conflicts cause `ESCALATE`.

Retrieved text is always untrusted data. Known instruction patterns are neutralized before composition, and security/tool policy is outside the prompt.

## Tamper-evident audit

Each event stores the previous hash and:

```text
event_hash = SHA256(canonical_event_payload + previous_hash)
```

`AuditLedger.verify_audit_chain()` and `GET /audit/verify` detect changed payloads, reordered events, broken links, and hash edits. PostgreSQL also rejects UPDATE/DELETE on `audit.events`. This is a simple hash chain, not blockchain. Production should periodically anchor signed checkpoints in immutable external storage.

## API

- `POST /ask`
- `GET /health`
- `GET /ontology`
- `GET /claims/{claim_id}/provenance`
- `GET /requests/{request_id}/trace`
- `GET /audit/verify`
- `GET /security/decisions/{request_id}`

The dark UI at `/` lets the interviewer choose an allowed demo identity, jurisdiction, and as-of date. Tenant is intentionally not an arbitrary request field; it is bound to the selected authenticated identity on the server.

## Run locally

```bash
cp .env.example .env
# Replace both example passwords.
docker compose up --build
# Open http://localhost:8000
```

Without Docker:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.main:app --reload
```

Run checks:

```bash
pytest
python scripts/evaluate.py
```

To verify PostgreSQL RLS against a running Compose database:

```bash
psql "$DATABASE_URL" -f scripts/verify_rls.sql
```

## Demo data

Seeds include Tenant Alpha and Tenant Beta, PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED records, FEDERAL and STATE-X jurisdictions, changing regulation versions, a superseded interval, contradictory requirements, a malicious prompt-injection document, restricted content, and unsupported cybersecurity topics. Every regulatory sentence is labeled `SYNTHETIC DEMO`.

## Tests and evaluation

The suite covers tenant chunk/vector/graph isolation; evidence and provenance isolation; classification and count/metadata suppression; valid and transaction time; future records; forged citations; unsupported numbers; prompt injection; expired capability; conflict escalation; abstention; audit tampering; RLS/role migration contracts; and API denial behavior. `RED_TEAM.md` maps attacks to expected outcomes.

Golden metrics include answer correctness, grounded-claim rate, abstention accuracy, temporal correctness, authorization correctness, tenant leakage, injection success, unauthorized retrieval, unsupported final claims, and undetected audit tampering. Security targets are all zero where lower is safer.

### Verified in this build

- `68 passed` automated tests in this environment; 10 live PostgreSQL tests are skipped when `TEST_DATABASE_URL` is absent.
- Golden evaluation: 6/6 scenarios passed.
- Cross-tenant leakage, unauthorized retrieval, unsupported released claims, prompt-injection success, and undetected audit tampering: zero in the deterministic suite.
- PostgreSQL migration/RLS is supplied and contract-tested. It was **not executed in this build environment because Docker/PostgreSQL was unavailable**; run the Compose command and `scripts/verify_rls.sql` before presenting the database enforcement as deployment-verified.

## Limitations and production improvements

- In-process repositories power the zero-setup demo; PostgreSQL adapters and schema are the production path.
- The graph demo uses an inspectable embedded relation store rather than a deployed triplestore.
- Retrieval uses deterministic keyword scoring in the zero-setup path; PostgreSQL has the hybrid pgvector/FTS query.
- The composer is deterministic, not a hosted LLM. A production model must use schema-constrained output and retain the same verifier/policy gate.
- Lexical entailment is conservative but not sufficient for legal semantics; add numeric/unit parsers, domain rules, and a separately authorized NLI verifier.
- Demo identity selection is not authentication. Add OIDC/JWT validation, short-lived credentials, CSRF/rate limits, and server-side membership lookup.
- In-memory audit state is for the demo. Use PostgreSQL append-only writes, serialized per-tenant chain heads, signed checkpoints, retention controls, and external immutable anchors.
- Add live Postgres integration tests in CI (including role impersonation), object-store immutability, KMS, observability redaction, backups, and disaster recovery.

## Interview walkthrough (5 minutes)

1. **Problem (30s):** “Normal RAG can answer from the wrong tenant, wrong classification, or wrong point in time. V3 treats the LLM as untrusted and makes evidence release a security transaction.”
2. **Boundary (45s):** Show the diagram. “Identity establishes tenant and clearance. A centralized RBAC+ABAC engine and PostgreSQL RLS independently enforce access. The model never sees credentials or arbitrary query tools.”
3. **Retrieval (45s):** Show `secure_retrieve` and the pgvector SQL. “Filters execute before ranking, so vectors, counts, and metadata cannot leak. Graph queries are allow-listed and scoped like named graphs.”
4. **Time/conflicts (45s):** Ask the 2026 and 2027 versions. “Valid time answers what applied; transaction time answers what we believed then. Contradictory authorized requirements produce ESCALATE, never an LLM guess.”
5. **Claims/provenance (45s):** Open claim details. “The model proposes `{text, evidence_ids}`. Each claim is checked for source existence, authorization, temporal validity, numbers, entailment, and citation. Provenance reaches the exact document version, chunk, run, model, prompt, policy, and verifier.”
6. **Adversarial proof (45s):** Switch to Alpha viewer and request code 991, then ask for Beta 48-hour content, then query an unsupported cybersecurity rule. All abstain without revealing metadata. Explain the malicious-document test.
7. **Audit/close (50s):** Show `/audit/verify` and the tamper test. “Every state leaves a trace; every important decision is attributable. The audit chain detects historical mutation. The design favors fail-closed behavior, clarity, and replaceable repositories.”

### Likely follow-ups

- **Why RDF?** Explicit typed relationships, provenance edges, and graph traversal complement semantic similarity; named-graph scope supports isolation.
- **Why not let the LLM write SPARQL?** Generated query text is executable authority. Use intent-to-approved-query mappings or a validated AST with graph allow-lists.
- **Why RLS if the app filters tenants?** Application bugs are expected. RLS makes isolation a database invariant and protects every query path.
- **RBAC vs ABAC?** RBAC grants coarse job capabilities; ABAC evaluates request/resource context such as classification, jurisdiction, tool, and purpose.
- **How is pgvector isolated?** Tenant/classification/jurisdiction/temporal predicates and RLS run before ordering/limit; protected vectors never join the candidate result.
- **What is bitemporal data?** Valid time models the world; transaction time models knowledge history. Both are needed for defensible historical answers.
- **Can provenance leak?** Yes, so provenance is a protected resource and returns only already-authorized lineage.
- **Is the hash ledger immutable?** It is tamper-evident, with DB update/delete prevention. Strong production immutability needs external signed anchors and operational controls.
- **How do you control hallucinations?** Structured claims, evidence-ID binding, deterministic checks, per-claim status, fail-closed release, conflict escalation, and abstention.
- **How do agents stay safe?** Short-lived capability objects restrict tenant, tools, operation, clearance, and expiry; wrappers expose domain operations, not databases.
- **How would this scale?** Partition large tenant tables, tune HNSW/IVFFlat per workload, cache only authorization-equivalent results, use a production triplestore, and serialize audit chain heads.

## V4 production-hardening layer

V4 implements the complete advanced roadmap on top of the V3 security core:

1. **Live PostgreSQL enforcement:** `ci/security-ci.yml.example` is a ready-to-install GitHub Actions workflow that boots pgvector/PostgreSQL, runs both migrations, seeds real Alpha/Beta records, provisions a non-owner login, and executes direct RLS tests across chunks, vectors, graph data, claims, packages, clearance boundaries, privileges, and pooled transaction context.
2. **Production identity boundary:** `OIDCAuthenticator` validates signed issuer/audience/expiry claims while `DatabaseMembershipAuthority` obtains tenant, roles, clearance, and jurisdictions exclusively from PostgreSQL. Token-supplied tenant or role claims are ignored.
3. **Signed evidence packages:** every configured answer produces an Ed25519-signed package binding question, answer, claims, evidence, document versions, policies, model manifest, temporal parameters, classification, jurisdiction, and audit checkpoint. `KMSDelegatingKey` provides the production HSM/KMS boundary.
4. **Advanced audit:** V4 adds serialized per-tenant chain heads, a `SECURITY DEFINER` append function, Merkle roots, signed checkpoints, and fields for an external immutable anchor.
5. **Independent verification pipeline:** evidence existence, temporal resolution, numeric/unit support, citation alignment, conflict state, and independent entailment are separate fail-closed stages.
6. **Regulatory precedence:** explicit supersession, specificity, and authority hierarchy can resolve a conflict; same-level or insufficient precedence escalates.
7. **RDF adapter:** RDFLib `Dataset` named graphs isolate tenants and classifications, record PROV-O lineage, and expose only allow-listed graph templates—never arbitrary SPARQL.
8. **Information-flow control:** derived values inherit the maximum input classification and cross-tenant derivation is forbidden.
9. **Side-channel controls:** denied resource IDs/counts stay internal, public denials are normalized, and a bounded-delay utility is available for high-risk existence endpoints.
10. **Secure ingestion:** MIME validation, malware scanning interface, hashing, secret detection, prompt-injection detection, classification review, parser/chunker/model version pinning, and quarantine manifests.
11. **Policy-as-code lifecycle:** versioned bundles support simulation, digesting, four-eyes approval, activation, rollback-ready states, and an OPA Data API adapter.
12. **Signed agent capability tokens:** tenant, audience, tool, operation, jurisdiction, purpose, classification, expiry, nonce, delegation depth, call budget, and revocation are enforced.
13. **Human review console:** `/review-console` shows tenant/classification-filtered conflict dossiers and requires two distinct reviewers for high-risk decisions.
14. **Model reproducibility:** manifests capture provider/model/prompt/tool schema/parameters/evidence order/safety/response hashes and whether deterministic replay is supported.
15. **Continuous security evaluation:** CI runs migrations, live RLS tests, unit/integration/adversarial tests, the golden suite, and critical lint checks. The authorization matrix tests every demo identity against returned tenant, classification, and jurisdiction labels.

### V4 verification status

- Local environment: **68 passed, 10 skipped**. The skipped tests require live PostgreSQL credentials.
- Golden suite: **6/6 passed**.
- Critical lint: passed.
- Live PostgreSQL tests cannot run in this sandbox because Docker/PostgreSQL is unavailable. The real workflow is `.github/workflows/security-ci.yml`; it runs all nine live tests.
- One non-security warning remains from Starlette’s transitional TestClient/httpx compatibility layer.

## Runtime enforcement status (V4.1)

### Implemented and runtime-enforced in production mode

When `APAS_RUNTIME_MODE=production`, `/ask` rejects JSON demo identities and requires a Bearer JWT. Startup fails if either database URL, OIDC configuration, or signing key is absent. The executable path is:

```text
Bearer JWT validation (issuer, audience, signature, expiry)
→ DatabaseMembershipAuthority(issuer, subject, selected tenant)
→ SecurityContext from database authorization attributes
→ one PostgreSQL transaction
→ transaction-local app.* context
→ RLS-secured hybrid pgvector retrieval and fixed graph template
→ bitemporal and precedence processing
→ tool-free untrusted-evidence composer
→ fail-closed deterministic checks, then semantic verification
→ persisted claims and transitive provenance
→ signed and persisted EvidencePackage
→ audit.append_event()
→ commit
```

PostgreSQL runtime LOGIN roles are provisioned separately from NOLOGIN group roles. The API runtime is non-owner, non-superuser, cannot bypass RLS, create databases/roles, administer policies, or mutate audit history. Capability use is bound twice: signed request claims are checked in Python, and the persisted capability row atomically validates scope and spends its call budget in PostgreSQL.

### Implemented but adapter-dependent

- Production OIDC uses a configured PEM verification key. Deployments needing rotating JWKS must add a cached JWKS provider without changing database membership resolution.
- `KMSDelegatingKey` defines the production signing boundary. AWS KMS, GCP Cloud KMS, Azure Key Vault, and Vault Transit require provider-specific `sign` and `verify` callables and deployment IAM. Local Ed25519 is development-only.
- The semantic verifier remains explicitly named `conservative-lexical-nli-v2`. It can reject but cannot override any deterministic failure. A separately authorized production NLI adapter may replace only that final stage.
- The RDFLib adapter is embedded. Production graph retrieval in `/ask` currently uses the PostgreSQL `knowledge.relations` projection behind a fixed query template and RLS.

### Demo-only

- `MemoryStore`, selectable identities, in-process graph data, in-memory capabilities, and `AuditLedger` are used only when `APAS_RUNTIME_MODE=demo`.
- The UI displays **DEMO SECURITY MODE** and hides the demo identity selector when production mode is reported.

## Security guarantees actually verified

### Verified locally in this execution environment

- 68 non-PostgreSQL tests pass.
- Golden evaluation passes 6/6.
- Capability tokens bind subject, tenant, audience, tool, operation, jurisdiction, purpose, classification, expiry, delegation depth, revocation, and budget.
- OIDC tests prove JWT tenant, role, and clearance claims do not determine authorization.
- Issuer collisions, multiple memberships, inactive identities, wrong audience, unknown issuer, and expired tokens fail closed.
- RDF named graphs prevent same-tenant unauthorized-jurisdiction observation.
- Hidden and nonexistent provenance produce the same public response.
- Higher-classification lineage is transitively denied without exposing its resource ID.
- Novel retrieved instructions have no tool-capability channel.
- Evidence-package and audit-chain tampering are detected in deterministic tests.

### Verified in real PostgreSQL CI

GitHub Actions run `36257915580` completed successfully with **78 tests passed**, including all ten live PostgreSQL tests. `.github/workflows/security-ci.yml` starts pgvector PostgreSQL, applies migrations 001–003 in order, seeds synthetic rows, creates non-owner runtime logins, and proves:

- Cross-tenant chunks, embeddings, graph edges, claims, and packages are invisible.
- PUBLIC context cannot count restricted rows.
- A closer Beta vector cannot enter Alpha ranking.
- `SET LOCAL` context disappears before a pooled connection is reused.
- Runtime role flags and database/schema/table ownership are non-privileged.
- Runtime SQL cannot assume the security-admin role, alter policies, disable RLS, drop tables, or read security tables.
- Runtime SQL cannot update or delete audit history.
- Two concurrent spends against `max_calls=1` produce exactly one success.
- The production runtime executes OIDC → database identity → SET LOCAL → RLS retrieval → persisted signed package.
- Tampering with persisted package JSON makes signature verification fail.

Docker/PostgreSQL remains unavailable in the agent sandbox, but the same commit passed the required live PostgreSQL suite in GitHub `security-ci`.

## Repository security controls recommended

Repository settings are intentionally not changed automatically. Recommended controls:

- Protect `main` and disallow direct pushes.
- Require the `security-ci` check and at least one pull-request review.
- Require signed commits and dismiss stale approvals after security changes.
- Enable secret scanning, push protection, dependency review, and CodeQL.
- Enable Dependabot or Renovate with grouped security updates.
- Add `CODEOWNERS` review requirements for `app/db/migrations/`, `app/security/`, `app/auth/`, `.github/workflows/`, and `docker/postgres-init/`.

## Production-only remaining work

- Configure a real OIDC issuer/JWKS lifecycle and rotate keys.
- Connect `KMSDelegatingKey` to the selected cloud or Vault provider; never mount a long-lived private key in a production container.
- Move database passwords to Docker/Kubernetes secrets or a workload-identity database authentication mechanism.
- Run and require `security-ci`, then retain its reports as release evidence.
- Add production observability with classified-field redaction and a tenant-independent authentication-failure security sink for failures that occur before tenant resolution.
