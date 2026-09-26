# Threat Model

## System being protected

A multi-tenant regulatory GraphRAG platform combining PostgreSQL, pgvector, structured graph data, temporal regulatory knowledge, provenance, model-generated candidate claims, verification, evidence signing, and audit.

## Main adversaries

### Malicious tenant user
Attempts to access another tenant or higher-classification information.

### Compromised or manipulated agent
Attempts to widen tool scope, call unauthorized operations, reveal protected evidence, or execute generated database queries.

### Malicious document
Contains prompt injection, secrets, misleading instructions, malformed content, or exploit payloads.

### External attacker
Targets API authentication, injection surfaces, leaked credentials, unsafe endpoints, or dependency vulnerabilities.

### Insider / privileged operator
Attempts to mutate audit history, misuse migration credentials, or access data beyond operational need.

### Accidental developer regression
Removes a tenant filter, uses an owner database connection, ranks before authorization, trusts JWT roles, or exposes sensitive metadata.

---

## Assets and impact

| Asset | Main risk |
|---|---|
| Tenant documents | cross-tenant confidentiality breach |
| Embeddings | semantic/data leakage |
| Knowledge graph | relationship/metadata leakage |
| Provenance | source and model-operation disclosure |
| Security policy | authorization bypass |
| Capability tokens | delegated privilege abuse |
| Audit | loss of accountability |
| Evidence packages | forged defensibility record |
| Signing keys | forged trusted artifacts |
| Human reviews | unauthorized approval |
| Historical regulatory state | incorrect compliance answer |

---

## Key attack paths

### Cross-tenant retrieval

Attack:
- manipulate tenant ID;
- exploit missing application filter;
- use vector similarity against all tenants.

Required defenses:
- server-bound tenant;
- RLS;
- non-owner runtime role;
- pre-ranking tenant filtering;
- cross-tenant integration tests.

### Classification inference

Attack:
- search restricted terms;
- compare counts/timing/status codes;
- inspect provenance or graph metadata.

Required defenses:
- classification-aware RLS/ABAC;
- normalized denials;
- protected provenance;
- pre-ranking filtering;
- metadata-leakage tests.

### OIDC claim escalation

Attack:
- add `roles=["admin"]`;
- add attacker's desired tenant;
- increase clearance.

Required defenses:
- validate issuer/audience/signature/expiry;
- use JWT for identity only;
- load authorization server-side.

### Capability abuse

Attack:
- use token for another tenant;
- replay after revocation;
- overspend call budget concurrently;
- use a lower-scope token for restricted data.

Required defenses:
- bind every material claim;
- persisted revocation;
- atomic usage accounting;
- short expiry;
- classification ceiling;
- audience/tool/operation/purpose validation.

### Prompt injection

Attack:
- a document instructs model to reveal another customer or invoke admin tools.

Required defenses:
- retrieved documents are untrusted data;
- tool authorization outside prompts;
- narrow tool wrappers;
- no model-controlled credentials;
- fail-closed verification.

### SQL/SPARQL injection

Attack:
- user/model supplies executable query language.

Required defenses:
- parameterized SQL;
- approved query templates;
- no arbitrary SPARQL endpoint;
- no unrestricted database tool.

### Evidence forgery

Attack:
- model invents an evidence ID or cites another tenant's evidence.

Required defenses:
- evidence IDs must exist in current authorized EvidenceSet;
- provenance authorization;
- signed evidence packages;
- deterministic citation checks.

### Temporal poisoning

Attack:
- old/superseded/future rule is presented as current.

Required defenses:
- valid-time + transaction-time filtering;
- immutable versions;
- tests before/after effective dates.

### Audit tampering

Attack:
- edit/delete/reorder events to hide actions.

Required defenses:
- append-only DB controls;
- hash chain;
- tenant-specific serialized heads;
- signed/Merkle checkpoints;
- external immutable anchor in production.

---

## Out of scope for the reference implementation

Unless explicitly implemented and tested:

- compromised database host/superuser;
- physical host compromise;
- cloud account takeover;
- hardware side channels;
- formally verified legal reasoning;
- guaranteed semantic entailment by a model;
- production HSM/KMS configuration;
- full malware sandboxing;
- DDoS protection.

Do not claim these are solved merely because interfaces exist.

---

## Security success criteria

The target is:

- cross-tenant leakage: **0**
- unauthorized vector retrieval: **0**
- unauthorized graph retrieval: **0**
- unsupported released claims: **0**
- undetected audit tampering: **0**
- capability scope bypass: **0**

Security claims should be backed by executable tests, not documentation alone.
