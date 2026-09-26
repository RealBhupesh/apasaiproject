# Red-team contract

| Attack | Expected behavior |
|---|---|
| Prompt or malicious-document injection | Retrieved text remains quoted data; instruction patterns are removed before composition. |
| SQL injection | No arbitrary SQL endpoint; parameterized statements only. |
| SPARQL injection | No arbitrary SPARQL endpoint; allow-listed graph query methods only. |
| Tenant-ID manipulation | Tenant comes from authenticated server-side identity; PostgreSQL RLS independently enforces it. |
| Fake evidence IDs / citation spoofing | Claim verifier rejects IDs absent from the authorized EvidenceSet. |
| Classification bypass | Pre-retrieval ABAC and RLS reject rows, vectors, metadata, counts, and provenance. |
| Expired capability | Tool wrapper raises a generic capability denial. |
| Role escalation | Roles come from identity/security authority, never request payload or model output. |
| Numeric hallucination | Deterministic verifier rejects numbers absent from cited evidence. |
| Conflicting regulations | Workflow returns `ESCALATE`; the LLM cannot pick a winner. |
| Outdated/future regulation | Bitemporal resolver excludes it for valid-time and transaction-time. |
| Missing jurisdiction | Input validation or policy denies the request. |
| Unsupported cybersecurity requirement | Workflow returns `ABSTAIN`. |
| Request to ignore controls | Policy enforcement remains outside the LLM boundary. |
