# Repository Security Instructions

Before proposing or editing code, read `SECURITY_CONSTITUTION.md` and `AGENTS.md`.

The Security Constitution is the canonical security policy for this repository.

All generated code must preserve its `SEC-*` rules, especially:

- server-bound tenant and authorization state;
- PostgreSQL RLS and least-privilege runtime roles;
- authorization before vector/graph ranking;
- tenant/classification/jurisdiction isolation;
- bounded and scoped agent capabilities;
- no arbitrary SQL, SPARQL, shell, or network authority for models;
- retrieved content treated as untrusted data;
- deterministic claim/evidence verification;
- protected provenance and append-only audit;
- fail-closed production behavior.

Do not suggest disabling a security control as a workaround. Do not weaken tests to make CI pass.
