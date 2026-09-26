# Claude Code Repository Instructions

Before making any code or configuration change, read and obey:

- `SECURITY_CONSTITUTION.md`
- `AGENTS.md`

`SECURITY_CONSTITUTION.md` is the canonical repository security policy.

For security-sensitive work, identify the relevant `SEC-*` rules and preserve them. Do not implement a feature by weakening RLS, tenant isolation, classification, jurisdiction controls, capability scope, prompt-injection boundaries, evidence verification, provenance authorization, audit integrity, secrets handling, or production fail-closed behavior.

If a task conflicts with the Security Constitution, preserve the constitution and explain the conflict instead of implementing the unsafe shortcut.

Do not weaken or skip a valid security test to make the build pass.
