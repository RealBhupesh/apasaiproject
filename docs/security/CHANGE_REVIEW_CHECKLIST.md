# Security Change Review Checklist

Use this before merging any security-sensitive change.

## Identity and authentication

- [ ] Is identity cryptographically verified in production?
- [ ] Are issuer and audience checked?
- [ ] Is authorization loaded server-side?
- [ ] Are token-supplied roles/tenant/clearance ignored for authorization?
- [ ] Can the same subject from another issuer collide?
- [ ] Are inactive memberships rejected?

## Authorization

- [ ] Does the request use the correct tenant?
- [ ] Are role and ABAC checks centralized?
- [ ] Is classification enforced?
- [ ] Is jurisdiction enforced?
- [ ] Are denials generic externally?
- [ ] Are access decisions auditable?

## PostgreSQL and RLS

- [ ] Does the protected table have RLS?
- [ ] Is FORCE RLS appropriate/enabled?
- [ ] Is the runtime role non-owner and NOBYPASSRLS?
- [ ] Is security context set inside the transaction?
- [ ] Does pooled-connection testing prove no context leakage?
- [ ] Are queries parameterized?
- [ ] Are grants minimal?

## Vector retrieval

- [ ] Are tenant/classification/jurisdiction filters applied before ranking?
- [ ] Are valid-time and transaction-time filters applied before ranking?
- [ ] Can a closer unauthorized vector affect the result?
- [ ] Can result counts leak protected data?

## Graph

- [ ] Is tenant scope enforced?
- [ ] Is classification scope enforced?
- [ ] Is jurisdiction scope enforced?
- [ ] Are predicates/templates allow-listed?
- [ ] Is arbitrary SPARQL still disabled?

## Capabilities

- [ ] Subject bound?
- [ ] Tenant bound?
- [ ] Audience bound?
- [ ] Tool bound?
- [ ] Operation bound?
- [ ] Jurisdiction bound?
- [ ] Purpose bound?
- [ ] Classification ceiling enforced?
- [ ] Expiry checked?
- [ ] Revocation persisted?
- [ ] Call budget persisted and atomic?
- [ ] Delegation constrained?

## LLM and prompt injection

- [ ] Is model output still untrusted?
- [ ] Are retrieved instructions treated as data?
- [ ] Can document text change tool permissions? It must not.
- [ ] Can the model execute arbitrary SQL/SPARQL? It must not.
- [ ] Does failure of the model/verifier fail closed?

## Claims

- [ ] Every material claim cites authorized evidence?
- [ ] Fake IDs fail?
- [ ] Cross-tenant evidence IDs fail?
- [ ] Numbers/units/dates are checked deterministically?
- [ ] Temporal applicability is checked?
- [ ] Conflicts produce ESCALATE?
- [ ] Missing evidence produces ABSTAIN?

## Provenance

- [ ] Is the claim authorized?
- [ ] Is every returned lineage hop authorized?
- [ ] Are hidden IDs/counts/titles redacted?
- [ ] Can provenance reveal another classification or tenant?

## Audit

- [ ] Production events use approved append path?
- [ ] Update/delete prohibited?
- [ ] Hash/checkpoint validation still works?
- [ ] Audit endpoint scoped to authorized tenant?
- [ ] Logs exclude secrets/JWTs/passwords?

## Ingestion

- [ ] MIME/content validated beyond extension?
- [ ] Hash recorded?
- [ ] Malware scanning interface used?
- [ ] Secrets detected?
- [ ] Prompt-injection indicators flagged?
- [ ] High-classification upload requires appropriate review?
- [ ] Parser does not execute active content?

## Human review

- [ ] Reviewer has tenant access?
- [ ] Reviewer has role/clearance/jurisdiction?
- [ ] Requester cannot approve own case?
- [ ] Duplicate reviewer vote blocked?
- [ ] Multi-review semantics deterministic?
- [ ] Review decisions persisted/audited?

## Deployment / CI

- [ ] Real migrations execute in CI?
- [ ] Live PostgreSQL RLS tests run?
- [ ] CI uses non-owner runtime credentials?
- [ ] Adversarial tests run?
- [ ] Golden evaluation runs?
- [ ] Lint/type checks relevant to the change run?
- [ ] No security workflow is merely an `.example` file?

## Documentation honesty

- [ ] README claim matches runtime reality?
- [ ] Demo-only vs production-enforced clearly labeled?
- [ ] Known limitations documented?
- [ ] New trust boundary documented?

## Merge rule

If a change can alter a trust boundary and there is no regression test for its abuse case, **do not merge it yet**.
