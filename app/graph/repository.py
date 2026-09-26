from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from app.security.context import Classification, Decision, Operation, ProtectedResource, SecurityContext
from app.security.policies import PolicyEngine


@dataclass(frozen=True)
class Relation:
    id: str
    tenant_id: UUID
    classification: Classification
    jurisdiction: str
    subject: str
    predicate: str
    object: str
    source_chunk_id: UUID


class SecureGraphRepository:
    """Named-graph equivalent isolation; callers cannot provide arbitrary SPARQL."""

    ALLOWED_PREDICATES = frozenset({
        "issuedBy", "appliesTo", "requires", "locatedIn", "measures", "violates",
        "supersedes", "derivedFrom", "supportedBy", "generatedBy", "authorizedBy",
    })

    def __init__(self, relations: list[Relation], policy: PolicyEngine):
        self.relations = relations
        self.policy = policy

    def query(self, context: SecurityContext, jurisdiction: str, terms: set[str]) -> list[Relation]:
        output: list[Relation] = []
        for rel in self.relations:
            if rel.tenant_id != context.tenant_id or rel.jurisdiction != jurisdiction:
                continue
            if rel.predicate not in self.ALLOWED_PREDICATES:
                continue
            decision = self.policy.authorize(
                context,
                ProtectedResource("graph_relation", rel.id, rel.tenant_id, rel.classification, rel.jurisdiction),
                Operation.SEARCH,
            )
            haystack = f"{rel.subject} {rel.predicate} {rel.object}".lower()
            if decision.decision == Decision.ALLOW and any(t.lower() in haystack for t in terms):
                output.append(rel)
        return output

    def execute_sparql(self, _query: str) -> None:
        raise PermissionError("arbitrary SPARQL is not exposed")
