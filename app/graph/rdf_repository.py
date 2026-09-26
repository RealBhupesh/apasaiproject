from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from rdflib import Dataset, Literal, Namespace, URIRef

from app.security.context import Classification, SecurityContext

APAS=Namespace("https://example.invalid/apas/")
PROV=Namespace("http://www.w3.org/ns/prov#")


@dataclass(frozen=True)
class GraphScope:
    tenant_id: UUID
    maximum_classification: Classification
    jurisdictions: frozenset[str]


class RDFGraphRepository:
    """RDF adapter using named graphs. It exposes templates, not arbitrary SPARQL."""

    def __init__(self): self.dataset=Dataset()

    @staticmethod
    def graph_uri(tenant_id: UUID, classification: Classification) -> URIRef:
        return URIRef(f"urn:tenant:{tenant_id}:{classification.name.lower()}")

    def add_relation(self, *, tenant_id: UUID, classification: Classification, subject: str,
                     predicate: str, object_: str, jurisdiction: str, source_chunk_id: UUID) -> None:
        graph=self.dataset.get_context(self.graph_uri(tenant_id,classification))
        s,p,o=URIRef(subject),APAS[predicate],URIRef(object_)
        graph.add((s,p,o)); graph.add((s,APAS.jurisdiction,Literal(jurisdiction))); graph.add((s,PROV.wasDerivedFrom,URIRef(f"urn:chunk:{source_chunk_id}")))

    def relations_for_subject(self, context: SecurityContext, subject: str, predicate: str | None = None) -> list[tuple[str,str,str]]:
        if predicate and predicate not in {"issuedBy","appliesTo","requires","locatedIn","measures","violates","supersedes","derivedFrom","supportedBy","generatedBy","authorizedBy"}:
            raise PermissionError("predicate not allowed")
        rows=[]
        for level in Classification:
            if level > context.clearance: continue
            graph=self.dataset.get_context(self.graph_uri(context.tenant_id,level))
            for _,p,o in graph.triples((URIRef(subject),APAS[predicate] if predicate else None,None)):
                rows.append((subject,str(p),str(o)))
        return rows

    def arbitrary_sparql(self, _query: str) -> None:
        raise PermissionError("arbitrary SPARQL is not exposed")
