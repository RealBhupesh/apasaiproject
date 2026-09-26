from dataclasses import replace
from uuid import uuid4
from app.graph.rdf_repository import RDFGraphRepository
from app.security.context import Classification
from tests.conftest import context

def test_named_graph_tenant_classification_and_jurisdiction_scope():
    g=RDFGraphRepository();alpha=context("alpha-viewer");beta=context("beta-analyst");subject="urn:reg:1"
    g.add_relation(tenant_id=alpha.tenant_id,classification=Classification.PUBLIC,subject=subject,predicate="issuedBy",object_="urn:federal",jurisdiction="FEDERAL",source_chunk_id=uuid4())
    g.add_relation(tenant_id=alpha.tenant_id,classification=Classification.PUBLIC,subject=subject,predicate="issuedBy",object_="urn:state-secret",jurisdiction="STATE-X",source_chunk_id=uuid4())
    g.add_relation(tenant_id=beta.tenant_id,classification=Classification.PUBLIC,subject=subject,predicate="issuedBy",object_="urn:beta",jurisdiction="FEDERAL",source_chunk_id=uuid4())
    federal_only=replace(alpha,jurisdictions=frozenset({"FEDERAL"}));rows=g.relations_for_subject(federal_only,subject,"issuedBy")
    assert len(rows)==1 and rows[0][2]=="urn:federal"
    assert "state-secret" not in str(rows) and "beta" not in str(rows)
