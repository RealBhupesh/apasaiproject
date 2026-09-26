from uuid import uuid4
from app.graph.rdf_repository import RDFGraphRepository
from app.security.context import Classification
from tests.conftest import context


def test_named_graph_tenant_and_classification_scope():
    g=RDFGraphRepository(); alpha=context("alpha-viewer"); beta=context("beta-analyst"); subject="urn:reg:1"
    g.add_relation(tenant_id=alpha.tenant_id,classification=Classification.PUBLIC,subject=subject,predicate="issuedBy",object_="urn:a",jurisdiction="FEDERAL",source_chunk_id=uuid4())
    g.add_relation(tenant_id=beta.tenant_id,classification=Classification.PUBLIC,subject=subject,predicate="issuedBy",object_="urn:b",jurisdiction="FEDERAL",source_chunk_id=uuid4())
    assert len(g.relations_for_subject(alpha,subject,"issuedBy"))==1
