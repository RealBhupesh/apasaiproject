from datetime import date
import pytest
from app.retrieval.secure import secure_retrieve
from tests.conftest import context

@pytest.mark.parametrize("identity",["alpha-viewer","alpha-analyst","alpha-admin","beta-analyst"])
def test_every_returned_row_matches_tenant_clearance_and_jurisdiction(system,identity):
    store,policy,_,_=system; ctx=context(identity)
    for jurisdiction in ctx.jurisdictions:
        result=secure_retrieve("facilities report sample result restricted confidential code",ctx,jurisdiction,date(2026,6,1),store,policy)
        for e in result.document_passages:
            chunk=store.chunks[e.chunk_id]
            assert chunk.tenant_id==ctx.tenant_id
            assert chunk.classification<=ctx.clearance
            assert chunk.jurisdiction in ctx.jurisdictions
