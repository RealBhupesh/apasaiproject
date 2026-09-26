from datetime import date

import pytest

from app.provenance.service import ProvenanceService
from app.security.policies import PolicyEngine
from tests.conftest import context


def test_claim_traces_to_version_and_chunk(workflow,system):
    result=workflow.ask("When must Alpha facilities report sample result?",context("alpha-analyst"),"FEDERAL",date(2026,6,1))
    assert result.claims
    store,_,_,_=system
    svc=ProvenanceService(store,PolicyEngine(store.save_decision))
    p=svc.get_claim_provenance(result.claims[0].id,context("alpha-analyst"))
    assert p["source_document_id"] and p["document_version_id"] and p["chunk_id"]
    assert p["model_version"] and p["prompt_version"] and p["policy_versions"]


def test_alpha_provenance_does_not_leak_to_beta(workflow,system):
    result=workflow.ask("When must Alpha facilities report a sample result?",context("alpha-analyst"),"FEDERAL",date(2026,6,1))
    store,_,_,_=system; svc=ProvenanceService(store,PolicyEngine(store.save_decision))
    with pytest.raises(PermissionError): svc.get_claim_provenance(result.claims[0].id,context("beta-analyst"))


def test_public_claim_with_hidden_lineage_denies_without_leaking_id(system):
    from uuid import uuid4
    from app.db.seed import ALPHA
    from app.security.context import Classification
    store,_,_,_=system
    restricted=next(c for c in store.chunks.values() if c.tenant_id==ALPHA and c.classification==Classification.RESTRICTED)
    claim_id=uuid4();store.provenance[claim_id]={"tenant_id":ALPHA,"classification":Classification.PUBLIC,"jurisdiction":"FEDERAL","claim_id":str(claim_id),"lineage_chunk_ids":[str(restricted.id)]}
    svc=ProvenanceService(store,PolicyEngine(store.save_decision))
    with pytest.raises(PermissionError) as exc:svc.get_claim_provenance(claim_id,context("alpha-analyst"))
    assert str(restricted.id) not in str(exc.value)
