from datetime import date
from uuid import uuid4

from app.retrieval.models import Evidence, EvidenceSet
from app.verification.claims import CandidateClaim, ClaimVerifier, VerificationStatus
from tests.conftest import context


def evidence_set():
    ctx=context("alpha-analyst")
    es=EvidenceSet(ctx.request_id,ctx.tenant_id,"FEDERAL",date(2026,6,1))
    es.document_passages=[Evidence(uuid4(),uuid4(),uuid4(),uuid4(),"Reporting is required within 24 hours.","s",1,"FEDERAL",1.0)]
    return es

def test_fake_citation_fails():
    assert ClaimVerifier.verify(CandidateClaim("Required within 24 hours",[uuid4()]),evidence_set()).status == VerificationStatus.UNSUPPORTED

def test_numeric_hallucination_fails():
    es=evidence_set(); eid=es.document_passages[0].id
    assert ClaimVerifier.verify(CandidateClaim("Reporting is required within 72 hours",[eid]),es).status == VerificationStatus.UNSUPPORTED
