from datetime import date
from uuid import uuid4
from app.retrieval.models import Evidence,EvidenceSet
from app.verification.claims import CandidateClaim,VerificationStatus
from app.verification.pipeline import VerificationPipeline
from tests.conftest import context


def test_unit_mismatch_fails_independent_pipeline():
    ctx=context("alpha-analyst"); es=EvidenceSet(ctx.request_id,ctx.tenant_id,"FEDERAL",date(2026,1,1)); eid=uuid4()
    es.document_passages=[Evidence(eid,uuid4(),uuid4(),uuid4(),"Report within 24 hours.","deadline",1,"FEDERAL",1)]
    result=VerificationPipeline().verify(CandidateClaim("Report within 24 days.",[eid]),es)
    assert result.status==VerificationStatus.UNSUPPORTED

def test_date_hallucination_fails_closed():
    ctx=context("alpha-analyst");es=EvidenceSet(ctx.request_id,ctx.tenant_id,"FEDERAL",date(2026,1,1));eid=uuid4();es.document_passages=[Evidence(eid,uuid4(),uuid4(),uuid4(),"Rule begins 2026-01-01.","dates",1,"FEDERAL",1)]
    assert VerificationPipeline().verify(CandidateClaim("Rule begins 2027-01-01.",[eid]),es).status==VerificationStatus.UNSUPPORTED
