from datetime import date

from app.db.seed import BETA
from app.retrieval.secure import secure_retrieve
from tests.conftest import context


def test_alpha_cannot_retrieve_beta_chunks_or_vectors(system):
    store,policy,_,_=system; ctx=context("alpha-analyst")
    result=secure_retrieve("Beta report 48 hours",ctx,"FEDERAL",date(2026,6,1),store,policy)
    assert all(store.chunks[e.chunk_id].tenant_id != BETA for e in result.document_passages)
    assert "48" not in " ".join(e.text for e in result.document_passages)


def test_alpha_cannot_query_beta_graph(system):
    store,_,graph,_=system; ctx=context("alpha-analyst")
    assert all(r.tenant_id == ctx.tenant_id for r in graph.query(ctx,"FEDERAL",{"authority"}))


def test_alpha_cannot_reference_beta_evidence_id(system):
    store,policy,_,_=system
    beta=secure_retrieve("Beta facilities 48",context("beta-analyst"),"FEDERAL",date(2026,6,1),store,policy)
    from app.retrieval.models import EvidenceSet
    from app.verification.claims import CandidateClaim, ClaimVerifier, VerificationStatus
    forged=EvidenceSet(context("alpha-analyst").request_id,context("alpha-analyst").tenant_id,"FEDERAL",date(2026,6,1))
    result=ClaimVerifier.verify(CandidateClaim("Beta requires 48 hours",[beta.document_passages[0].id]),forged)
    assert result.status == VerificationStatus.UNSUPPORTED
