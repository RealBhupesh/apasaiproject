from datetime import date

from app.retrieval.secure import secure_retrieve
from tests.conftest import context


def test_lower_clearance_cannot_retrieve_or_infer_restricted(system):
    store,policy,_,_=system
    result=secure_retrieve("restricted response plan code 991",context("alpha-viewer"),"FEDERAL",date(2026,6,1),store,policy)
    # Neither passages nor request-visible decisions contain denied resource metadata.
    assert result.document_passages == []
    assert all(d.decision == "ALLOW" for d in result.security_decisions)


def test_admin_can_retrieve_restricted(system):
    store,policy,_,_=system
    result=secure_retrieve("restricted response plan code 991",context("alpha-admin"),"FEDERAL",date(2026,6,1),store,policy)
    assert any("991" in e.text for e in result.document_passages)
