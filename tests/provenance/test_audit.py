from uuid import uuid4
from app.audit.ledger import AuditLedger
from app.db.seed import ALPHA


def test_audit_chain_passes_and_tampering_fails():
    ledger=AuditLedger(); request=uuid4()
    ledger.append(tenant_id=ALPHA,actor="a",event_type="x",resource="r",request_id=request,metadata={"ok":1})
    ledger.append(tenant_id=ALPHA,actor="a",event_type="y",resource="r",request_id=request,metadata={"ok":2})
    assert ledger.verify_audit_chain()=={"valid":True,"events_checked":2}
    ledger.events[0].metadata["ok"]=999
    assert ledger.verify_audit_chain()["valid"] is False
