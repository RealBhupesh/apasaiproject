from datetime import datetime,timedelta,timezone
from uuid import uuid4
import pytest
from app.security.capability_tokens import CapabilityClaims,CapabilityTokenService
from app.signing.evidence_package import Ed25519SigningKey


def claims(**changes):
    base=dict(subject="agent",tenant_id=uuid4(),tools=("search",),operations=("READ",),jurisdictions=("FEDERAL",),max_classification=1,purpose="research",audience="apas",expires_at=datetime.now(timezone.utc)+timedelta(minutes=5),nonce="n1",max_calls=1)
    return CapabilityClaims(**(base|changes))

def test_signed_capability_scope_budget_and_revocation():
    s=CapabilityTokenService(Ed25519SigningKey()); t=s.issue(claims())
    assert s.verify(t,audience="apas",tool="search",operation="READ",jurisdiction="FEDERAL",purpose="research").subject=="agent"
    with pytest.raises(PermissionError): s.verify(t,audience="apas",tool="search",operation="READ",jurisdiction="FEDERAL",purpose="research")

def test_expired_capability_denied():
    s=CapabilityTokenService(Ed25519SigningKey()); t=s.issue(claims(expires_at=datetime.now(timezone.utc)-timedelta(seconds=1),nonce="n2"))
    with pytest.raises(PermissionError): s.verify(t,audience="apas",tool="search",operation="READ",jurisdiction="FEDERAL",purpose="research")
