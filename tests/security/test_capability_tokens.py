from datetime import datetime,timedelta,timezone
from uuid import uuid4
import pytest
from app.security.capability_tokens import CapabilityClaims,CapabilityTokenService,InMemoryCapabilityState
from app.signing.evidence_package import Ed25519SigningKey

def claims(**changes):
    base=dict(subject="agent",tenant_id=uuid4(),tools=("search",),operations=("READ",),jurisdictions=("FEDERAL",),max_classification=1,purpose="research",audience="apas",expires_at=datetime.now(timezone.utc)+timedelta(minutes=5),nonce="n1",max_calls=1)
    return CapabilityClaims(**(base|changes))
def verify(s,t,c,**changes):
    args=dict(subject=c.subject,tenant_id=c.tenant_id,audience="apas",tool="search",operation="READ",jurisdiction="FEDERAL",purpose="research",requested_classification=1);args.update(changes);return s.verify(t,**args)
def test_signed_capability_all_bindings_and_budget():
    c=claims();s=CapabilityTokenService(Ed25519SigningKey());t=s.issue(c);assert verify(s,t,c).subject=="agent"
    with pytest.raises(PermissionError):verify(s,t,c)
@pytest.mark.parametrize("change",[
 {"subject":"other"},{"tenant_id":uuid4()},{"audience":"wrong"},{"tool":"admin"},{"operation":"WRITE"},{"jurisdiction":"STATE-X"},{"purpose":"other"},{"requested_classification":2}
])
def test_each_request_binding_fails_closed(change):
    c=claims();s=CapabilityTokenService(Ed25519SigningKey());t=s.issue(c)
    with pytest.raises(PermissionError):verify(s,t,c,**change)
def test_expired_revoked_and_tampered_denied():
    key=Ed25519SigningKey();state=InMemoryCapabilityState();s=CapabilityTokenService(key,state)
    expired=claims(expires_at=datetime.now(timezone.utc)-timedelta(seconds=1),nonce="expired")
    with pytest.raises(PermissionError):verify(s,s.issue(expired),expired)
    c=claims(nonce="revoked",max_calls=2);t=s.issue(c);s.revoke("revoked")
    with pytest.raises(PermissionError):verify(s,t,c)
    with pytest.raises(PermissionError):verify(s,t[:-2]+"xx",c)
def test_delegation_depth_denied():
    c=claims(delegation_depth=1);s=CapabilityTokenService(Ed25519SigningKey(),max_delegation_depth=0)
    with pytest.raises(PermissionError):verify(s,s.issue(c),c)
