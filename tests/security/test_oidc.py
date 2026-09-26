from datetime import datetime,timedelta,timezone
from uuid import uuid4
import jwt,pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.security.context import Classification
from app.security.identity import OIDCAuthenticator,VerifiedMembership
class Memberships:
    def __init__(self,rows):self.rows=rows;self.calls=[]
    def resolve(self,issuer,subject,tenant_id=None):
        self.calls.append((issuer,subject,tenant_id));matches=[x for x in self.rows if x.issuer==issuer and x.subject==subject and (tenant_id is None or x.tenant_id==tenant_id)]
        if len(matches)!=1:raise PermissionError("membership denied")
        return matches[0]
def setup():
    private=Ed25519PrivateKey.generate();public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo);return private,public
def token(private,**changes):
    now=datetime.now(timezone.utc);body={"iss":"issuer-a","aud":"apas","sub":"user123","iat":now,"exp":now+timedelta(minutes=5),"tenant":"forged","roles":["admin"],"clearance":"RESTRICTED"};body.update(changes);return jwt.encode(body,private,algorithm="EdDSA")
def test_oidc_ignores_forged_authorization_claims_and_uses_issuer_subject():
    private,public=setup();tenant=uuid4();members=Memberships([VerifiedMembership("issuer-a","user123",tenant,frozenset({"viewer"}),Classification.PUBLIC,frozenset({"FEDERAL"}))]);auth=OIDCAuthenticator(issuer="issuer-a",audience="apas",public_key=public,memberships=members)
    ctx=auth.authenticate(token(private),uuid4(),"research");assert ctx.tenant_id==tenant and ctx.roles==frozenset({"viewer"}) and ctx.clearance==Classification.PUBLIC;assert members.calls[0][:2]==("issuer-a","user123")
def test_issuer_collision_cannot_resolve_other_issuer():
    private,public=setup();a,b=uuid4(),uuid4();members=Memberships([VerifiedMembership("issuer-a","user123",a,frozenset({"viewer"}),Classification.PUBLIC,frozenset({"FEDERAL"})),VerifiedMembership("issuer-b","user123",b,frozenset({"admin"}),Classification.RESTRICTED,frozenset({"FEDERAL"}))]);auth=OIDCAuthenticator(issuer="issuer-a",audience="apas",public_key=public,memberships=members);assert auth.authenticate(token(private),uuid4(),"research").tenant_id==a
def test_wrong_audience_expired_and_unknown_issuer_fail():
    private,public=setup();m=Memberships([]);auth=OIDCAuthenticator(issuer="issuer-a",audience="apas",public_key=public,memberships=m);now=datetime.now(timezone.utc)
    for bad in [token(private,aud="wrong"),token(private,exp=now-timedelta(seconds=1)),token(private,iss="issuer-b")]:
        with pytest.raises(Exception):auth.authenticate(bad,uuid4(),"research")
def test_inactive_and_multiple_memberships_fail():
    private,public=setup();a,b=uuid4(),uuid4();inactive=VerifiedMembership("issuer-a","user123",a,frozenset({"viewer"}),Classification.PUBLIC,frozenset({"FEDERAL"}),False);auth=OIDCAuthenticator(issuer="issuer-a",audience="apas",public_key=public,memberships=Memberships([inactive]))
    with pytest.raises(PermissionError):auth.authenticate(token(private),uuid4(),"research")
    multi=Memberships([VerifiedMembership("issuer-a","user123",a,frozenset({"viewer"}),Classification.PUBLIC,frozenset({"FEDERAL"})),VerifiedMembership("issuer-a","user123",b,frozenset({"viewer"}),Classification.PUBLIC,frozenset({"FEDERAL"}))]);auth=OIDCAuthenticator(issuer="issuer-a",audience="apas",public_key=public,memberships=multi)
    with pytest.raises(PermissionError):auth.authenticate(token(private),uuid4(),"research")
    assert auth.authenticate(token(private),uuid4(),"research",a).tenant_id==a
