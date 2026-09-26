from datetime import datetime,timedelta,timezone
from uuid import uuid4
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.security.context import Classification
from app.security.identity import OIDCAuthenticator,VerifiedMembership


class Memberships:
    def __init__(self,m): self.m=m
    def resolve(self,subject): return self.m


def test_oidc_uses_server_side_membership_not_token_tenant():
    private=Ed25519PrivateKey.generate(); public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    now=datetime.now(timezone.utc); tenant=uuid4()
    token=jwt.encode({"iss":"issuer","aud":"apas","sub":"user-1","iat":now,"exp":now+timedelta(minutes=5),"tenant":"attacker-value","roles":["admin"]},private,algorithm="EdDSA")
    auth=OIDCAuthenticator(issuer="issuer",audience="apas",public_key=public,memberships=Memberships(VerifiedMembership("user-1",tenant,frozenset({"viewer"}),Classification.PUBLIC,frozenset({"FEDERAL"}))))
    ctx=auth.authenticate(token,uuid4(),"research")
    assert ctx.tenant_id==tenant and ctx.roles==frozenset({"viewer"})
