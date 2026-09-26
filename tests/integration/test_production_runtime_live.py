from __future__ import annotations
import os
from datetime import date,datetime,timedelta,timezone
from uuid import UUID
import jwt,pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.config import RuntimeMode,Settings
from app.runtime import ProductionRuntime
URL=os.getenv("TEST_DATABASE_URL");AUTH=os.getenv("TEST_AUTH_DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL or not AUTH,reason="live databases unavailable")
def test_production_runtime_executes_oidc_to_rls_to_signed_package():
    oidc=Ed25519PrivateKey.generate();signer=Ed25519PrivateKey.generate();public=oidc.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode();private=signer.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    settings=Settings(RuntimeMode.PRODUCTION,URL,AUTH,"https://issuer-a.example","apas",public,private);runtime=ProductionRuntime(settings);now=datetime.now(timezone.utc);token=jwt.encode({"iss":"https://issuer-a.example","aud":"apas","sub":"user123","iat":now,"exp":now+timedelta(minutes=5),"tenant":"forged-beta","roles":["admin"]},oidc,algorithm="EdDSA")
    result=runtime.ask(bearer_token=token,question="What does the synthetic Alpha document say?",jurisdiction="FEDERAL",as_of=date(2026,6,1),known_at=now,purpose="regulatory-research",selected_tenant=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
    assert result.evidence_package_id is not None
    assert all(str(e["tenant_id"])=="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" for e in result.evidence)
