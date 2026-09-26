"""Live attacks executed as a non-owner runtime login."""
from __future__ import annotations
import os
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID,uuid4
import pytest
from sqlalchemy import create_engine,text
from sqlalchemy.exc import DBAPIError
URL=os.getenv("TEST_DATABASE_URL");ADMIN=os.getenv("TEST_ADMIN_DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="TEST_DATABASE_URL not configured")
ALPHA=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");BETA=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
def context(c,tenant=ALPHA,clearance="PUBLIC",jurisdictions="FEDERAL"):
    for n,v in {"app.tenant_id":str(tenant),"app.user_id":"live-test","app.clearance":clearance,"app.role":"viewer","app.jurisdictions":jurisdictions,"app.agent":"","app.tool":"","app.purpose":"test"}.items():c.execute(text("SELECT set_config(:n,:v,true)"),{"n":n,"v":v})
def scalar(sql,params=None):
    e=create_engine(URL)
    with e.begin() as c:context(c);value=c.execute(text(sql),params or {}).scalar()
    e.dispose();return value
def denied(sql):
    e=create_engine(URL)
    try:
        with pytest.raises(DBAPIError):
            with e.begin() as c:context(c);c.execute(text(sql))
    finally:e.dispose()
def test_runtime_flags_and_ownership():
    e=create_engine(URL)
    with e.begin() as c:
        row=c.execute(text("SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user")).one();assert row==(False,False,False,False)
        assert c.execute(text("SELECT pg_get_userbyid(datdba)=current_user FROM pg_database WHERE datname=current_database()" )).scalar() is False
        assert c.execute(text("SELECT count(*) FROM pg_namespace WHERE nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)")).scalar()==0
        assert c.execute(text("SELECT count(*) FROM pg_class WHERE relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND relkind='r'")).scalar()==0
    e.dispose()
def test_cross_tenant_and_classification_isolation():
    for table in ["documents.chunks","documents.embeddings","knowledge.relations","provenance.claims","provenance.answer_packages"]:assert scalar(f"SELECT count(*) FROM {table} WHERE tenant_id=:b",{"b":BETA})==0
    assert scalar("SELECT count(*) FROM documents.chunks WHERE security.classification_rank(classification)>0")==0
    assert scalar("SELECT count(*) FROM documents.source_documents WHERE classification='RESTRICTED'")==0
def test_closer_beta_vector_is_removed_before_ranking():
    tenant=scalar("SELECT tenant_id FROM documents.embeddings ORDER BY embedding <=> CAST(:q AS vector) LIMIT 1",{"q":"["+",".join(["0"]*1536)+"]"})
    assert tenant==ALPHA
def test_transaction_context_does_not_leak_through_one_slot():
    e=create_engine(URL,pool_size=1,max_overflow=0)
    with e.begin() as c:context(c)
    with e.begin() as c:assert c.execute(text("SELECT current_setting('app.tenant_id',true)")).scalar() in (None,"")
    e.dispose()
def test_runtime_cannot_escalate_or_mutate_security_boundary():
    denied("SET ROLE apas_security_admin")
    denied("ALTER TABLE documents.chunks DISABLE ROW LEVEL SECURITY")
    denied("DROP TABLE documents.chunks")
    denied("ALTER POLICY secured_chunks ON documents.chunks USING (true)")
    denied("SELECT * FROM security.users")
def test_runtime_cannot_update_or_delete_audit_history():
    e=create_engine(URL)
    with e.begin() as c:
        context(c);event=c.execute(text("SELECT (audit.append_event(:t,'tester','TEST','r',:r,'{}','tester')).id"),{"t":ALPHA,"r":uuid4()}).scalar()
    for statement in [f"UPDATE audit.events SET actor='tampered' WHERE id='{event}'",f"DELETE FROM audit.events WHERE id='{event}'"]:denied(statement)
    e.dispose()
def test_capability_budget_is_atomic_under_concurrency():
    if not ADMIN:pytest.skip("TEST_ADMIN_DATABASE_URL not configured")
    admin=create_engine(ADMIN)
    with admin.begin() as c:c.execute(text("UPDATE security.capability_tokens SET calls_used=0,revoked_at=NULL WHERE nonce='concurrency-1'"))
    admin.dispose()
    def spend(_):
        e=create_engine(URL)
        try:
            with e.begin() as c:context(c,clearance="INTERNAL");return bool(c.execute(text("SELECT security.consume_capability('concurrency-1',:t,'user123','apas','regulatory_search','READ','FEDERAL','regulatory-research','INTERNAL')"),{"t":ALPHA}).scalar())
        finally:e.dispose()
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(spend,range(2)))
    assert sorted(results)==[False,True]

def test_persisted_evidence_package_tampering_fails_signature():
    if not ADMIN:pytest.skip("TEST_ADMIN_DATABASE_URL not configured")
    from app.db.repositories.postgres_runtime import PostgresEvidencePackageRepository
    from app.signing.evidence_package import Ed25519SigningKey,EvidencePackageService
    key=Ed25519SigningKey();service=EvidencePackageService(key);request=uuid4();package=service.issue(tenant_id=ALPHA,request_id=request,answer_classification="PUBLIC",jurisdiction="FEDERAL",question="q",answer="a",claims=[],evidence=[],document_versions=[],policy_versions=["p"],model_manifest={},temporal_parameters={},audit_checkpoint="h")
    e=create_engine(URL)
    with e.begin() as c:
        context(c);PostgresEvidencePackageRepository(c).save(package)
    admin=create_engine(ADMIN)
    with admin.begin() as c:c.execute(text("UPDATE provenance.answer_packages SET package=jsonb_set(package,'{answer_hash}','\"tampered\"') WHERE id=:id"),{"id":package.package_id})
    admin.dispose()
    with e.begin() as c:context(c);loaded=PostgresEvidencePackageRepository(c).get(package.package_id);assert service.verify(loaded) is False
    e.dispose()

def test_persisted_capability_revocation_is_global():
    if not ADMIN:pytest.skip("TEST_ADMIN_DATABASE_URL not configured")
    admin=create_engine(ADMIN)
    with admin.begin() as c:c.execute(text("UPDATE security.capability_tokens SET calls_used=0,revoked_at=now() WHERE nonce='concurrency-1'"))
    admin.dispose()
    assert scalar("SELECT security.consume_capability('concurrency-1',:t,'user123','apas','regulatory_search','READ','FEDERAL','regulatory-research','INTERNAL')",{"t":ALPHA}) is False
