"""Live database tests. CI supplies TEST_DATABASE_URL for a non-owner apas_api_reader login."""
from __future__ import annotations

import os
from uuid import UUID

import pytest
from sqlalchemy import create_engine, text

URL=os.getenv("TEST_DATABASE_URL")
pytestmark=pytest.mark.skipif(not URL,reason="TEST_DATABASE_URL not configured")
ALPHA=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

@pytest.fixture
def conn():
    engine=create_engine(URL,pool_pre_ping=True)
    with engine.begin() as c:
        yield c
    engine.dispose()


def set_context(c,tenant=str(ALPHA),clearance="PUBLIC",jurisdictions="FEDERAL"):
    for name,value in {"app.tenant_id":tenant,"app.user_id":"live-test","app.clearance":clearance,"app.role":"viewer","app.jurisdictions":jurisdictions}.items():
        c.execute(text("SELECT set_config(:n,:v,true)"),{"n":name,"v":value})


def test_role_cannot_bypass_rls_or_own_database(conn):
    row=conn.execute(text("SELECT rolbypassrls,rolsuper FROM pg_roles WHERE rolname=current_user")).one()
    assert row == (False,False)
    assert conn.execute(text("SELECT pg_get_userbyid(datdba)=current_user FROM pg_database WHERE datname=current_database()" )).scalar() is False


def test_alpha_cannot_read_beta_chunks_vectors_graph_or_provenance(conn):
    set_context(conn)
    for table in ["documents.chunks","documents.embeddings","knowledge.relations","provenance.claims","provenance.answer_packages"]:
        assert conn.execute(text(f'SELECT count(*) FROM {table} WHERE tenant_id<>:t'),{"t":ALPHA}).scalar()==0


def test_clearance_blocks_metadata(conn):
    set_context(conn,clearance="PUBLIC")
    assert conn.execute(text("SELECT count(*) FROM documents.chunks WHERE security.classification_rank(classification)>0")).scalar()==0


def test_context_is_transaction_local():
    engine=create_engine(URL,pool_size=1,max_overflow=0)
    with engine.begin() as c: set_context(c)
    with engine.begin() as c:
        assert c.execute(text("SELECT current_setting('app.tenant_id',true)")).scalar() in (None,"")
    engine.dispose()
