from datetime import date, datetime, timezone
from uuid import uuid4

from app.db.repositories.memory import Chunk, Document, DocumentVersion
from app.orchestration.models import Disposition
from app.security.context import Classification
from tests.conftest import context


def test_conflicting_rules_escalate(workflow, system):
    store,_,_,_=system; tenant=context("alpha-analyst").tenant_id
    text="SYNTHETIC DEMO: Alpha facilities shall report a sample result within 12 hours."
    doc_id,ver_id,chunk_id=uuid4(),uuid4(),uuid4(); now=datetime(2026,1,1,tzinfo=timezone.utc)
    store.documents[doc_id]=Document(doc_id,tenant,"Synthetic State Authority","FEDERAL",Classification.INTERNAL,"conflict.txt","demo://conflict","0"*64,"test",now)
    store.versions[ver_id]=DocumentVersion(ver_id,doc_id,"1","0"*64,date(2026,1,1),None,now,None)
    store.chunks[chunk_id]=Chunk(chunk_id,tenant,ver_id,"conflict",1,text,Classification.INTERNAL,"0"*64,"FEDERAL")
    answer=workflow.ask("When must Alpha facilities report a sample result?",context("alpha-analyst"),"FEDERAL",date(2026,6,1))
    assert answer.disposition==Disposition.ESCALATE
    assert answer.conflicts
