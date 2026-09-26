from datetime import date, datetime, timezone
from uuid import uuid4

from app.db.repositories.memory import DocumentVersion
from app.temporal.resolver import applicable


def test_valid_time_before_and_after_effective_date():
    v=DocumentVersion(uuid4(),uuid4(),"2","x",date(2027,1,1),None,datetime(2026,12,1,tzinfo=timezone.utc),None)
    assert not applicable(v,date(2026,6,1),datetime(2027,5,1,tzinfo=timezone.utc))
    assert applicable(v,date(2027,6,1),datetime(2027,5,1,tzinfo=timezone.utc))


def test_transaction_time_as_system_believed_then():
    v=DocumentVersion(uuid4(),uuid4(),"corrected","x",date(2027,1,1),None,datetime(2027,5,15,tzinfo=timezone.utc),None)
    assert not applicable(v,date(2027,6,1),datetime(2027,5,1,tzinfo=timezone.utc))
    assert applicable(v,date(2027,6,1),datetime(2027,6,1,tzinfo=timezone.utc))
