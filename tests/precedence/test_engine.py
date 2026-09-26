from datetime import date
from uuid import uuid4
from app.precedence.engine import AuthorityLevel,Norm,PrecedenceEngine,Resolution


def n(level,value,**kw): return Norm(uuid4(),level,"X","deadline",value,date(2026,1,1),**kw)

def test_higher_explicit_authority_resolves():
    low,high=n(AuthorityLevel.STATE,"12"),n(AuthorityLevel.FEDERAL,"24")
    r=PrecedenceEngine().resolve([low,high],date(2026,6,1))
    assert r.resolution==Resolution.RESOLVED and r.winner==high.evidence_id

def test_same_level_ambiguity_escalates():
    r=PrecedenceEngine().resolve([n(AuthorityLevel.STATE,"12"),n(AuthorityLevel.STATE,"24")],date(2026,6,1))
    assert r.resolution==Resolution.ESCALATE
