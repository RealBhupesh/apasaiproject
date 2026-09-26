from uuid import uuid4
import pytest
from app.human_review.service import ReviewCase,ReviewService,ReviewStatus

def case():
    s=ReviewService();return s,s.request(ReviewCase(uuid4(),uuid4(),"conflict",[],{},"requester",2))
def test_two_independent_approvals_required():
    s,c=case();assert s.decide(c.id,"reviewer-1",ReviewStatus.APPROVED,"first",require_dual=True).status==ReviewStatus.OPEN;assert s.decide(c.id,"reviewer-2",ReviewStatus.APPROVED,"second",require_dual=True).status==ReviewStatus.APPROVED;assert len(c.votes)==2
def test_any_rejection_finalizes_rejected():
    s,c=case();s.decide(c.id,"reviewer-1",ReviewStatus.APPROVED,"first");assert s.decide(c.id,"reviewer-2",ReviewStatus.REJECTED,"unsafe").status==ReviewStatus.REJECTED
def test_requester_and_duplicate_vote_denied():
    s,c=case()
    with pytest.raises(PermissionError):s.decide(c.id,"requester",ReviewStatus.APPROVED,"self")
    s.decide(c.id,"reviewer-1",ReviewStatus.APPROVED,"first")
    with pytest.raises(PermissionError):s.decide(c.id,"reviewer-1",ReviewStatus.APPROVED,"again")
