from uuid import uuid4
from app.human_review.service import ReviewCase,ReviewService,ReviewStatus


def test_high_risk_review_requires_two_people():
    s=ReviewService(); c=s.request(ReviewCase(uuid4(),uuid4(),"conflict",[],{},"requester",2))
    assert s.decide(c.id,"reviewer-1",ReviewStatus.APPROVED,"first review",require_dual=True).status==ReviewStatus.OPEN
    assert s.decide(c.id,"reviewer-2",ReviewStatus.APPROVED,"confirmed",require_dual=True).status==ReviewStatus.APPROVED
