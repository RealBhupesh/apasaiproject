from __future__ import annotations
from dataclasses import dataclass,field
from datetime import datetime,timezone
from enum import StrEnum
from typing import Any
from uuid import UUID,uuid4
class ReviewStatus(StrEnum):OPEN="OPEN";APPROVED="APPROVED";REJECTED="REJECTED"
@dataclass(frozen=True)
class ReviewVote:
    reviewer:str; decision:ReviewStatus; rationale:str; timestamp:datetime=field(default_factory=lambda:datetime.now(timezone.utc))
@dataclass
class ReviewCase:
    tenant_id:UUID; request_id:UUID; reason:str; evidence:list[dict[str,Any]]; conflict:dict[str,Any]; requested_by:str; classification:int
    jurisdiction:str="FEDERAL"; id:UUID=field(default_factory=uuid4); status:ReviewStatus=ReviewStatus.OPEN; votes:list[ReviewVote]=field(default_factory=list); rationale:str|None=None; created_at:datetime=field(default_factory=lambda:datetime.now(timezone.utc)); decided_at:datetime|None=None
    @property
    def reviewers(self)->list[str]:return [v.reviewer for v in self.votes]
class ReviewService:
    def __init__(self):self.cases:dict[UUID,ReviewCase]={}
    def request(self,case:ReviewCase)->ReviewCase:self.cases[case.id]=case;return case
    def decide(self,case_id:UUID,reviewer:str,decision:ReviewStatus,rationale:str,*,require_dual:bool=True)->ReviewCase:
        case=self.cases[case_id]
        if case.status!=ReviewStatus.OPEN:raise ValueError("case already decided")
        if reviewer==case.requested_by:raise PermissionError("requester cannot approve own case")
        if reviewer in case.reviewers:raise PermissionError("reviewer already voted")
        if decision not in {ReviewStatus.APPROVED,ReviewStatus.REJECTED}:raise ValueError("invalid final decision")
        case.votes.append(ReviewVote(reviewer,decision,rationale))
        if decision==ReviewStatus.REJECTED:
            case.status,case.rationale,case.decided_at=ReviewStatus.REJECTED,rationale,datetime.now(timezone.utc)
        elif not require_dual or len([v for v in case.votes if v.decision==ReviewStatus.APPROVED])>=2:
            case.status,case.rationale,case.decided_at=ReviewStatus.APPROVED,rationale,datetime.now(timezone.utc)
        else:case.rationale="awaiting second independent approval"
        return case
