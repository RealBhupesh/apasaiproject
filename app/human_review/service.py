from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4


class ReviewStatus(StrEnum):
    OPEN = "OPEN"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass
class ReviewCase:
    tenant_id: UUID
    request_id: UUID
    reason: str
    evidence: list[dict[str, Any]]
    conflict: dict[str, Any]
    requested_by: str
    classification: int
    id: UUID = field(default_factory=uuid4)
    status: ReviewStatus = ReviewStatus.OPEN
    reviewers: list[str] = field(default_factory=list)
    rationale: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    decided_at: datetime | None = None


class ReviewService:
    def __init__(self): self.cases: dict[UUID, ReviewCase] = {}

    def request(self, case: ReviewCase) -> ReviewCase:
        self.cases[case.id] = case
        return case

    def decide(self, case_id: UUID, reviewer: str, decision: ReviewStatus, rationale: str, *, require_dual: bool = True) -> ReviewCase:
        case=self.cases[case_id]
        if case.status != ReviewStatus.OPEN: raise ValueError("case already decided")
        if reviewer == case.requested_by: raise PermissionError("requester cannot approve own case")
        if reviewer not in case.reviewers: case.reviewers.append(reviewer)
        if require_dual and len(case.reviewers) < 2:
            case.rationale = "awaiting second reviewer"
            return case
        if decision not in {ReviewStatus.APPROVED,ReviewStatus.REJECTED}: raise ValueError("invalid final decision")
        case.status,case.rationale,case.decided_at=decision,rationale,datetime.now(timezone.utc)
        return case
