from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID

from app.verification.claims import CandidateClaim


class Disposition(StrEnum):
    ANSWER = "ANSWER"
    ABSTAIN = "ABSTAIN"
    ESCALATE = "ESCALATE"


@dataclass
class Answer:
    request_id: UUID
    disposition: Disposition
    answer: str
    confidence: float
    claims: list[CandidateClaim]
    verification: list[Any]
    evidence: list[dict[str, Any]]
    graph_relations: list[dict[str, Any]]
    temporal_reasoning: str
    conflicts: list[dict[str, Any]]
    security_decisions: list[dict[str, Any]]
    trace: list[dict[str, Any]]
    audit_event_id: UUID
    answer_classification: str = "PUBLIC"
    evidence_package_id: UUID | None = None
    review_case_id: UUID | None = None
