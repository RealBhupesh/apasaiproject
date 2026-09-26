from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from uuid import UUID, uuid4

from app.security.decisions import AccessDecision


@dataclass(frozen=True)
class Evidence:
    id: UUID
    chunk_id: UUID
    document_id: UUID
    document_version_id: UUID
    text: str
    section: str
    page: int
    jurisdiction: str
    score: float
    tenant_id: UUID | None = None
    classification: str | None = None
    valid_from: date | None = None
    valid_to: date | None = None
    transaction_from: datetime | None = None
    transaction_to: datetime | None = None


@dataclass
class EvidenceSet:
    request_id: UUID
    tenant_id: UUID
    jurisdiction: str
    as_of_date: date
    facts: list[dict[str, Any]] = field(default_factory=list)
    graph_relations: list[dict[str, Any]] = field(default_factory=list)
    document_passages: list[Evidence] = field(default_factory=list)
    source_versions: list[str] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    security_decisions: list[AccessDecision] = field(default_factory=list)
    evidence_set_id: UUID = field(default_factory=uuid4)
    known_at: datetime | None = None
