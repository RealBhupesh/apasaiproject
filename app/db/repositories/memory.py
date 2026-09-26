from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from uuid import UUID

from app.security.context import Classification
from app.security.decisions import AccessDecision


@dataclass(frozen=True)
class Document:
    id: UUID
    tenant_id: UUID
    authority: str
    jurisdiction: str
    classification: Classification
    original_filename: str
    storage_uri: str
    sha256: str
    created_by: str
    created_at: datetime


@dataclass(frozen=True)
class DocumentVersion:
    id: UUID
    source_document_id: UUID
    version: str
    sha256: str
    effective_from: date
    effective_to: date | None
    transaction_from: datetime
    transaction_to: datetime | None
    parser_version: str = "synthetic-v1"


@dataclass(frozen=True)
class Chunk:
    id: UUID
    tenant_id: UUID
    document_version_id: UUID
    section: str
    page: int
    text: str
    classification: Classification
    content_hash: str
    jurisdiction: str
    embedding: tuple[float, ...] = ()


@dataclass
class MemoryStore:
    documents: dict[UUID, Document] = field(default_factory=dict)
    versions: dict[UUID, DocumentVersion] = field(default_factory=dict)
    chunks: dict[UUID, Chunk] = field(default_factory=dict)
    decisions: list[AccessDecision] = field(default_factory=list)
    traces: dict[UUID, list[dict[str, Any]]] = field(default_factory=dict)
    claims: dict[UUID, Any] = field(default_factory=dict)
    provenance: dict[UUID, dict[str, Any]] = field(default_factory=dict)
    evidence_packages: dict[UUID, Any] = field(default_factory=dict)

    def save_decision(self, decision: AccessDecision) -> None:
        self.decisions.append(decision)

    def decisions_for(self, request_id: UUID) -> list[AccessDecision]:
        return [d for d in self.decisions if d.request_id == request_id]
