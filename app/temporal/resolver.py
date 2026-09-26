from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Iterable

from app.db.repositories.memory import Chunk, DocumentVersion


def applicable(version: DocumentVersion, valid_at: date, known_at: datetime | None = None) -> bool:
    known_at = known_at or datetime.now(timezone.utc)
    valid = version.effective_from <= valid_at and (
        version.effective_to is None or valid_at < version.effective_to
    )
    believed = version.transaction_from <= known_at and (
        version.transaction_to is None or known_at < version.transaction_to
    )
    return valid and believed


def resolve_chunks(
    chunks: Iterable[Chunk], versions: dict, valid_at: date, known_at: datetime | None = None
) -> list[Chunk]:
    return [c for c in chunks if applicable(versions[c.document_version_id], valid_at, known_at)]
