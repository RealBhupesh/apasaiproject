from __future__ import annotations

import math
import re
from datetime import date, datetime
from uuid import uuid4

from app.db.repositories.memory import MemoryStore
from app.retrieval.models import Evidence, EvidenceSet
from app.security.context import Decision, Operation, ProtectedResource, SecurityContext
from app.security.policies import PolicyEngine
from app.temporal.resolver import resolve_chunks

_WORD = re.compile(r"[a-z0-9]+")


def _score(query: str, text: str) -> float:
    q, t = set(_WORD.findall(query.lower())), set(_WORD.findall(text.lower()))
    return len(q & t) / math.sqrt(max(1, len(q) * len(t)))


def secure_retrieve(
    query: str,
    security_context: SecurityContext,
    jurisdiction: str,
    as_of_date: date,
    store: MemoryStore,
    policy: PolicyEngine,
    known_at: datetime | None = None,
    limit: int = 8,
) -> EvidenceSet:
    """Security filters are applied before scoring or result-count construction."""
    candidates = [
        c for c in store.chunks.values()
        if c.tenant_id == security_context.tenant_id and c.jurisdiction == jurisdiction
    ]
    candidates = resolve_chunks(candidates, store.versions, as_of_date, known_at)
    allowed, decisions = [], []
    for chunk in candidates:
        decision = policy.authorize(
            security_context,
            ProtectedResource("chunk", str(chunk.id), chunk.tenant_id, chunk.classification, chunk.jurisdiction),
            Operation.SEARCH,
        )
        # Denials are persisted for security/audit review but are not returned to the
        # requesting principal: even denied IDs/counts can disclose protected metadata.
        if decision.decision == Decision.ALLOW:
            decisions.append(decision)
            allowed.append(chunk)
    ranked = sorted(((_score(query, c.text), c) for c in allowed), reverse=True, key=lambda x: x[0])
    evidence: list[Evidence] = []
    source_versions: list[str] = []
    for score, chunk in ranked[:limit]:
        # Fail closed on weak semantic/keyword matches; low-relevance evidence must not
        # be promoted merely because it is the best authorized row.
        if score < 0.40:
            continue
        version = store.versions[chunk.document_version_id]
        doc = store.documents[version.source_document_id]
        evidence.append(Evidence(uuid4(), chunk.id, doc.id, version.id, chunk.text, chunk.section, chunk.page, chunk.jurisdiction, score))
        source_versions.append(version.version)
    return EvidenceSet(
        request_id=security_context.request_id or uuid4(), tenant_id=security_context.tenant_id,
        jurisdiction=jurisdiction, as_of_date=as_of_date, document_passages=evidence,
        source_versions=source_versions, security_decisions=decisions,
    )
