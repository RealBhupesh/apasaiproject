from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID, uuid4

from app.retrieval.models import EvidenceSet


class VerificationStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    CONFLICTING = "CONFLICTING"


@dataclass
class CandidateClaim:
    text: str
    evidence_ids: list[UUID]
    id: UUID = field(default_factory=uuid4)


@dataclass(frozen=True)
class VerificationResult:
    claim_id: UUID
    status: VerificationStatus
    reason: str
    verifier: str = "deterministic-verifier-v1"


class ClaimVerifier:
    """Fail-closed verifier. Production can add NLI, never replace deterministic checks."""

    @staticmethod
    def verify(claim: CandidateClaim, evidence_set: EvidenceSet) -> VerificationResult:
        evidence = {e.id: e for e in evidence_set.document_passages}
        if not claim.evidence_ids or any(eid not in evidence for eid in claim.evidence_ids):
            return VerificationResult(claim.id, VerificationStatus.UNSUPPORTED, "missing or fake evidence id")
        if evidence_set.conflicts:
            return VerificationResult(claim.id, VerificationStatus.CONFLICTING, "unresolved evidence conflict")
        passages = " ".join(evidence[eid].text.lower() for eid in claim.evidence_ids)
        claim_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", claim.text))
        source_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", passages))
        if not claim_numbers <= source_numbers:
            return VerificationResult(claim.id, VerificationStatus.UNSUPPORTED, "numeric value not in evidence")
        meaningful = {w for w in re.findall(r"[a-z]+", claim.text.lower()) if len(w) > 3}
        overlap = meaningful & set(re.findall(r"[a-z]+", passages))
        coverage = len(overlap) / max(1, len(meaningful))
        if coverage >= 0.7:
            return VerificationResult(claim.id, VerificationStatus.SUPPORTED, "entailed by authorized evidence")
        if coverage >= 0.4:
            return VerificationResult(claim.id, VerificationStatus.PARTIALLY_SUPPORTED, "partial lexical entailment")
        return VerificationResult(claim.id, VerificationStatus.UNSUPPORTED, "not entailed by evidence")
