from __future__ import annotations

import re
from dataclasses import dataclass

from app.retrieval.models import EvidenceSet
from app.verification.claims import CandidateClaim

INJECTION_PATTERNS = re.compile(
    r"ignore (?:all |any )?(?:previous|prior|system) instructions|reveal .*customer|call the admin tool|"
    r"bypass (?:security|authorization)|system prompt",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ModelRun:
    model: str = "deterministic-demo-composer"
    model_version: str = "1"
    prompt_version: str = "v3-evidence-only"


class EvidenceOnlyComposer:
    """Demo structured-output boundary. Retrieved text is data, never instructions."""

    model_run = ModelRun()

    def compose(self, question: str, evidence_set: EvidenceSet) -> list[CandidateClaim]:
        del question
        claims: list[CandidateClaim] = []
        for e in evidence_set.document_passages[:3]:
            sanitized = INJECTION_PATTERNS.sub("[untrusted instruction removed]", e.text).strip()
            if sanitized and sanitized != "[untrusted instruction removed]":
                claims.append(CandidateClaim(sanitized, [e.id]))
        return claims
