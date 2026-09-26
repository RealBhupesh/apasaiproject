from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from app.retrieval.models import EvidenceSet
from app.verification.claims import CandidateClaim, VerificationStatus


class EntailmentVerifier(Protocol):
    name: str
    def entails(self, claim: str, passages: list[str]) -> bool: ...


class ConservativeLexicalNLI:
    name="conservative-lexical-nli-v2"
    def entails(self, claim: str, passages: list[str]) -> bool:
        stop={"this","that","with","from","into","must","shall"}
        words={x for x in re.findall(r"[a-z]+",claim.lower()) if len(x)>3 and x not in stop}
        source=set(re.findall(r"[a-z]+"," ".join(passages).lower()))
        return len(words & source)/max(1,len(words)) >= .75


@dataclass(frozen=True)
class StageResult:
    stage: str
    passed: bool
    reason: str


@dataclass(frozen=True)
class PipelineVerification:
    claim_id: UUID
    status: VerificationStatus
    stages: tuple[StageResult,...]
    verifier_chain: tuple[str,...]


class VerificationPipeline:
    UNIT_PATTERN=re.compile(r"\b(\d+(?:\.\d+)?)\s*(hours?|days?|mg/L|ppm|percent|%)\b",re.I)

    def __init__(self, nli: EntailmentVerifier | None = None): self.nli=nli or ConservativeLexicalNLI()

    def verify(self, claim: CandidateClaim, evidence_set: EvidenceSet) -> PipelineVerification:
        evidence={e.id:e for e in evidence_set.document_passages}; stages=[]
        ids_ok=bool(claim.evidence_ids) and all(i in evidence for i in claim.evidence_ids)
        stages.append(StageResult("evidence_ids",ids_ok,"all cited evidence exists in authorized EvidenceSet" if ids_ok else "missing/fake evidence"))
        if not ids_ok: return PipelineVerification(claim.id,VerificationStatus.UNSUPPORTED,tuple(stages),(self.nli.name,))
        passages=[evidence[i].text for i in claim.evidence_ids]
        temporal=evidence_set.as_of_date is not None
        stages.append(StageResult("temporal",temporal,"EvidenceSet resolved for requested valid time"))
        claim_units=set(self.UNIT_PATTERN.findall(claim.text)); source_units=set(self.UNIT_PATTERN.findall(" ".join(passages)))
        units_ok={(v.lower(),u.lower()) for v,u in claim_units} <= {(v.lower(),u.lower()) for v,u in source_units}
        stages.append(StageResult("numeric_units",units_ok,"numbers and units align" if units_ok else "unsupported number or unit"))
        citation_ok=all(e.page>=1 and bool(e.section) for e in (evidence[i] for i in claim.evidence_ids))
        stages.append(StageResult("citation_alignment",citation_ok,"page and section available" if citation_ok else "citation span unavailable"))
        conflict_ok=not evidence_set.conflicts
        stages.append(StageResult("conflict",conflict_ok,"no unresolved conflict" if conflict_ok else "unresolved conflict"))
        entailed=self.nli.entails(claim.text,passages)
        stages.append(StageResult("independent_nli",entailed,"independent verifier entailed claim" if entailed else "independent verifier rejected claim"))
        passed=all(x.passed for x in stages)
        status=VerificationStatus.SUPPORTED if passed else (VerificationStatus.CONFLICTING if not conflict_ok else VerificationStatus.UNSUPPORTED)
        return PipelineVerification(claim.id,status,tuple(stages),(self.nli.name,))
