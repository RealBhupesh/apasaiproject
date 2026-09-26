from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from app.retrieval.models import EvidenceSet
from app.security.context import Classification, SecurityContext
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
    DATE_PATTERN=re.compile(r"\b\d{4}-\d{2}-\d{2}\b")

    def __init__(self, nli: EntailmentVerifier | None = None): self.nli=nli or ConservativeLexicalNLI()

    def verify(self, claim: CandidateClaim, evidence_set: EvidenceSet, context: SecurityContext | None = None) -> PipelineVerification:
        evidence={e.id:e for e in evidence_set.document_passages}; stages=[]
        ids_ok=bool(claim.evidence_ids) and all(i in evidence for i in claim.evidence_ids)
        stages.append(StageResult("evidence_ids",ids_ok,"all cited evidence exists in authorized EvidenceSet" if ids_ok else "missing/fake evidence"))
        if not ids_ok: return PipelineVerification(claim.id,VerificationStatus.UNSUPPORTED,tuple(stages),(self.nli.name,))
        cited=[evidence[i] for i in claim.evidence_ids]
        binding=all(e.chunk_id and e.document_id and e.document_version_id for e in cited)
        stages.append(StageResult("document_version_binding",binding,"document, version and chunk IDs bound" if binding else "lineage binding missing"))
        authorized=True
        if context:
            authorized=all(e.tenant_id==context.tenant_id and (e.classification is None or Classification[e.classification]<=context.clearance) and e.jurisdiction in context.jurisdictions for e in cited)
        stages.append(StageResult("authorization",authorized,"tenant, classification and jurisdiction authorized" if authorized else "evidence authorization failed"))
        temporal=all((e.valid_from is None or e.valid_from<=evidence_set.as_of_date) and (e.valid_to is None or evidence_set.as_of_date<e.valid_to) and (e.transaction_from is None or evidence_set.known_at is None or e.transaction_from<=evidence_set.known_at) and (e.transaction_to is None or evidence_set.known_at is None or evidence_set.known_at<e.transaction_to) for e in cited)
        stages.append(StageResult("temporal",temporal,"valid and transaction time verified" if temporal else "evidence outside temporal range"))
        passages=[e.text for e in cited]
        claim_units=set(self.UNIT_PATTERN.findall(claim.text)); source_units=set(self.UNIT_PATTERN.findall(" ".join(passages)))
        units_ok={(v.lower(),u.lower()) for v,u in claim_units} <= {(v.lower(),u.lower()) for v,u in source_units}
        stages.append(StageResult("numeric_units",units_ok,"numbers and units align" if units_ok else "unsupported number or unit"))
        dates_ok=set(self.DATE_PATTERN.findall(claim.text))<=set(self.DATE_PATTERN.findall(" ".join(passages)))
        stages.append(StageResult("dates_deadlines",dates_ok,"dates are source-bound" if dates_ok else "unsupported date or deadline"))
        citation_ok=all(e.page>=1 and bool(e.section) for e in (evidence[i] for i in claim.evidence_ids))
        stages.append(StageResult("citation_alignment",citation_ok,"page and section available" if citation_ok else "citation span unavailable"))
        conflict_ok=not evidence_set.conflicts
        stages.append(StageResult("conflict",conflict_ok,"no unresolved conflict" if conflict_ok else "unresolved conflict"))
        entailed=self.nli.entails(claim.text,passages)
        stages.append(StageResult("independent_nli",entailed,"independent verifier entailed claim" if entailed else "independent verifier rejected claim"))
        passed=all(x.passed for x in stages)
        status=VerificationStatus.SUPPORTED if passed else (VerificationStatus.CONFLICTING if not conflict_ok else VerificationStatus.UNSUPPORTED)
        return PipelineVerification(claim.id,status,tuple(stages),(self.nli.name,))
