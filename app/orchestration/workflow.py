from __future__ import annotations

import re
from dataclasses import asdict
from datetime import date, datetime, timezone
from uuid import UUID

from app.audit.ledger import AuditLedger
from app.db.repositories.memory import MemoryStore
from app.graph.repository import SecureGraphRepository
from app.llm.boundary import EvidenceOnlyComposer
from app.orchestration.models import Answer, Disposition
from app.retrieval.secure import secure_retrieve
from app.security.capabilities import Capability, require_capability
from app.security.context import Operation, SecurityContext
from app.security.policies import PolicyEngine
from app.verification.claims import ClaimVerifier, VerificationStatus

NORMATIVE = re.compile(r"\b(?:must|shall|required|within|deadline)\b", re.I)


class DefensibleGraphRAG:
    STATES = (
        "authenticate", "authorize_request", "classify_query", "create_query_plan", "authorize_tools",
        "graph_retrieval", "document_retrieval", "build_evidence_set", "temporal_resolution",
        "conflict_detection", "compose_claims", "verify_claims", "policy_gate", "final_answer",
        "provenance", "audit",
    )

    def __init__(self, store: MemoryStore, policy: PolicyEngine, graph: SecureGraphRepository, ledger: AuditLedger, capability: Capability | None = None):
        self.store, self.policy, self.graph, self.ledger = store, policy, graph, ledger
        self.capability = capability
        self.composer = EvidenceOnlyComposer()
        self.verifier = ClaimVerifier()

    def _trace(self, request_id: UUID, node: str, outcome: str = "ok") -> None:
        self.store.traces.setdefault(request_id, []).append({
            "node": node, "outcome": outcome, "at": datetime.now(timezone.utc).isoformat()
        })

    def ask(self, question: str, context: SecurityContext, jurisdiction: str, as_of: date, known_at: datetime | None = None) -> Answer:
        request_id = context.request_id
        if request_id is None:
            raise ValueError("request_id required")
        for node in self.STATES[:4]: self._trace(request_id, node)
        if context.actor_type == "agent":
            if self.capability is None:
                raise PermissionError("agent has no capability")
            require_capability(self.capability, context, "graph_query", Operation.SEARCH)
            require_capability(self.capability, context, "regulatory_search", Operation.SEARCH)
        self._trace(request_id, "authorize_tools")
        terms = {w.lower() for w in re.findall(r"[a-zA-Z]{4,}", question)}
        relations = self.graph.query(context, jurisdiction, terms)
        self._trace(request_id, "graph_retrieval")
        es = secure_retrieve(question, context, jurisdiction, as_of, self.store, self.policy, known_at)
        es.graph_relations = [asdict(r) for r in relations]
        self._trace(request_id, "document_retrieval")
        self._trace(request_id, "build_evidence_set")
        self._trace(request_id, "temporal_resolution")

        # Conflict if authorized, applicable normative evidence disagrees on a number.
        numbers = {}
        for e in es.document_passages:
            if NORMATIVE.search(e.text):
                for n in re.findall(r"\b\d+(?:\.\d+)?\b", e.text): numbers.setdefault(n, []).append(str(e.id))
        if len(numbers) > 1:
            es.conflicts.append({"reason": "incompatible normative numeric requirements", "evidence_by_value": numbers})
        self._trace(request_id, "conflict_detection", "conflict" if es.conflicts else "clean")

        claims = [] if es.conflicts else self.composer.compose(question, es)
        self._trace(request_id, "compose_claims", f"{len(claims)} candidates")
        results = [self.verifier.verify(c, es) for c in claims]
        self._trace(request_id, "verify_claims")
        supported = [c for c, r in zip(claims, results) if r.status == VerificationStatus.SUPPORTED]
        if es.conflicts:
            disposition, text, confidence = Disposition.ESCALATE, "Conflicting applicable evidence requires human review.", 0.0
        elif not supported:
            disposition, text, confidence = Disposition.ABSTAIN, "Insufficient authorized, temporally valid evidence.", 0.0
        else:
            disposition, text = Disposition.ANSWER, "\n\n".join(c.text for c in supported)
            confidence = len(supported) / max(1, len(claims))
        self._trace(request_id, "policy_gate", disposition)
        self._trace(request_id, "final_answer")

        for claim, result in zip(claims, results):
            self.store.claims[claim.id] = claim
            ev = next((e for e in es.document_passages if e.id in claim.evidence_ids), None)
            if ev:
                chunk = self.store.chunks[ev.chunk_id]
                self.store.provenance[claim.id] = {
                    "tenant_id": context.tenant_id, "classification": chunk.classification,
                    "jurisdiction": jurisdiction, "claim_id": str(claim.id), "source_document_id": str(ev.document_id),
                    "document_version_id": str(ev.document_version_id), "chunk_id": str(ev.chunk_id),
                    "page": ev.page, "section": ev.section, "retrieval_run_id": str(es.evidence_set_id),
                    "query": question, "model": self.composer.model_run.model,
                    "model_version": self.composer.model_run.model_version,
                    "prompt_version": self.composer.model_run.prompt_version,
                    "policy_versions": sorted({d.policy_version for d in es.security_decisions}),
                    "verifier": result.verifier, "verification_status": result.status,
                }
        self._trace(request_id, "provenance")
        event = self.ledger.append(tenant_id=context.tenant_id, actor=context.actor_id, event_type="ANSWER_COMPLETED", resource=str(request_id), request_id=request_id, metadata={"disposition": disposition})
        self._trace(request_id, "audit")
        return Answer(
            request_id, disposition, text, confidence, supported, results,
            [asdict(e) for e in es.document_passages], es.graph_relations,
            f"valid_at={as_of.isoformat()}; known_at={(known_at or datetime.now(timezone.utc)).isoformat()}",
            es.conflicts, [asdict(d) for d in es.security_decisions], self.store.traces[request_id], event.id,
        )
