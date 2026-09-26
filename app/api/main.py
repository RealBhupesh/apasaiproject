from __future__ import annotations

from dataclasses import asdict
from datetime import date, datetime, timezone
from uuid import UUID, uuid4

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.audit.ledger import AuditLedger
from app.auth.demo import authenticate_demo, demo_identities
from app.db.repositories.memory import MemoryStore
from app.db.seed import ALPHA, seed_demo
from app.graph.repository import SecureGraphRepository
from app.human_review.service import ReviewService, ReviewStatus
from app.orchestration.workflow import DefensibleGraphRAG
from app.provenance.service import ProvenanceService
from app.security.capabilities import Capability
from app.security.context import Classification, Operation
from app.security.context import Decision, ProtectedResource
from app.security.policies import PolicyEngine
from app.signing.evidence_package import Ed25519SigningKey, EvidencePackageService

store = MemoryStore()
policy = PolicyEngine(store.save_decision)
relations = seed_demo(store)
ledger = AuditLedger()
graph = SecureGraphRepository(relations, policy)
demo_agent_capability = Capability(
    agent="compliance-assistant", tenant_id=ALPHA,
    tools=frozenset({"regulatory_search", "graph_query"}), operations=frozenset({Operation.SEARCH}),
    max_classification=Classification.INTERNAL,
    expires_at=datetime(2100, 1, 1, tzinfo=timezone.utc),
)
signing_key = Ed25519SigningKey()
package_service = EvidencePackageService(signing_key)
review_service = ReviewService()
workflow = DefensibleGraphRAG(store, policy, graph, ledger, demo_agent_capability, package_service, review_service)
provenance = ProvenanceService(store, policy)

app = FastAPI(title="APAS Defensible GraphRAG", version="4.0.0")


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    identity: str
    jurisdiction: str = Field(pattern=r"^[A-Z][A-Z0-9-]{1,31}$")
    as_of_date: date
    known_at: datetime | None = None


@app.get("/")
def ui():
    return FileResponse("app/ui/index.html")


@app.get("/review-console")
def review_console():
    return FileResponse("app/ui/reviews.html")


@app.get("/health")
def health():
    return {"status": "ok", "version": "4.0.0", "security_authority": "postgresql-ready"}


@app.get("/demo/identities")
def identities():
    return {"identities": demo_identities()}


@app.get("/ontology")
def ontology():
    return {
        "entities": ["Authority", "Jurisdiction", "Regulation", "Requirement", "Facility", "Utility", "Contaminant", "Measurement", "Violation", "Deadline", "Document", "DocumentVersion", "Claim", "Evidence", "Agent", "ModelRun"],
        "relationships": sorted(graph.ALLOWED_PREDICATES),
    }


@app.post("/ask")
def ask(body: AskRequest):
    request_id = uuid4()
    try:
        context = authenticate_demo(body.identity, request_id, "regulatory_search" if "agent" in body.identity else None)
        if body.jurisdiction not in context.jurisdictions:
            raise PermissionError("jurisdiction not allowed")
        return asdict(workflow.ask(body.question, context, body.jurisdiction, body.as_of_date, body.known_at))
    except PermissionError:
        raise HTTPException(403, "Request denied by policy") from None


def _context(identity: str, request_id: UUID):
    try:
        return authenticate_demo(identity, request_id)
    except PermissionError:
        raise HTTPException(403, "Request denied by policy") from None


@app.get("/claims/{claim_id}/provenance")
def claim_provenance(claim_id: UUID, x_demo_identity: str = Header(...)):
    try:
        return provenance.get_claim_provenance(claim_id, _context(x_demo_identity, uuid4()))
    except KeyError:
        raise HTTPException(404, "Claim not found") from None
    except PermissionError:
        raise HTTPException(403, "Provenance denied") from None


@app.get("/requests/{request_id}/trace")
def request_trace(request_id: UUID, x_demo_identity: str = Header(...)):
    context = _context(x_demo_identity, request_id)
    matching = [d for d in store.decisions_for(request_id) if d.tenant_id == context.tenant_id]
    if not matching: raise HTTPException(404, "Request not found")
    return {"request_id": request_id, "trace": store.traces.get(request_id, [])}


@app.get("/security/decisions/{request_id}")
def security_decisions(request_id: UUID, x_demo_identity: str = Header(...)):
    context = _context(x_demo_identity, request_id)
    if not ({"admin", "auditor", "security_admin"} & context.roles):
        raise HTTPException(403, "Security decision access denied")
    rows = [asdict(d) for d in store.decisions_for(request_id) if d.tenant_id == context.tenant_id]
    if not rows: raise HTTPException(404, "Request not found")
    return {"request_id": request_id, "decisions": rows}


@app.get("/audit/verify")
def audit_verify(x_demo_identity: str = Header(...)):
    context = _context(x_demo_identity, uuid4())
    if not ({"admin", "auditor", "security_admin"} & context.roles):
        raise HTTPException(403, "Audit verification denied")
    return ledger.verify_audit_chain()

class ReviewDecisionRequest(BaseModel):
    identity: str
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    rationale: str = Field(min_length=10, max_length=2000)


@app.get("/evidence-packages/{package_id}")
def evidence_package(package_id: UUID, x_demo_identity: str = Header(...)):
    package = store.evidence_packages.get(package_id)
    if not package:
        raise HTTPException(404, "Evidence package not found")
    context = _context(x_demo_identity, package.request_id)
    decision = policy.authorize(
        context,
        ProtectedResource("evidence_package", str(package_id), package.tenant_id,
                          Classification[package.answer_classification], package.jurisdiction),
        Operation.PROVENANCE,
    )
    if decision.decision != Decision.ALLOW:
        raise HTTPException(403, "Evidence package denied")
    return {"package": asdict(package), "signature_valid": package_service.verify(package)}


@app.get("/reviews")
def reviews(x_demo_identity: str = Header(...)):
    context = _context(x_demo_identity, uuid4())
    rows = [asdict(c) for c in review_service.cases.values()
            if c.tenant_id == context.tenant_id and c.classification <= int(context.clearance)]
    return {"reviews": rows}


@app.post("/reviews/{case_id}/decision")
def decide_review(case_id: UUID, body: ReviewDecisionRequest):
    context = _context(body.identity, uuid4())
    if not ({"admin", "security_admin"} & context.roles):
        raise HTTPException(403, "Human review decision denied")
    case = review_service.cases.get(case_id)
    if not case or case.tenant_id != context.tenant_id or case.classification > int(context.clearance):
        raise HTTPException(404, "Review case not found")
    try:
        updated = review_service.decide(case_id, context.actor_id, ReviewStatus(body.decision), body.rationale)
        return asdict(updated)
    except (PermissionError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from None
