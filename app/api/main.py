from __future__ import annotations

from dataclasses import asdict
from datetime import date, datetime, timezone
from uuid import UUID, uuid4

from fastapi import FastAPI, Header, HTTPException
from sqlalchemy import text
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.audit.ledger import AuditLedger
from app.config import RuntimeMode, Settings
from app.auth.demo import authenticate_demo, demo_identities
from app.db.repositories.memory import MemoryStore
from app.db.seed import ALPHA, seed_demo
from app.db.repositories.postgres_runtime import PostgresAuditRepository, PostgresEvidencePackageRepository, PostgresProvenanceRepository, PostgresReviewRepository
from app.db.rls.context import set_local_security_context
from app.graph.repository import SecureGraphRepository
from app.human_review.service import ReviewService, ReviewStatus
from app.orchestration.workflow import DefensibleGraphRAG
from app.provenance.service import ProvenanceService
from app.security.capabilities import Capability
from app.security.context import Classification, Operation
from app.security.context import Decision, ProtectedResource
from app.security.policies import PolicyEngine
from app.runtime import ProductionRuntime
from app.signing.evidence_package import Ed25519SigningKey, EvidencePackageService

settings = Settings.from_env()
production_runtime = ProductionRuntime(settings) if settings.runtime_mode == RuntimeMode.PRODUCTION else None

# Demo components are never consulted by production endpoints.
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

app = FastAPI(title="APAS Defensible GraphRAG", version="4.1.0")


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    identity: str | None = None  # accepted only in explicit demo mode
    tenant_id: UUID | None = None  # production selection; validated by membership authority
    jurisdiction: str = Field(pattern=r"^[A-Z][A-Z0-9-]{1,31}$")
    as_of_date: date
    known_at: datetime | None = None
    purpose: str = Field(default="regulatory-research", min_length=3, max_length=100)


@app.get("/")
def ui():
    return FileResponse("app/ui/index.html")


@app.get("/review-console")
def review_console():
    return FileResponse("app/ui/reviews.html")


@app.get("/health")
def health():
    if settings.runtime_mode == RuntimeMode.PRODUCTION:
        try:
            with production_runtime.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:
            raise HTTPException(503, "Production security dependency unavailable") from None
    return {"status": "ok", "version": "4.1.0", "runtime_mode": settings.runtime_mode, "security_authority": "postgresql" if production_runtime else "demo-memory"}


@app.get("/demo/identities")
def identities():
    if settings.runtime_mode != RuntimeMode.DEMO:
        raise HTTPException(404, "Not found")
    return {"mode": "DEMO SECURITY MODE", "identities": demo_identities()}


@app.get("/ontology")
def ontology():
    return {
        "entities": ["Authority", "Jurisdiction", "Regulation", "Requirement", "Facility", "Utility", "Contaminant", "Measurement", "Violation", "Deadline", "Document", "DocumentVersion", "Claim", "Evidence", "Agent", "ModelRun"],
        "relationships": sorted(graph.ALLOWED_PREDICATES),
    }


def _bearer(value: str | None) -> str:
    if not value or not value.startswith("Bearer ") or len(value) < 20:
        raise HTTPException(403, "Request denied by policy")
    return value[7:]


@app.post("/ask")
def ask(body: AskRequest, authorization: str | None = Header(None), x_capability_token: str | None = Header(None)):
    try:
        if settings.runtime_mode == RuntimeMode.PRODUCTION:
            if body.identity is not None:
                raise PermissionError("demo identity forbidden")
            result = production_runtime.ask(
                bearer_token=_bearer(authorization), question=body.question,
                jurisdiction=body.jurisdiction, as_of=body.as_of_date,
                known_at=body.known_at, purpose=body.purpose,
                selected_tenant=body.tenant_id, capability_token=x_capability_token,
            )
            return asdict(result)
        if not body.identity:
            raise PermissionError("demo identity required")
        request_id = uuid4()
        context = authenticate_demo(body.identity, request_id, "regulatory_search" if "agent" in body.identity else None)
        if body.jurisdiction not in context.jurisdictions:
            raise PermissionError("jurisdiction not allowed")
        return asdict(workflow.ask(body.question, context, body.jurisdiction, body.as_of_date, body.known_at))
    except (PermissionError, ValueError):
        raise HTTPException(403, "Request denied by policy") from None


def _context(identity: str, request_id: UUID):
    if settings.runtime_mode != RuntimeMode.DEMO:
        raise HTTPException(403, "Request denied by policy")
    try:
        return authenticate_demo(identity, request_id)
    except PermissionError:
        raise HTTPException(403, "Request denied by policy") from None


@app.get("/claims/{claim_id}/provenance")
def claim_provenance(claim_id: UUID, x_demo_identity: str | None = Header(None), authorization: str | None = Header(None), x_tenant_id: UUID | None = Header(None)):
    try:
        if settings.runtime_mode == RuntimeMode.PRODUCTION:
            context=production_runtime.auth.authenticate(_bearer(authorization),uuid4(),"provenance",x_tenant_id)
            with production_runtime.engine.begin() as connection:
                set_local_security_context(connection,context)
                return PostgresProvenanceRepository(connection).load_claim_transitively(claim_id)
        return provenance.get_claim_provenance(claim_id, _context(x_demo_identity or "", uuid4()))
    except (KeyError, PermissionError):
        raise HTTPException(404, "Resource not found") from None


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
def audit_verify(x_demo_identity: str | None = Header(None), authorization: str | None = Header(None), x_tenant_id: UUID | None = Header(None)):
    if settings.runtime_mode == RuntimeMode.PRODUCTION:
        try:
            context=production_runtime.auth.authenticate(_bearer(authorization),uuid4(),"audit",x_tenant_id)
            if not ({"admin","auditor","security_admin"}&context.roles):raise PermissionError("denied")
            with production_runtime.engine.begin() as connection:
                set_local_security_context(connection,context)
                return PostgresAuditRepository(connection).verify_tenant(context)
        except PermissionError:
            raise HTTPException(403,"Request denied by policy") from None
    context = _context(x_demo_identity or "", uuid4())
    if not ({"admin", "auditor", "security_admin"} & context.roles):
        raise HTTPException(403, "Request denied by policy")
    result=ledger.verify_audit_chain(); result["tenant_id"]=str(context.tenant_id); result["chain_head"]=ledger.events[-1].event_hash if ledger.events else "GENESIS"; return result

class ReviewDecisionRequest(BaseModel):
    identity: str | None = None
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    rationale: str = Field(min_length=10, max_length=2000)


@app.get("/evidence-packages/{package_id}")
def evidence_package(package_id: UUID, x_demo_identity: str | None = Header(None), authorization: str | None = Header(None), x_tenant_id: UUID | None = Header(None)):
    if settings.runtime_mode == RuntimeMode.PRODUCTION:
        try:
            context=production_runtime.auth.authenticate(_bearer(authorization),uuid4(),"provenance",x_tenant_id)
            with production_runtime.engine.begin() as connection:
                set_local_security_context(connection,context)
                package=PostgresEvidencePackageRepository(connection).get(package_id)
                return {"package":asdict(package),"signature_valid":EvidencePackageService(production_runtime.key).verify(package)}
        except (PermissionError,KeyError):
            raise HTTPException(404,"Resource not found") from None
    package = store.evidence_packages.get(package_id)
    if not package:
        raise HTTPException(404, "Resource not found")
    context = _context(x_demo_identity or "", package.request_id)
    decision = policy.authorize(
        context,
        ProtectedResource("evidence_package", str(package_id), package.tenant_id,
                          Classification[package.answer_classification], package.jurisdiction),
        Operation.PROVENANCE,
    )
    if decision.decision != Decision.ALLOW:
        raise HTTPException(404, "Resource not found")
    return {"package": asdict(package), "signature_valid": package_service.verify(package)}


@app.get("/reviews")
def reviews(x_demo_identity: str | None = Header(None), authorization: str | None = Header(None), x_tenant_id: UUID | None = Header(None)):
    if settings.runtime_mode == RuntimeMode.PRODUCTION:
        try:
            context=production_runtime.auth.authenticate(_bearer(authorization),uuid4(),"human-review",x_tenant_id)
            if not ({"reviewer","admin","security_admin"}&context.roles):raise PermissionError("denied")
            with production_runtime.engine.begin() as connection:
                set_local_security_context(connection,context); return {"reviews":PostgresReviewRepository(connection).list_authorized()}
        except PermissionError:raise HTTPException(403,"Request denied by policy") from None
    context = _context(x_demo_identity or "", uuid4())
    if not ({"reviewer","admin","security_admin"}&context.roles):raise HTTPException(403,"Request denied by policy")
    rows = [asdict(c) for c in review_service.cases.values() if c.tenant_id == context.tenant_id and c.classification <= int(context.clearance) and c.jurisdiction in context.jurisdictions]
    return {"reviews": rows}


@app.post("/reviews/{case_id}/decision")
def decide_review(case_id: UUID, body: ReviewDecisionRequest, authorization: str | None = Header(None), x_tenant_id: UUID | None = Header(None)):
    if settings.runtime_mode == RuntimeMode.PRODUCTION:
        try:
            if body.identity is not None:raise PermissionError("demo identity forbidden")
            context=production_runtime.auth.authenticate(_bearer(authorization),uuid4(),"human-review",x_tenant_id)
            if not ({"reviewer","admin","security_admin"}&context.roles):raise PermissionError("denied")
            with production_runtime.engine.begin() as connection:
                set_local_security_context(connection,context); result=PostgresReviewRepository(connection).decide(case_id,context,body.decision,body.rationale); PostgresAuditRepository(connection).append(context,"HUMAN_REVIEW_DECIDED",str(case_id),{"decision":body.decision}); return result
        except (PermissionError,ValueError):raise HTTPException(403,"Request denied by policy") from None
    context = _context(body.identity or "", uuid4())
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
