from __future__ import annotations
import re
from dataclasses import asdict
from datetime import date,datetime,timezone
from app.db.repositories.postgres_runtime import PostgresAuditRepository,PostgresDocumentRepository,PostgresEvidencePackageRepository,PostgresGraphRepository,PostgresProvenanceRepository,PostgresReviewRepository,PostgresSecurityDecisionRepository
from app.llm.boundary import EvidenceOnlyComposer
from app.orchestration.models import Answer,Disposition
from app.precedence.engine import AuthorityLevel,Norm,PrecedenceEngine,Resolution
from app.security.context import Classification,SecurityContext
from app.signing.evidence_package import EvidencePackageService
from app.verification.claims import VerificationStatus
from app.verification.pipeline import VerificationPipeline
NORMATIVE=re.compile(r"\b(?:must|shall|required|within|deadline)\b",re.I)
class ProductionDefensibleGraphRAG:
    """Explicit production state machine. Every DB dependency shares one RLS transaction."""
    def __init__(self,documents:PostgresDocumentRepository,graph:PostgresGraphRepository,provenance:PostgresProvenanceRepository,audit:PostgresAuditRepository,decisions:PostgresSecurityDecisionRepository,packages:PostgresEvidencePackageRepository,reviews:PostgresReviewRepository,signer:EvidencePackageService):
        self.documents,self.graph,self.provenance,self.audit,self.decisions,self.packages,self.reviews=documents,graph,provenance,audit,decisions,packages,reviews
        self.signer=signer; self.composer=EvidenceOnlyComposer(); self.verifier=VerificationPipeline(); self.precedence=PrecedenceEngine()
    def ask(self,question:str,context:SecurityContext,jurisdiction:str,as_of:date,known_at:datetime)->Answer:
        trace=[]
        def step(node,outcome="ok"):trace.append({"node":node,"outcome":outcome,"at":datetime.now(timezone.utc).isoformat()})
        self.audit.append(context,"RETRIEVAL_STARTED",str(context.request_id),{"jurisdiction":jurisdiction,"as_of":as_of.isoformat()}); step("retrieval_started")
        evidence=self.documents.retrieve(question,context,jurisdiction,as_of,known_at)
        terms={w.lower() for w in re.findall(r"[a-zA-Z]{4,}",question)}; evidence.graph_relations=self.graph.query_template(context,jurisdiction,terms,as_of=as_of,known_at=known_at)
        for item in evidence.document_passages:self.decisions.save(context,"chunk",str(item.chunk_id),"SEARCH","ALLOW","RLS returned authorized row")
        self.audit.append(context,"RETRIEVAL_COMPLETED",str(context.request_id),{"evidence_count":len(evidence.document_passages),"graph_count":len(evidence.graph_relations)}); step("secured_retrieval")
        norms=[]
        for item in evidence.document_passages:
            if NORMATIVE.search(item.text):
                level=AuthorityLevel.FEDERAL if item.jurisdiction=="FEDERAL" else AuthorityLevel.STATE
                for number in re.findall(r"\b\d+(?:\.\d+)?\b",item.text):norms.append(Norm(item.id,level,item.jurisdiction,"requirement",number,as_of))
        resolution=self.precedence.resolve(norms,as_of)
        if resolution.resolution==Resolution.RESOLVED and resolution.winner:evidence.document_passages=[x for x in evidence.document_passages if x.id==resolution.winner]
        elif resolution.resolution==Resolution.ESCALATE:evidence.conflicts=[{"reason":resolution.rationale,"evidence_ids":[str(x) for x in resolution.considered]}]
        step("temporal_and_conflict",resolution.resolution)
        claims=[] if evidence.conflicts else self.composer.compose(question,evidence)
        for claim in claims:self.audit.append(context,"CLAIM_GENERATED",str(claim.id),{"evidence_ids":[str(x) for x in claim.evidence_ids]})
        results=[self.verifier.verify(c,evidence,context) for c in claims]
        for result in results:self.audit.append(context,"CLAIM_VERIFIED",str(result.claim_id),{"status":result.status})
        supported=[c for c,r in zip(claims,results) if r.status==VerificationStatus.SUPPORTED]
        if evidence.conflicts: disposition,text,confidence=Disposition.ESCALATE,"Conflicting applicable evidence requires human review.",0.0
        elif not supported: disposition,text,confidence=Disposition.ABSTAIN,"Insufficient authorized, temporally valid evidence.",0.0
        else: disposition,text,confidence=Disposition.ANSWER,"\n\n".join(c.text for c in supported),len(supported)/max(1,len(claims))
        level=max((Classification[x.classification] for x in evidence.document_passages if x.classification),default=Classification.PUBLIC)
        review_case_id=None
        if disposition==Disposition.ESCALATE:
            review_case_id=self.reviews.create(context,"unresolved regulatory conflict",evidence.conflicts[0],[x.id for x in evidence.document_passages],level.name,jurisdiction)
            self.audit.append(context,"HUMAN_REVIEW_CREATED",str(review_case_id),{"classification":level.name,"jurisdiction":jurisdiction})
        for claim,result in zip(claims,results):
            cited=[x for x in evidence.document_passages if x.id in claim.evidence_ids]
            lineage={"evidence":[{"chunk_id":str(x.chunk_id),"document_version_id":str(x.document_version_id),"document_id":str(x.document_id),"page":x.page,"section":x.section} for x in cited],"model":asdict(self.composer.model_run),"policy_versions":["postgres-rls-v1"],"verifier":list(result.verifier_chain)}
            self.provenance.save_claim(claim_id=claim.id,context=context,text=claim.text,status=str(result.status),classification=level.name,jurisdiction=jurisdiction,lineage=lineage)
        checkpoint=self.audit.append(context,"EVIDENCE_PACKAGE_SIGNING_STARTED",str(context.request_id),{"classification":level.name})["event_hash"]
        evidence_rows=[asdict(x) for x in evidence.document_passages]
        package=self.signer.issue(tenant_id=context.tenant_id,request_id=context.request_id,answer_classification=level.name,jurisdiction=jurisdiction,question=question,answer=text,claims=[asdict(x) for x in supported],evidence=evidence_rows,document_versions=[{"id":str(x.document_version_id)} for x in evidence.document_passages],policy_versions=["postgres-rls-v1"],model_manifest=asdict(self.composer.model_run),temporal_parameters={"valid_at":as_of.isoformat(),"known_at":known_at.isoformat()},audit_checkpoint=checkpoint)
        self.packages.save(package); self.audit.append(context,"EVIDENCE_PACKAGE_SIGNED",str(package.package_id),{"key_id":package.key_id})
        event_type={Disposition.ANSWER:"ANSWER_RELEASED",Disposition.ABSTAIN:"ANSWER_ABSTAINED",Disposition.ESCALATE:"ANSWER_ESCALATED"}[disposition]
        final=self.audit.append(context,event_type,str(context.request_id),{"classification":level.name,"package_id":str(package.package_id)}); step("committed_release",disposition)
        return Answer(context.request_id,disposition,text,confidence,supported,results,evidence_rows,evidence.graph_relations,f"valid_at={as_of.isoformat()}; known_at={known_at.isoformat()}",evidence.conflicts,[],trace,final["id"],level.name,package.package_id,review_case_id)
