from __future__ import annotations
import json
from dataclasses import asdict
from datetime import date,datetime
from typing import Any
from uuid import UUID,uuid4
from sqlalchemy import Connection,text
from app.retrieval.models import Evidence,EvidenceSet
from app.retrieval.postgres import secure_hybrid_query
from app.security.context import Classification,SecurityContext
from app.signing.evidence_package import SignedEvidencePackage,canonical_json,sha256

def deterministic_embedding(query:str,dimensions:int=1536)->list[float]:
    import hashlib
    digest=hashlib.sha256(query.encode()).digest(); values=[]
    for i in range(dimensions): values.append((digest[i%len(digest)]-127.5)/127.5)
    return values

class PostgresDocumentRepository:
    def __init__(self,connection:Connection):self.connection=connection
    def retrieve(self,query:str,context:SecurityContext,jurisdiction:str,as_of:date,known_at:datetime,limit:int=8)->EvidenceSet:
        vector="["+",".join(str(x) for x in deterministic_embedding(query))+"]"
        rows=secure_hybrid_query(self.connection,query=query,query_embedding=vector,jurisdiction=jurisdiction,as_of=as_of,known_at=known_at,limit=limit)
        evidence=[]
        for row in rows:
            evidence.append(Evidence(uuid4(),row["id"],row["document_id"],row["document_version_id"],row["text"],row["section"] or "unknown",row["page"] or 1,jurisdiction,float(row["combined_score"] or 0),context.tenant_id,str(row["classification"]),row["effective_from"],row["effective_to"],row["transaction_from"],row["transaction_to"]))
        return EvidenceSet(context.request_id,context.tenant_id,jurisdiction,as_of,document_passages=evidence,source_versions=[str(r["version"]) for r in rows],known_at=known_at)

class PostgresGraphRepository:
    SQL=text("""SELECT id,subject,predicate,object,source_chunk_id,classification,jurisdiction FROM knowledge.relations WHERE tenant_id=current_setting('app.tenant_id')::uuid AND jurisdiction=:jurisdiction AND transaction_from<=:known_at AND (transaction_to IS NULL OR :known_at<transaction_to) AND valid_from<=:as_of AND (valid_to IS NULL OR :as_of<valid_to) ORDER BY id LIMIT :limit""")
    def __init__(self,connection:Connection):self.connection=connection
    def query_template(self,context:SecurityContext,jurisdiction:str,terms:set[str],limit:int=50,as_of:date|None=None,known_at:datetime|None=None)->list[dict[str,Any]]:
        rows=self.connection.execute(self.SQL,{"jurisdiction":jurisdiction,"limit":limit,"as_of":as_of or date.today(),"known_at":known_at or datetime.now().astimezone()}).mappings().all(); output=[]
        for r in rows:
            hay=f'{r["subject"]} {r["predicate"]} {r["object"]}'.lower()
            if not terms or any(t.lower() in hay for t in terms): output.append(dict(r))
        return output

class PostgresSecurityDecisionRepository:
    SQL=text("""INSERT INTO security.access_decisions(request_id,tenant_id,actor_type,actor_id,resource_type,resource_id,operation,decision,reason,policy_version,created_by) VALUES(:request,:tenant,:actor_type,:actor,:resource_type,:resource_id,:operation,CAST(:decision AS security.access_decision_value),:reason,'runtime-v1',:actor)""")
    def __init__(self,connection:Connection):self.connection=connection
    def save(self,context:SecurityContext,resource_type:str,resource_id:str,operation:str,decision:str,reason:str)->None:
        self.connection.execute(self.SQL,{"request":context.request_id,"tenant":context.tenant_id,"actor_type":context.actor_type,"actor":context.actor_id,"resource_type":resource_type,"resource_id":resource_id,"operation":operation,"decision":decision,"reason":reason})

class PostgresAuditRepository:
    APPEND=text("SELECT (audit.append_event(:tenant,:actor,:event_type,:resource,:request,CAST(:metadata AS jsonb),:actor)).*")
    def __init__(self,connection:Connection):self.connection=connection
    def append(self,context:SecurityContext,event_type:str,resource:str,metadata:dict[str,Any])->dict[str,Any]:
        row=self.connection.execute(self.APPEND,{"tenant":context.tenant_id,"actor":context.actor_id,"event_type":event_type,"resource":resource,"request":context.request_id,"metadata":json.dumps(metadata)}).mappings().one(); return dict(row)
    def verify_tenant(self,context:SecurityContext)->dict[str,Any]:
        rows=self.connection.execute(text("""SELECT sequence,previous_hash,event_hash,encode(public.digest(event_payload::text||previous_hash,'sha256'),'hex') expected_hash,lag(event_hash) OVER(ORDER BY sequence) prior_hash FROM audit.events WHERE tenant_id=:t ORDER BY sequence"""),{"t":context.tenant_id}).mappings().all(); previous="0"*64
        for row in rows:
            linked=(row["previous_hash"]==(row["prior_hash"] or "0"*64))
            if not linked or row["event_hash"]!=row["expected_hash"]:return {"valid":False,"tenant_id":str(context.tenant_id),"events_checked":row["sequence"]-1,"chain_head":previous}
            previous=row["event_hash"]
        return {"valid":True,"tenant_id":str(context.tenant_id),"events_checked":len(rows),"chain_head":previous}

class PostgresProvenanceRepository:
    def __init__(self,connection:Connection):self.connection=connection
    def save_claim(self,*,claim_id:UUID,context:SecurityContext,claim_text:str,status:str,classification:str,jurisdiction:str,lineage:dict[str,Any])->None:
        self.connection.execute(text("""INSERT INTO provenance.claims(id,tenant_id,request_id,text,status,classification,jurisdiction,lineage,created_by) VALUES(:id,:tenant,:request,:text,:status,CAST(:classification AS security.classification),:jurisdiction,CAST(:lineage AS jsonb),:actor)"""),{"id":claim_id,"tenant":context.tenant_id,"request":context.request_id,"text":claim_text,"status":status,"classification":classification,"jurisdiction":jurisdiction,"lineage":json.dumps(lineage),"actor":context.actor_id})
    def load_claim_transitively(self,claim_id:UUID)->dict[str,Any]:
        claim=self.connection.execute(text("SELECT id,text,status,lineage FROM provenance.claims WHERE id=:id"),{"id":claim_id}).mappings().one_or_none()
        if not claim: raise KeyError("not found")
        lineage=dict(claim["lineage"]); visible=[]
        for item in lineage.get("evidence",[]):
            row=self.connection.execute(text("""SELECT c.id chunk_id,c.section,c.page,v.id version_id,d.id document_id FROM documents.chunks c JOIN documents.document_versions v ON v.id=c.document_version_id JOIN documents.source_documents d ON d.id=v.source_document_id WHERE c.id=:id"""),{"id":item["chunk_id"]}).mappings().one_or_none()
            if not row: raise PermissionError("provenance unavailable")
            visible.append(dict(row))
        return {"claim_id":str(claim["id"]),"text":claim["text"],"status":claim["status"],"lineage":visible,"model":lineage.get("model"),"policy_versions":lineage.get("policy_versions",[])}

class PostgresEvidencePackageRepository:
    def __init__(self,connection:Connection):self.connection=connection
    def save(self,p:SignedEvidencePackage)->None:
        body=json.loads(canonical_json(asdict(p))); self.connection.execute(text("""INSERT INTO provenance.answer_packages(id,tenant_id,request_id,package,package_hash,signature,signing_key_id,classification,jurisdiction,created_by) VALUES(:id,:tenant,:request,CAST(:package AS jsonb),:hash,:signature,:key,CAST(:classification AS security.classification),:jurisdiction,'runtime')"""),{"id":p.package_id,"tenant":p.tenant_id,"request":p.request_id,"package":json.dumps(body),"hash":sha256(body),"signature":p.signature,"key":p.key_id,"classification":p.answer_classification,"jurisdiction":p.jurisdiction})
    def get(self,package_id:UUID)->SignedEvidencePackage:
        row=self.connection.execute(text("SELECT package FROM provenance.answer_packages WHERE id=:id"),{"id":package_id}).scalar_one_or_none()
        if not row: raise KeyError("not found")
        d=dict(row); d["package_id"]=UUID(d["package_id"]); d["tenant_id"]=UUID(d["tenant_id"]); d["request_id"]=UUID(d["request_id"]); d["issued_at"]=datetime.fromisoformat(d["issued_at"]); d["claim_hashes"]=tuple(d["claim_hashes"]); d["evidence_hashes"]=tuple(d["evidence_hashes"]); d["document_version_hashes"]=tuple(d["document_version_hashes"]); d["policy_versions"]=tuple(d["policy_versions"]); return SignedEvidencePackage(**d)

class PostgresReviewRepository:
    def __init__(self,connection:Connection):self.connection=connection
    def create(self,context:SecurityContext,reason:str,conflict:dict[str,Any],evidence_ids:list[UUID],classification:str,jurisdiction:str)->UUID:
        case_id=uuid4(); self.connection.execute(text("""INSERT INTO security.human_review_cases(id,tenant_id,request_id,status,reason,conflict,evidence_ids,classification,jurisdiction,requested_by,created_by) VALUES(:id,:tenant,:request,'OPEN',:reason,CAST(:conflict AS jsonb),:evidence,CAST(:classification AS security.classification),:jurisdiction,:actor,:actor)"""),{"id":case_id,"tenant":context.tenant_id,"request":context.request_id,"reason":reason,"conflict":json.dumps(conflict),"evidence":evidence_ids,"classification":classification,"jurisdiction":jurisdiction,"actor":context.actor_id}); return case_id
    def list_authorized(self)->list[dict[str,Any]]:
        return [dict(x) for x in self.connection.execute(text("SELECT id,request_id,status,reason,conflict,evidence_ids,classification,jurisdiction,requested_by,final_rationale,created_at,decided_at FROM security.human_review_cases ORDER BY created_at DESC LIMIT 100")).mappings().all()]
    def decide(self,case_id:UUID,context:SecurityContext,decision:str,rationale:str)->dict[str,Any]:
        case=self.connection.execute(text("SELECT * FROM security.human_review_cases WHERE id=:id FOR UPDATE"),{"id":case_id}).mappings().one_or_none()
        if not case or case["status"]!="OPEN" or case["requested_by"]==context.actor_id or str(case["classification"]) not in Classification.__members__ or Classification[str(case["classification"])]>context.clearance or case["jurisdiction"] not in context.jurisdictions:raise PermissionError("review denied")
        reviewer=self.connection.execute(text("SELECT user_id FROM security.identities WHERE issuer=:issuer AND subject=:subject AND tenant_id=:tenant AND active=true"),{"issuer":context.identity_issuer,"subject":context.actor_id,"tenant":context.tenant_id}).scalar_one_or_none()
        if not reviewer:raise PermissionError("review denied")
        self.connection.execute(text("""INSERT INTO security.human_review_decisions(tenant_id,case_id,reviewer_id,reviewer_subject,reviewer_issuer,decision,rationale,created_by) VALUES(:tenant,:case,:reviewer,:subject,:issuer,:decision,:rationale,:subject)"""),{"tenant":context.tenant_id,"case":case_id,"reviewer":reviewer,"subject":context.actor_id,"issuer":context.identity_issuer,"decision":"APPROVE" if decision=="APPROVED" else "REJECT","rationale":rationale})
        votes=self.connection.execute(text("SELECT decision,count(*) n FROM security.human_review_decisions WHERE case_id=:id GROUP BY decision"),{"id":case_id}).mappings().all(); counts={x["decision"]:x["n"] for x in votes}
        status="REJECTED" if counts.get("REJECT",0)>0 else ("APPROVED" if counts.get("APPROVE",0)>=2 else "OPEN")
        if status!="OPEN":self.connection.execute(text("UPDATE security.human_review_cases SET status=:status,final_rationale=:rationale,decided_at=now() WHERE id=:id"),{"status":status,"rationale":rationale,"id":case_id})
        return {"id":str(case_id),"status":status,"approvals":counts.get("APPROVE",0),"rejections":counts.get("REJECT",0)}
