from __future__ import annotations
import base64,json
from dataclasses import asdict,dataclass
from datetime import datetime,timezone
from typing import Protocol
from uuid import UUID
from sqlalchemy import Connection,text
from app.signing.evidence_package import SigningKey,canonical_json
@dataclass(frozen=True)
class CapabilityClaims:
    subject:str; tenant_id:UUID; tools:tuple[str,...]; operations:tuple[str,...]; jurisdictions:tuple[str,...]; max_classification:int; purpose:str; audience:str; expires_at:datetime; nonce:str; delegation_depth:int=0; max_calls:int=100
class CapabilityState(Protocol):
    def consume(self,claims:CapabilityClaims)->None:...
    def revoke(self,nonce:str)->None:...
class InMemoryCapabilityState:
    def __init__(self): self.revoked:set[str]=set(); self.usage:dict[str,int]={}
    def consume(self,claims:CapabilityClaims)->None:
        if claims.nonce in self.revoked or self.usage.get(claims.nonce,0)>=claims.max_calls: raise PermissionError("capability denied")
        self.usage[claims.nonce]=self.usage.get(claims.nonce,0)+1
    def revoke(self,nonce:str)->None:self.revoked.add(nonce)
class PostgresCapabilityState:
    CONSUME=text("SELECT security.consume_capability(:nonce,:tenant,:subject,:audience,:tool,:operation,:jurisdiction,:purpose,CAST(:classification AS security.classification))")
    def __init__(self,connection:Connection,*,audience:str,tool:str,operation:str,jurisdiction:str,purpose:str,requested_classification:int):
        self.connection=connection;self.binding={"audience":audience,"tool":tool,"operation":operation,"jurisdiction":jurisdiction,"purpose":purpose,"classification":["PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"][requested_classification]}
    def consume(self,claims:CapabilityClaims)->None:
        params={"nonce":claims.nonce,"tenant":claims.tenant_id,"subject":claims.subject}|self.binding
        if not self.connection.execute(self.CONSUME,params).scalar_one(): raise PermissionError("capability denied")
    def revoke(self,nonce:str)->None:raise PermissionError("revocation requires security administration")
class CapabilityTokenService:
    def __init__(self,key:SigningKey,state:CapabilityState|None=None,max_delegation_depth:int=0): self.key=key; self.state=state or InMemoryCapabilityState(); self.max_delegation_depth=max_delegation_depth
    def issue(self,claims:CapabilityClaims)->str:
        body=asdict(claims); body["tenant_id"]=str(claims.tenant_id); body["expires_at"]=claims.expires_at.isoformat(); payload=base64.urlsafe_b64encode(canonical_json(body)).decode().rstrip("="); sig=base64.urlsafe_b64encode(self.key.sign(payload.encode())).decode().rstrip("="); return f"{self.key.key_id}.{payload}.{sig}"
    def verify(self,token:str,*,subject:str,tenant_id:UUID,audience:str,tool:str,operation:str,jurisdiction:str,purpose:str,requested_classification:int)->CapabilityClaims:
        try:
            _,payload,sig=token.split(".",2); self.key.verify(payload.encode(),base64.urlsafe_b64decode(sig+"="*(-len(sig)%4))); body=json.loads(base64.urlsafe_b64decode(payload+"="*(-len(payload)%4))); claims=CapabilityClaims(**(body|{"tenant_id":UUID(body["tenant_id"]),"expires_at":datetime.fromisoformat(body["expires_at"]),"tools":tuple(body["tools"]),"operations":tuple(body["operations"]),"jurisdictions":tuple(body["jurisdictions"])}))
        except Exception as exc: raise PermissionError("capability denied") from exc
        valid=claims.subject==subject and claims.tenant_id==tenant_id and claims.audience==audience and tool in claims.tools and operation in claims.operations and jurisdiction in claims.jurisdictions and claims.purpose==purpose and requested_classification<=claims.max_classification and claims.expires_at>datetime.now(timezone.utc) and claims.delegation_depth<=self.max_delegation_depth
        if not valid: raise PermissionError("capability denied")
        self.state.consume(claims); return claims
    def revoke(self,nonce:str)->None:self.state.revoke(nonce)
