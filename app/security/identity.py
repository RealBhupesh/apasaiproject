from __future__ import annotations
from dataclasses import dataclass
from typing import Any,Protocol
from uuid import UUID
import jwt
from app.security.context import Classification,SecurityContext
class MembershipAuthority(Protocol):
    def resolve(self,issuer:str,subject:str,tenant_id:UUID|None=None)->"VerifiedMembership":...
@dataclass(frozen=True)
class VerifiedMembership:
    issuer:str; subject:str; tenant_id:UUID; roles:frozenset[str]; clearance:Classification; jurisdictions:frozenset[str]; active:bool=True
class OIDCAuthenticator:
    """JWT establishes identity; PostgreSQL establishes authorization."""
    def __init__(self,*,issuer:str,audience:str,public_key:str|bytes,memberships:MembershipAuthority): self.issuer,self.audience,self.public_key,self.memberships=issuer,audience,public_key,memberships
    def authenticate(self,token:str,request_id:UUID,purpose:str,tenant_id:UUID|None=None)->SecurityContext:
        claims:dict[str,Any]=jwt.decode(token,self.public_key,algorithms=["RS256","EdDSA"],audience=self.audience,issuer=self.issuer,options={"require":["exp","iat","iss","aud","sub"]})
        m=self.memberships.resolve(str(claims["iss"]),str(claims["sub"]),tenant_id)
        if not m.active: raise PermissionError("inactive membership")
        actor_type="agent" if "ai_agent" in m.roles else "user"
        return SecurityContext(m.tenant_id,m.subject,actor_type,m.roles,m.clearance,m.jurisdictions,purpose,agent_id=m.subject if actor_type=="agent" else None,request_id=request_id,identity_issuer=m.issuer)
