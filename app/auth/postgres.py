from __future__ import annotations
from uuid import UUID
from sqlalchemy import Engine,text
from app.security.context import Classification
from app.security.identity import VerifiedMembership
class DatabaseMembershipAuthority:
    SQL=text("SELECT * FROM security.resolve_identity_memberships(:issuer,:subject)")
    def __init__(self,engine:Engine): self.engine=engine
    def resolve(self,issuer:str,subject:str,tenant_id:UUID|None=None)->VerifiedMembership:
        with self.engine.begin() as c: rows=c.execute(self.SQL,{"issuer":issuer,"subject":subject}).mappings().all()
        if tenant_id is not None: rows=[r for r in rows if r["tenant_id"]==tenant_id]
        if not rows: raise PermissionError("membership not found")
        if len(rows)>1: raise PermissionError("explicit authorized tenant selection required")
        r=rows[0]
        return VerifiedMembership(issuer,subject,r["tenant_id"],frozenset(r["roles"] or []),Classification[str(r["clearance"])],frozenset(r["jurisdictions"] or []),bool(r["active"]))
