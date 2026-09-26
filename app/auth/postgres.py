from __future__ import annotations

from sqlalchemy import Engine, text

from app.security.context import Classification
from app.security.identity import VerifiedMembership


class DatabaseMembershipAuthority:
    """Security-authority lookup performed with a dedicated auth role, never by the LLM."""
    SQL=text("""
      SELECT i.subject,i.tenant_id,array_agg(DISTINCT r.name) roles,uc.clearance,uc.jurisdictions,i.active
      FROM security.identities i
      JOIN security.memberships m ON m.user_id=i.user_id AND m.tenant_id=i.tenant_id AND m.status='ACTIVE'
      JOIN security.user_clearances uc ON uc.user_id=i.user_id AND uc.tenant_id=i.tenant_id
      JOIN security.membership_roles mr ON mr.membership_id=m.id AND mr.tenant_id=m.tenant_id
      JOIN security.roles r ON r.id=mr.role_id AND r.tenant_id=mr.tenant_id
      WHERE i.subject=:subject AND i.active=true
      GROUP BY i.subject,i.tenant_id,uc.clearance,uc.jurisdictions,i.active
    """)
    def __init__(self,engine: Engine): self.engine=engine
    def resolve(self,subject: str)->VerifiedMembership:
        with self.engine.begin() as c: row=c.execute(self.SQL,{"subject":subject}).mappings().one_or_none()
        if not row: raise PermissionError("membership not found")
        return VerifiedMembership(row["subject"],row["tenant_id"],frozenset(row["roles"] or []),Classification[row["clearance"]],frozenset(row["jurisdictions"]),row["active"])
