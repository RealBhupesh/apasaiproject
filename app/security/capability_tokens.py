from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import UUID

from app.signing.evidence_package import SigningKey, canonical_json


@dataclass(frozen=True)
class CapabilityClaims:
    subject: str
    tenant_id: UUID
    tools: tuple[str, ...]
    operations: tuple[str, ...]
    jurisdictions: tuple[str, ...]
    max_classification: int
    purpose: str
    audience: str
    expires_at: datetime
    nonce: str
    delegation_depth: int = 0
    max_calls: int = 100


class CapabilityTokenService:
    def __init__(self, key: SigningKey): self.key=key; self.revoked: set[str]=set(); self.usage: dict[str,int]={}

    def issue(self, claims: CapabilityClaims) -> str:
        body=asdict(claims); body["tenant_id"]=str(claims.tenant_id); body["expires_at"]=claims.expires_at.isoformat()
        payload=base64.urlsafe_b64encode(canonical_json(body)).decode().rstrip("=")
        sig=base64.urlsafe_b64encode(self.key.sign(payload.encode())).decode().rstrip("=")
        return f"{self.key.key_id}.{payload}.{sig}"

    def verify(self, token: str, *, audience: str, tool: str, operation: str, jurisdiction: str, purpose: str) -> CapabilityClaims:
        try:
            _,payload,sig=token.split(".",2)
            self.key.verify(payload.encode(),base64.urlsafe_b64decode(sig+"="*(-len(sig)%4)))
            body=json.loads(base64.urlsafe_b64decode(payload+"="*(-len(payload)%4)))
            claims=CapabilityClaims(**(body|{"tenant_id":UUID(body["tenant_id"]),"expires_at":datetime.fromisoformat(body["expires_at"]),"tools":tuple(body["tools"]),"operations":tuple(body["operations"]),"jurisdictions":tuple(body["jurisdictions"])}))
        except Exception as exc: raise PermissionError("invalid capability") from exc
        if claims.nonce in self.revoked or claims.expires_at <= datetime.now(timezone.utc): raise PermissionError("expired or revoked capability")
        if audience != claims.audience or tool not in claims.tools or operation not in claims.operations or jurisdiction not in claims.jurisdictions or purpose != claims.purpose: raise PermissionError("capability scope denied")
        used=self.usage.get(claims.nonce,0)
        if used >= claims.max_calls: raise PermissionError("capability budget exhausted")
        self.usage[claims.nonce]=used+1
        return claims

    def revoke(self, nonce: str) -> None: self.revoked.add(nonce)
