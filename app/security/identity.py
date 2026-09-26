from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

import jwt

from app.security.context import Classification, SecurityContext


class MembershipAuthority(Protocol):
    def resolve(self, subject: str) -> "VerifiedMembership": ...


@dataclass(frozen=True)
class VerifiedMembership:
    subject: str
    tenant_id: UUID
    roles: frozenset[str]
    clearance: Classification
    jurisdictions: frozenset[str]
    active: bool = True


class OIDCAuthenticator:
    """Validates identity, then resolves all authorization attributes server-side."""

    def __init__(self, *, issuer: str, audience: str, public_key: str, memberships: MembershipAuthority):
        self.issuer, self.audience, self.public_key, self.memberships = issuer, audience, public_key, memberships

    def authenticate(self, token: str, request_id: UUID, purpose: str) -> SecurityContext:
        claims: dict[str, Any] = jwt.decode(
            token, self.public_key, algorithms=["RS256", "EdDSA"], audience=self.audience,
            issuer=self.issuer, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
        membership = self.memberships.resolve(str(claims["sub"]))
        if not membership.active:
            raise PermissionError("inactive membership")
        return SecurityContext(
            membership.tenant_id, membership.subject, "user", membership.roles,
            membership.clearance, membership.jurisdictions, purpose, request_id=request_id,
        )
