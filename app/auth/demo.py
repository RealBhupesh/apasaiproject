from __future__ import annotations

from uuid import UUID

from app.db.seed import ALPHA, BETA
from app.security.context import Classification, SecurityContext

# Explicit demo identities only. Tenant comes from server-side identity mapping, never request input.
_IDENTITIES = {
    "alpha-viewer": (ALPHA, "viewer-alpha", "user", frozenset({"viewer"}), Classification.PUBLIC, frozenset({"FEDERAL"}), None),
    "alpha-analyst": (ALPHA, "analyst-alpha", "user", frozenset({"analyst"}), Classification.INTERNAL, frozenset({"FEDERAL", "STATE-X"}), None),
    "alpha-admin": (ALPHA, "admin-alpha", "user", frozenset({"admin"}), Classification.RESTRICTED, frozenset({"FEDERAL", "STATE-X"}), None),
    "alpha-agent": (ALPHA, "compliance-assistant", "agent", frozenset({"ai_agent"}), Classification.INTERNAL, frozenset({"FEDERAL", "STATE-X"}), "compliance-assistant"),
    "beta-analyst": (BETA, "analyst-beta", "user", frozenset({"analyst"}), Classification.INTERNAL, frozenset({"FEDERAL"}), None),
}


def authenticate_demo(identity: str, request_id: UUID, tool_id: str | None = None) -> SecurityContext:
    if identity not in _IDENTITIES:
        raise PermissionError("unknown demo identity")
    tenant, actor, kind, roles, clearance, jurisdictions, agent = _IDENTITIES[identity]
    return SecurityContext(tenant, actor, kind, roles, clearance, jurisdictions, "regulatory-research", agent, tool_id, request_id)


def demo_identities() -> list[str]:
    return list(_IDENTITIES)
