from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from app.security.context import Classification, Operation, SecurityContext


@dataclass(frozen=True)
class Capability:
    agent: str
    tenant_id: UUID
    tools: frozenset[str]
    operations: frozenset[Operation]
    max_classification: Classification
    expires_at: datetime

    def permits(self, context: SecurityContext, tool: str, operation: Operation) -> bool:
        now = datetime.now(timezone.utc)
        return (
            context.actor_type == "agent"
            and context.agent_id == self.agent
            and context.tenant_id == self.tenant_id
            and tool in self.tools
            and operation in self.operations
            and context.clearance <= self.max_classification
            and self.expires_at > now
        )


def require_capability(capability: Capability, context: SecurityContext, tool: str, operation: Operation) -> None:
    if not capability.permits(context, tool, operation):
        raise PermissionError("capability denied")
