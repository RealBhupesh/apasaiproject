from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from app.security.context import Decision, Operation, ProtectedResource, SecurityContext
from app.security.decisions import AccessDecision

ROLE_PERMISSIONS: dict[str, frozenset[Operation]] = {
    "admin": frozenset(Operation),
    "security_admin": frozenset(Operation),
    "analyst": frozenset({Operation.READ, Operation.SEARCH, Operation.PROVENANCE, Operation.ASK}),
    "engineer": frozenset({Operation.READ, Operation.SEARCH, Operation.PROVENANCE, Operation.ASK}),
    "viewer": frozenset({Operation.READ, Operation.SEARCH, Operation.ASK}),
    "ai_agent": frozenset({Operation.READ, Operation.SEARCH, Operation.ASK}),
    "ingestion_worker": frozenset(),
    "auditor": frozenset({Operation.PROVENANCE, Operation.AUDIT_VERIFY}),
}


class PolicyEngine:
    """Single RBAC + ABAC enforcement point. Every evaluation is persisted by the sink."""

    def __init__(self, sink: Callable[[AccessDecision], None], policy_version: str = "3.0.0"):
        self._sink = sink
        self.policy_version = policy_version

    def authorize(
        self, context: SecurityContext, resource: ProtectedResource, operation: Operation
    ) -> AccessDecision:
        reason = "authorized"
        result = Decision.ALLOW
        if context.tenant_id != resource.tenant_id:
            result, reason = Decision.DENY, "tenant mismatch"
        elif not any(operation in ROLE_PERMISSIONS.get(role, frozenset()) for role in context.roles):
            result, reason = Decision.DENY, "role lacks operation"
        elif context.clearance < resource.classification:
            result, reason = Decision.DENY, "insufficient clearance"
        elif resource.jurisdiction and resource.jurisdiction not in context.jurisdictions:
            result, reason = Decision.DENY, "jurisdiction not allowed"
        elif context.actor_type == "agent" and not context.tool_id:
            result, reason = Decision.DENY, "agent tool identity missing"

        decision = AccessDecision(
            request_id=context.request_id or uuid4(),
            tenant_id=context.tenant_id,
            actor_type=context.actor_type,
            actor_id=context.actor_id,
            resource_type=resource.resource_type,
            resource_id=resource.resource_id,
            operation=operation,
            decision=result,
            reason=reason,
            policy_id="default-rbac-abac",
            policy_version=self.policy_version,
        )
        self._sink(decision)
        return decision
