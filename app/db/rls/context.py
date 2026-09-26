from __future__ import annotations

from sqlalchemy import Connection, text

from app.security.context import SecurityContext


def set_local_security_context(connection: Connection, context: SecurityContext) -> None:
    """Transaction-local, parameterized context. Call after BEGIN and before every query."""
    values = {
        "tenant": str(context.tenant_id), "user": context.actor_id,
        "clearance": context.clearance.name, "role": ",".join(sorted(context.roles)),
        "jurisdictions": ",".join(sorted(context.jurisdictions)),
        "agent": context.agent_id or "", "tool": context.tool_id or "", "purpose": context.purpose,
    }
    for key, value in values.items():
        connection.execute(text("SELECT set_config(:name, :value, true)"), {"name": f"app.{key}_id" if key in {"tenant","user"} else f"app.{key}", "value": value})
