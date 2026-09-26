from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.security.context import Decision, Operation, utcnow


@dataclass(frozen=True)
class AccessDecision:
    request_id: UUID
    tenant_id: UUID
    actor_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    operation: Operation
    decision: Decision
    reason: str
    policy_id: str
    policy_version: str
    timestamp: datetime = field(default_factory=utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)
