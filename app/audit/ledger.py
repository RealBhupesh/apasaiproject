from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.security.context import utcnow


@dataclass
class AuditEvent:
    tenant_id: UUID
    actor: str
    event_type: str
    resource: str
    request_id: UUID
    metadata: dict[str, Any]
    previous_hash: str
    timestamp: datetime = field(default_factory=utcnow)
    id: UUID = field(default_factory=uuid4)
    event_hash: str = ""

    def canonical_payload(self) -> str:
        body = asdict(self) | {"event_hash": ""}
        body["id"], body["tenant_id"], body["request_id"] = map(str, (self.id, self.tenant_id, self.request_id))
        body["timestamp"] = self.timestamp.isoformat()
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class AuditLedger:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, *, tenant_id: UUID, actor: str, event_type: str, resource: str, request_id: UUID, metadata: dict[str, Any]) -> AuditEvent:
        previous = self.events[-1].event_hash if self.events else "GENESIS"
        event = AuditEvent(tenant_id, actor, event_type, resource, request_id, metadata, previous)
        event.event_hash = hashlib.sha256((event.canonical_payload() + previous).encode()).hexdigest()
        self.events.append(event)
        return event

    def verify_audit_chain(self) -> dict[str, int | bool | str]:
        previous = "GENESIS"
        for index, event in enumerate(self.events):
            expected = hashlib.sha256((event.canonical_payload() + previous).encode()).hexdigest()
            if event.previous_hash != previous or event.event_hash != expected:
                return {"valid": False, "events_checked": index, "failed_event_id": str(event.id)}
            previous = event.event_hash
        return {"valid": True, "events_checked": len(self.events)}
