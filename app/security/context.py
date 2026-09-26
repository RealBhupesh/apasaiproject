from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import FrozenSet
from uuid import UUID


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class Operation(StrEnum):
    READ = "READ"
    SEARCH = "SEARCH"
    PROVENANCE = "PROVENANCE"
    ASK = "ASK"
    AUDIT_VERIFY = "AUDIT_VERIFY"


@dataclass(frozen=True)
class SecurityContext:
    tenant_id: UUID
    actor_id: str
    actor_type: str
    roles: FrozenSet[str]
    clearance: Classification
    jurisdictions: FrozenSet[str]
    purpose: str
    agent_id: str | None = None
    tool_id: str | None = None
    request_id: UUID | None = None
    identity_issuer: str | None = None


@dataclass(frozen=True)
class ProtectedResource:
    resource_type: str
    resource_id: str
    tenant_id: UUID
    classification: Classification
    jurisdiction: str | None = None
    owner_id: str | None = None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
