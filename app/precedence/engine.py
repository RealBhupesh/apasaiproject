from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import IntEnum, StrEnum
from typing import Iterable
from uuid import UUID


class AuthorityLevel(IntEnum):
    GUIDANCE = 0
    LOCAL = 1
    STATE = 2
    FEDERAL = 3
    STATUTE = 4
    EMERGENCY_ORDER = 5


class Resolution(StrEnum):
    RESOLVED = "RESOLVED"
    NO_CONFLICT = "NO_CONFLICT"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True)
class Norm:
    evidence_id: UUID
    authority_level: AuthorityLevel
    jurisdiction: str
    topic: str
    value: str
    valid_from: date
    valid_to: date | None = None
    specific_to: str | None = None
    supersedes: UUID | None = None


@dataclass(frozen=True)
class PrecedenceResult:
    resolution: Resolution
    winner: UUID | None
    considered: tuple[UUID, ...]
    rationale: str


class PrecedenceEngine:
    """Deterministic rules only; ambiguity always escalates."""

    def resolve(self, norms: Iterable[Norm], as_of: date, facility: str | None = None) -> PrecedenceResult:
        active = [n for n in norms if n.valid_from <= as_of and (n.valid_to is None or as_of < n.valid_to)]
        if len({n.value for n in active}) <= 1:
            return PrecedenceResult(Resolution.NO_CONFLICT, active[0].evidence_id if active else None, tuple(n.evidence_id for n in active), "no incompatible values")
        ids = {n.evidence_id for n in active}
        superseders = [n for n in active if n.supersedes in ids]
        if len(superseders) == 1:
            return PrecedenceResult(Resolution.RESOLVED, superseders[0].evidence_id, tuple(ids), "explicit supersedes edge")
        specific = [n for n in active if facility and n.specific_to == facility]
        if len(specific) == 1:
            return PrecedenceResult(Resolution.RESOLVED, specific[0].evidence_id, tuple(ids), "single applicable facility-specific rule")
        top = max((n.authority_level for n in active), default=None)
        winners = [n for n in active if n.authority_level == top]
        if len(winners) == 1:
            return PrecedenceResult(Resolution.RESOLVED, winners[0].evidence_id, tuple(ids), "explicit authority hierarchy")
        return PrecedenceResult(Resolution.ESCALATE, None, tuple(ids), "precedence insufficient or same-level conflict")
