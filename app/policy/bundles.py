from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4


class BundleStatus(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


@dataclass
class PolicyBundle:
    tenant_id: UUID
    version: str
    definition: dict[str, Any]
    created_by: str
    id: UUID = field(default_factory=uuid4)
    status: BundleStatus = BundleStatus.DRAFT
    approvals: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.definition, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def approve(self, reviewer: str) -> None:
        if reviewer == self.created_by: raise PermissionError("four-eyes approval required")
        if reviewer not in self.approvals: self.approvals.append(reviewer)
        self.status = BundleStatus.APPROVED

    def activate(self) -> None:
        if self.status != BundleStatus.APPROVED or not self.approvals: raise PermissionError("approved bundle required")
        self.status = BundleStatus.ACTIVE


@dataclass(frozen=True)
class SimulationCase:
    attributes: dict[str, Any]
    expected: str


def simulate(bundle: PolicyBundle, cases: list[SimulationCase]) -> dict[str, Any]:
    """Small local policy simulator; production adapter sends the same bundle to OPA/Cedar."""
    mismatches=[]
    allowed_ops=set(bundle.definition.get("allowed_operations", []))
    max_classification=int(bundle.definition.get("max_classification", 0))
    for i,case in enumerate(cases):
        actual="ALLOW" if case.attributes.get("operation") in allowed_ops and int(case.attributes.get("classification",99)) <= max_classification else "DENY"
        if actual != case.expected: mismatches.append({"case":i,"expected":case.expected,"actual":actual})
    return {"valid":not mismatches,"cases":len(cases),"mismatches":mismatches,"bundle_digest":bundle.digest}
