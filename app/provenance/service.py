from __future__ import annotations

from typing import Any
from uuid import UUID

from app.db.repositories.memory import MemoryStore
from app.security.context import Decision, Operation, ProtectedResource, SecurityContext
from app.security.policies import PolicyEngine


class ProvenanceService:
    def __init__(self, store: MemoryStore, policy: PolicyEngine):
        self.store, self.policy = store, policy

    def get_claim_provenance(self, claim_id: UUID, context: SecurityContext) -> dict[str, Any]:
        record = self.store.provenance.get(claim_id)
        if not record:
            raise KeyError("claim not found")
        decision = self.policy.authorize(
            context,
            ProtectedResource("claim", str(claim_id), record["tenant_id"], record["classification"], record["jurisdiction"]),
            Operation.PROVENANCE,
        )
        if decision.decision != Decision.ALLOW:
            raise PermissionError("provenance denied")
        # Return only previously authorized lineage; no global IDs or counts.
        return {k: v for k, v in record.items() if k not in {"tenant_id", "classification"}}
