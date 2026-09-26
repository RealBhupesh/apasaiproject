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
        resource_ids=[]
        if record.get("chunk_id"): resource_ids.append(UUID(record["chunk_id"]))
        resource_ids.extend(UUID(str(x)) for x in record.get("lineage_chunk_ids",[]))
        for chunk_id in resource_ids:
            chunk=self.store.chunks.get(chunk_id)
            if not chunk:
                raise PermissionError("provenance denied")
            hop=self.policy.authorize(context,ProtectedResource("chunk",str(chunk.id),chunk.tenant_id,chunk.classification,chunk.jurisdiction),Operation.PROVENANCE)
            if hop.decision!=Decision.ALLOW:
                raise PermissionError("provenance denied")
            version=self.store.versions.get(chunk.document_version_id); document=self.store.documents.get(version.source_document_id) if version else None
            if not document:
                raise PermissionError("provenance denied")
            doc_hop=self.policy.authorize(context,ProtectedResource("document",str(document.id),document.tenant_id,document.classification,document.jurisdiction),Operation.PROVENANCE)
            if doc_hop.decision!=Decision.ALLOW:
                raise PermissionError("provenance denied")
        return {k: v for k, v in record.items() if k not in {"tenant_id", "classification", "lineage_chunk_ids"}}
