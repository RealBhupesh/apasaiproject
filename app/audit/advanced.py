from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from app.signing.evidence_package import SigningKey


def merkle_root(hashes: list[str]) -> str:
    if not hashes: return hashlib.sha256(b"").hexdigest()
    layer=[bytes.fromhex(h) for h in hashes]
    while len(layer)>1:
        if len(layer)%2: layer.append(layer[-1])
        layer=[hashlib.sha256(layer[i]+layer[i+1]).digest() for i in range(0,len(layer),2)]
    return layer[0].hex()


@dataclass(frozen=True)
class SignedAuditCheckpoint:
    tenant_id: str
    sequence: int
    merkle_root: str
    chain_head: str
    created_at: datetime
    key_id: str
    signature_hex: str


def create_checkpoint(tenant_id: str, hashes: list[str], key: SigningKey) -> SignedAuditCheckpoint:
    root=merkle_root(hashes); head=hashes[-1] if hashes else "GENESIS"; now=datetime.now(timezone.utc)
    payload=f"{tenant_id}|{len(hashes)}|{root}|{head}|{now.isoformat()}".encode()
    return SignedAuditCheckpoint(tenant_id,len(hashes),root,head,now,key.key_id,key.sign(payload).hex())
