from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class SigningKey(Protocol):
    @property
    def key_id(self) -> str: ...
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> None: ...


class Ed25519SigningKey:
    """Local/dev signer. Production replaces this with a KMS/HSM adapter."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None, key_id: str = "dev-ed25519-v1"):
        self._private = private_key or Ed25519PrivateKey.generate()
        self._public: Ed25519PublicKey = self._private.public_key()
        self._key_id = key_id

    @property
    def key_id(self) -> str: return self._key_id
    def sign(self, payload: bytes) -> bytes: return self._private.sign(payload)
    def verify(self, payload: bytes, signature: bytes) -> None: self._public.verify(signature, payload)


@dataclass(frozen=True)
class SignedEvidencePackage:
    package_id: UUID
    issued_at: datetime
    tenant_id: UUID
    request_id: UUID
    answer_classification: str
    jurisdiction: str
    question_hash: str
    answer_hash: str
    claim_hashes: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    document_version_hashes: tuple[str, ...]
    policy_versions: tuple[str, ...]
    model_manifest_hash: str
    temporal_parameters_hash: str
    audit_checkpoint: str
    key_id: str
    signature: str

    def unsigned_payload(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value


class EvidencePackageService:
    def __init__(self, key: SigningKey): self.key = key

    def issue(self, *, tenant_id: UUID, request_id: UUID, answer_classification: str, jurisdiction: str, question: str, answer: str,
              claims: list[dict[str, Any]], evidence: list[dict[str, Any]],
              document_versions: list[dict[str, Any]], policy_versions: list[str],
              model_manifest: dict[str, Any], temporal_parameters: dict[str, Any], audit_checkpoint: str) -> SignedEvidencePackage:
        base = {
            "package_id": uuid4(), "issued_at": datetime.now(timezone.utc), "tenant_id": tenant_id,
            "request_id": request_id, "answer_classification": answer_classification, "jurisdiction": jurisdiction,
            "question_hash": sha256(question), "answer_hash": sha256(answer),
            "claim_hashes": tuple(sha256(x) for x in claims), "evidence_hashes": tuple(sha256(x) for x in evidence),
            "document_version_hashes": tuple(sha256(x) for x in document_versions),
            "policy_versions": tuple(sorted(set(policy_versions))), "model_manifest_hash": sha256(model_manifest),
            "temporal_parameters_hash": sha256(temporal_parameters), "audit_checkpoint": audit_checkpoint,
            "key_id": self.key.key_id,
        }
        signature = base64.urlsafe_b64encode(self.key.sign(canonical_json(base))).decode()
        return SignedEvidencePackage(**base, signature=signature)

    def verify(self, package: SignedEvidencePackage) -> bool:
        try:
            self.key.verify(canonical_json(package.unsigned_payload()), base64.urlsafe_b64decode(package.signature))
            return True
        except Exception:
            return False
